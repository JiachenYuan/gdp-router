use std::{fs, process::Command, net::Ipv4Addr};
use anyhow::Result;
use capsule::{Runtime, batch::{self, Batch, Pipeline, Poll, Disposition}, Mbuf, PortQueue, packets::{Ethernet, ip::v4::Ipv4, Udp, Packet}, net::MacAddr};

use crate::{network_protocols::gdp::Gdp, structs::{GdpAction, GdpName}, utils::{query_local_ip_address, generate_gdpname, set_payload, ipv4_addr_from_bytes, gdpname_byte_array_to_hex, uuid_byte_array_to_hex}, pipeline, router_store::Store};
use crate::utils::get_payload;



pub fn send_register_request(q: PortQueue, access_point_addr: Ipv4Addr, gdpname: [u8; 32]) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    // Broadcasting the packet
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = access_point_addr;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_register_packet(reply, gdpname, src_mac, src_ip, dst_mac, dst_ip)
        })
        .send(q.clone())
        .run_once();
}

fn prepare_register_packet(
    reply: Mbuf,
    gdpname: [u8; 32],
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,) -> Result<Gdp<Udp<Ipv4>>> {

        let mut reply = reply.push::<Ethernet>()?;
        reply.set_src(src_mac);
        reply.set_dst(dst_mac);
    
        let mut reply = reply.push::<Ipv4>()?;
        reply.set_src(src_ip);
        reply.set_dst(dst_ip);
    
        let mut reply = reply.push::<Udp<Ipv4>>()?;
        reply.set_src_port(31415);
        reply.set_dst_port(31415);
    
        // Setting Gdp-related information in the GDP header
        let mut reply = reply.push::<Gdp<Udp<Ipv4>>>()?;
        reply.set_action(GdpAction::Register);
        reply.set_data_len(4);
        let mut src_gdpname: [u8; 32] = Default::default();
        src_gdpname.copy_from_slice(&gdpname[..]);
        reply.set_src(src_gdpname);
        // because this is a register packet, we don't use GdpName for the destination
        // the distination is a access point, we use ip to find it
    
        let offset = reply.payload_offset();
    
        let local_ip_as_octets = src_ip.octets();
        
        // packet payload is set to be local ip address
        reply.mbuf_mut().extend(offset, local_ip_as_octets.len())?;
        reply.mbuf_mut().write_data_slice(offset, &local_ip_as_octets[..local_ip_as_octets.len()])?;
        // set_payload(&mut reply, &local_ip_as_octets);
        
        reply.reconcile_all();
    
        Ok(reply)

    }

fn register_client(packet: &Gdp<Udp<Ipv4>>, store: Store) -> Result<()>{
    let client_gdpname = packet.src();
    let message:&[u8] = get_payload(packet)?;
    
    println!("{:?} from {:?}", message, gdpname_byte_array_to_hex(client_gdpname));

    let sender_ip = ipv4_addr_from_bytes(message.try_into().unwrap());
    store.get_neighbors().write().unwrap().insert(client_gdpname, sender_ip);

    println!("Current registered clients: {:?}", store.get_neighbors().read().unwrap());

    Ok(())
}

fn forward_packet(mut packet: Gdp<Udp<Ipv4>>, local_mac_address: MacAddr, access_point_addr: Ipv4Addr) -> Result<Gdp<Udp<Ipv4>>> {    
    packet.header_mut().ttl -= 1;

    let ip_layer = packet.envelope_mut().envelope_mut();
    ip_layer.set_src(ip_layer.dst());
    ip_layer.set_dst(access_point_addr);
    
    let ether_layer = ip_layer.envelope_mut();
    ether_layer.set_src(local_mac_address);
    Ok(packet)
}

fn to_client(mut packet:Gdp<Udp<Ipv4>>, local_ip: Ipv4Addr, client_addr: Ipv4Addr, local_mac_address: MacAddr) -> Result<Gdp<Udp<Ipv4>>> {
    packet.header_mut().ttl -= 1;
    
    let ip_layer = packet.envelope_mut().envelope_mut();
    ip_layer.set_src(local_ip);
    ip_layer.set_dst(client_addr);

    let ether_layer = ip_layer.envelope_mut();
    ether_layer.set_src(local_mac_address);
    Ok(packet)
}


fn switch_pipeline(q: PortQueue, access_point_addr: Ipv4Addr, gdpname: [u8; 32], store: Store, local_ip_address: Ipv4Addr) -> impl Pipeline {

    let local_mac_addr = q.mac_addr().clone();

    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        // .inspect(|disp| {
        //     if let Disposition::Act(v4) = disp {
        //         println!("{:?}", v4.src());
        //     }
        // })
        .filter(move |packet| packet.dst() == local_ip_address)
        .map(|packet| packet.parse::<Udp<Ipv4>>()?.parse::<Gdp<Udp<Ipv4>>>())
        .group_by (
            |packet| packet.action().unwrap(),
            pipeline! {
                    GdpAction::RegisterAck => |group| {
                        group.for_each(|packet| {
                            println!("Acknowledgement received!");
                            Ok(())
                        })
                        
                    }
                    ,
                    GdpAction::Ping => |group| {
                        group.for_each(|packet| {
                            println!("Being pined...");
                            let msg = get_payload(packet).unwrap();
                            println!("Message is: {:?}", std::str::from_utf8(msg));
                            Ok(())
                        })
                    }
                    ,
                    GdpAction::Register => |group| {
                        group.for_each(move |packet| {
                            println!("{:?}", packet);
                            register_client(packet, store)
                        })
                        .filter(|_| { false })
                    }
                    ,
                    GdpAction::PacketForward => |group| {
                        // group.for_each(move |packet| {
                        //     println!("Packet received, to be forward... packet series is {:?}. Coming from {:?}, Destination is {:?}",
                        //          uuid_byte_array_to_hex(packet.header().uuid) , gdpname_byte_array_to_hex(packet.src()), gdpname_byte_array_to_hex(packet.dst()));
                        //     println!("{:?}", packet);
                        //     Ok(())
                        // })
                        group.map(move |mut packet| {
                            println!("Packet forwarded");
                            let gdpname_hash_map = store.get_neighbors().read().unwrap();
                            let value_option = gdpname_hash_map.get(&packet.dst());
                            if let Some(client_addr) = value_option{
                                to_client(packet, local_ip_address, *client_addr, local_mac_addr)
                            } else {
                                forward_packet(packet, local_mac_addr, access_point_addr)
                            }

                            
                        })
                    }
                    ,


                    _ => |group| {
                        group.filter(|_| {
                            false
                        })
                    }
                }
        )
        .send(q)
        
}



pub fn start_switch(access_point_addr: Ipv4Addr) -> Result<()>{
     // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;
    

    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;


    // Obtain local IPv4 address
    let local_ip = query_local_ip_address();

    // Obtain GDPName and print it
    let gdpname = generate_gdpname(&local_ip);

    // println!("I am a GDP Switch. My GdpName is {:?}", gdpname);

    // Initialize shared information store
    let store = Store::new();


    runtime.add_pipeline_to_port("eth1", move |q| {
        send_register_request(q.clone(), access_point_addr, gdpname);
        println!("sent register request");
        switch_pipeline(q, access_point_addr, gdpname, store, Ipv4Addr::from(local_ip))

    })?
    
    .execute()
}