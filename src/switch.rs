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

// fn prepare_test_packet(
//     reply: Mbuf,
//     src_gdpname: &[u8; 32],
//     dst_gdpname: &[u8; 32],
//     src_mac: MacAddr,
//     src_ip: Ipv4Addr,
//     dst_mac: MacAddr,
//     dst_ip: Ipv4Addr,
//     access_point_addr: Ipv4Addr,
//     payload_size: usize
// ) -> Result<Gdp<Udp<Ipv4>>> {

//     let mut reply = reply.push::<Ethernet>()?;
//     reply.set_src(src_mac);
//     reply.set_dst(dst_mac);

//     let mut reply = reply.push::<Ipv4>()?;
//     reply.set_src(src_ip);
//     // delegate public access point to forward packet
//     reply.set_dst(access_point_addr);

//     let mut reply = reply.push::<Udp<Ipv4>>()?;
//     reply.set_src_port(31415);
//     reply.set_dst_port(31415);

//     // Setting Gdp-related information in the GDP header
//     let mut reply = reply.push::<Gdp<Udp<Ipv4>>>()?;
//     reply.set_action(GdpAction::Ping);
//     reply.set_data_len(payload_size);
//     let src_gdpname: [u8; 32] = Default::default();
//     src_gdpname.copy_from_slice(&src_gdpname[..]);
//     reply.set_src(src_gdpname);
//     let dst_gdpname: [u8; 32] = Default::default();
//     dst_gdpname.copy_from_slice(&dst_gdpname[..]);
//     reply.set_dst(dst_gdpname);

//     let offset = reply.payload_offset();

//     let message = "this is a ping message...".as_bytes(); // This message has length 25 bytes, == payload_size

//     // reply.mbuf_mut().extend(offset, payload_size)?;
//     // reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;
//     set_payload(&mut reply, message);
    
//     reply.reconcile_all();

//     Ok(reply)
// }


// fn send_test_packet(q: &PortQueue, access_point_addr: Ipv4Addr, target: Ipv4Addr) {
//     let src_mac = q.mac_addr();
//     let src_ip = query_local_ip_address();
//     let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
//     let dst_ip = target;
//     let payload_size = 25;

//     batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
//         .map(move |packet| {
//             prepare_test_packet(packet, src_mac, src_ip, dst_mac, dst_ip, access_point_addr, payload_size)
//         })
//         .send(q.clone())
//         .run_once();
// }

fn register_client(packet: &Gdp<Udp<Ipv4>>, store: Store) -> Result<()>{
    let client_gdpname = packet.src();
    // let message:&[u8] = get_payload(packet)?;
    let data = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.data_len())?;
    let message: &[u8]= unsafe { data.as_ref() };

    println!("{:?} from {:?}", message, gdpname_byte_array_to_hex(client_gdpname));

    let sender_ip = ipv4_addr_from_bytes(message.try_into().unwrap());
    store.get_neighbors().write().unwrap().insert(client_gdpname, sender_ip);

    println!("Current registered clients: {:?}", store.get_neighbors().read().unwrap());

    Ok(())
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
                            println!("Packet received, to be forward... packet series is {:?}. Coming from {:?}, Destination is {:?}",
                                 uuid_byte_array_to_hex(packet.header().uuid) , gdpname_byte_array_to_hex(packet.src()), gdpname_byte_array_to_hex(packet.dst()));
                            
                            println!("Received>>>");
                            println!("{:?}", packet);

                            packet.set_dst(packet.src());
                            packet.set_src(gdpname);

                            let udp_layer = packet.envelope_mut();
                            udp_layer.set_dst_port(31415);
                            udp_layer.set_src_port(31415);


                            let ip_layer = udp_layer.envelope_mut();
                            ip_layer.set_dst(ip_layer.src());
                            ip_layer.set_src(local_ip_address);

                            let ether_layer = ip_layer.envelope_mut();
                            ether_layer.set_src(local_mac_addr);

                            println!("echo<<<");
                            println!("{:?}", packet);
                            Ok(packet)
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