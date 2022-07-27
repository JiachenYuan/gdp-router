use std::{fs, process::Command, net::Ipv4Addr};
use anyhow::Result;

use capsule::{batch::{Pipeline, Poll, Batch, self, Disposition}, PortQueue, Runtime, packets::{Ethernet, Packet, ip::v4::Ipv4, Udp}, Mbuf, net::MacAddr};
use tracing::debug;
use crate::{utils::{query_local_ip_address, get_payload}, network_protocols::gdp::Gdp, structs::GdpAction, persistence::Store,};


fn register_neighbor(ip_addr: Ipv4Addr, store: &mut Store) {
    store.neighbors.insert(ip_addr);
}

fn prepare_ack_packet(
    reply: Mbuf,
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
        reply.set_action(GdpAction::RibRegisterAck);
        reply.set_data_len(4);
        reply.set_src(src_ip);
        reply.set_dst(dst_ip);
    
        let offset = reply.payload_offset();
    
        let message = src_ip.octets();
    
        reply.mbuf_mut().extend(offset, message.len())?;
        reply.mbuf_mut().write_data_slice(offset, &message[..message.len()])?;
        
        reply.reconcile_all();
    
        Ok(reply)
    
        
    
    }


fn register_and_ack(q: &PortQueue, packet: &Gdp<Udp<Ipv4>>, store: &mut Store) -> Result<()> {
    let message:&[u8] = get_payload(packet)?;
    let mut first_four_octats: [u8; 4] = [0; 4];
    first_four_octats[0] = message[0];
    first_four_octats[1] = message[1];
    first_four_octats[2] = message[2];
    first_four_octats[3] = message[3];
    let sender_ip = Ipv4Addr::from(first_four_octats);

    register_neighbor(sender_ip, store);


    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    let packet_ip_layer = packet.envelope().envelope();
    let packet_ether_layer = packet_ip_layer.envelope();
    let dst_mac = packet_ether_layer.src();
    let dst_ip = packet_ip_layer.src();

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_ack_packet(reply, src_mac, src_ip, dst_mac, dst_ip)
        })
        .send(q.clone())
        .run_once();

    Ok(())
}


fn pipeline_installer(q: PortQueue) -> impl Pipeline {
    let local_ip_address = query_local_ip_address();
    let q_clone_for_closure = q.clone();
    let mut store = Store::new();

    Poll::new(q.clone())
        .map(|packet| {
            packet.parse::<Ethernet>()?.parse::<Ipv4>()
        })
        .filter(move |packet| {
            packet.dst() == local_ip_address
        })
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        .map(|packet| packet.parse::<Gdp<Udp<Ipv4>>>())

        .inspect(|disp| {
            if let Disposition::Act(gdp_packet) = disp {
                println!("received a packet. GDP action is {:?}", gdp_packet.action().unwrap());
            }
        })
      
        .group_by(
            |packet| packet.action().unwrap(), 
            |groups| {
                crate::compose! ( groups {
                            GdpAction::RibRegister => |group| {
                                group.for_each(move |register_packet| {
                                    println!("processing the register request");
                                    register_and_ack(&q_clone_for_closure, register_packet, &mut store)
                                })
                            }
                            _ => |group| {
                                group.filter(|_| {
                                    false
                                })
                            }
                        })
                    }
        )
        .send(q)
}



pub fn start_rib() -> Result<()> {
    // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;

    println!("I'm a RIB, my ip is: {:?}", query_local_ip_address());

    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;

    runtime.add_pipeline_to_port("eth1", pipeline_installer)?
        .execute()
}