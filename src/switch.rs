use std::{fs, process::Command, net::Ipv4Addr, time::Duration, thread::sleep};
use anyhow::Result;
use capsule::{Runtime, batch::{self, Batch, Pipeline, Poll}, Mbuf, PortQueue, packets::{Ethernet, ip::v4::Ipv4, Udp, Packet}, net::MacAddr};
use capsule::batch::Disposition;
use tokio_timer::delay_for;
use crate::{network_protocols::gdp::Gdp, structs::GdpAction, utils::query_local_ip_address, packet_sender::send_packet_to, schedule::Schedule};
use tracing::debug;
use crate::utils::get_payload;

pub fn send_register_request(q: PortQueue, access_point_addr: Ipv4Addr) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    // Broadcasting the packet
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = access_point_addr;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_register_packet(reply, src_mac, src_ip, dst_mac, dst_ip)
        })
        .send(q.clone())
        .run_once();
}

fn prepare_register_packet(
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
        reply.set_action(GdpAction::RibRegister);
        reply.set_data_len(4);
        reply.set_src(src_ip);
        reply.set_dst(dst_ip);
    
        let offset = reply.payload_offset();
    
        let local_ip_as_octets = src_ip.octets();
        
        // packet payload is set to be local ip address
        reply.mbuf_mut().extend(offset, local_ip_as_octets.len())?;
        reply.mbuf_mut().write_data_slice(offset, &local_ip_as_octets[..local_ip_as_octets.len()])?;
        
        reply.reconcile_all();
    
        Ok(reply)

    }

fn prepare_test_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    access_point_addr: Ipv4Addr,
    payload_size: usize
) -> Result<Gdp<Udp<Ipv4>>> {

    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(src_mac);
    reply.set_dst(dst_mac);

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(src_ip);
    // delegate public access point to forward packet
    reply.set_dst(access_point_addr);

    let mut reply = reply.push::<Udp<Ipv4>>()?;
    reply.set_src_port(31415);
    reply.set_dst_port(31415);

    // Setting Gdp-related information in the GDP header
    let mut reply = reply.push::<Gdp<Udp<Ipv4>>>()?;
    reply.set_action(GdpAction::Ping);
    reply.set_data_len(payload_size);
    reply.set_src(src_ip);
    reply.set_dst(dst_ip);

    let offset = reply.payload_offset();

    let message = "this is a ping message...".as_bytes(); // This message has length 25 bytes, == payload_size

    reply.mbuf_mut().extend(offset, payload_size)?;
    reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;
    
    reply.reconcile_all();

    Ok(reply)
}


fn send_test_packet(q: &PortQueue, access_point_addr: Ipv4Addr, target: Ipv4Addr) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = target;
    let payload_size = 25;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| {
            prepare_test_packet(packet, src_mac, src_ip, dst_mac, dst_ip, access_point_addr, payload_size)
        })
        .send(q.clone())
        .run_once();
}


fn switch_pipeline(q: PortQueue, access_point_addr: Ipv4Addr, target: Ipv4Addr) -> impl Pipeline {
    let local_ip_address = query_local_ip_address();

    let closure_q = q.clone();

    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| packet.dst() == local_ip_address)
        .map(|packet| packet.parse::<Udp<Ipv4>>()?.parse::<Gdp<Udp<Ipv4>>>())
        .group_by(
            |packet| packet.action().unwrap(),
            |groups| {
                crate::compose!( groups {
                    GdpAction::RibRegisterAck => |group| {
                        group.inspect(move |disp| {
                            if let Disposition::Act(packet) = disp {
                                
                                println!("Current switch is registered.");
                                //* Workflow starts here...
                                // todo: workflow, sending initial packet. It has problem for now
                                // println!("Sending test packet");
                                // send_test_packet(&closure_q, access_point_addr, target);
                                // send_test_packet(&closure_q, access_point_addr, target);
                                // send_test_packet(&closure_q, access_point_addr, target);
                                // send_test_packet(&closure_q, access_point_addr, target);
                            }
                        })
                        
                    }
                    GdpAction::Ping => |group| {
                        group.inspect(|disp| {
                            if let Disposition::Act(packet) = disp {
                                println!("Being pinged...");
                                let message = get_payload(packet).unwrap();
                                println!("{:?}", message);
                            }
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



pub fn start_switch(access_point_addr: Ipv4Addr, target: Ipv4Addr) -> Result<()>{
     // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;
    

    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;


    runtime.add_pipeline_to_port("eth1", move |q| {
        send_register_request(q.clone(), access_point_addr);
        println!("sent register request");
        switch_pipeline(q, access_point_addr, target)

    })?
    
    .execute()
}