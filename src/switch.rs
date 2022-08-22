use std::{fs, process::Command, net::Ipv4Addr, time::Duration, thread::sleep};
use anyhow::Result;
use capsule::{Runtime, batch::{self, Batch, Pipeline, Poll}, Mbuf, PortQueue, packets::{Ethernet, ip::v4::Ipv4, Udp, Packet}, net::MacAddr};
use capsule::batch::Disposition;
use tokio_net::signal::unix::libc::access;
use tokio_timer::delay_for;
use crate::{network_protocols::gdp::Gdp, structs::GdpAction, utils::query_local_ip_address, packet_sender::send_packet_to, schedule::Schedule};
use tracing::debug;
use crate::utils::get_payload;
use crate::ospf::LinkStateDatabase;
use std::sync::{Arc, Mutex};

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


pub fn send_neighbor_request(q: PortQueue, lsdb: Arc<Mutex<LinkStateDatabase>>, access_point_addr: Ipv4Addr) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    // Broadcasting the packet
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = access_point_addr;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_packet(reply, src_mac, src_ip, dst_mac, dst_ip, lsdb.lock().unwrap().table_as_str().as_bytes(), GdpAction::LSA)
        })
        .send(q.clone())
        .run_once();
}

// Change to send arbitrary messages, specifically the entire routing table
fn prepare_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    payload: &[u8],
    action: GdpAction,
) -> Result<Gdp<Udp<Ipv4>>> {

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
    reply.set_action(action);
    reply.set_data_len(payload.len());
    reply.set_src(src_ip);
    reply.set_dst(dst_ip);

    let offset = reply.payload_offset();
    let payload_size = payload.len();

    reply.mbuf_mut().extend(offset, payload_size)?;
    reply.mbuf_mut().write_data_slice(offset, &payload[..payload_size])?;
    
    reply.reconcile_all();

    Ok(reply)
}

fn prepare_test_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    payload_size: usize
) -> Result<Gdp<Udp<Ipv4>>> {

    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(src_mac);
    reply.set_dst(dst_mac);

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(src_ip);
    // delegate public access point to forward packet
    reply.set_dst(dst_ip);

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


fn send_test_packet(q: &PortQueue, target: Ipv4Addr) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = target;
    let payload_size = 25;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_packet(reply, src_mac, src_ip, dst_mac, dst_ip, "test packet 123".as_bytes(), GdpAction::Ping)
        })
        .send(q.clone())
        .run_once();
}


fn switch_pipeline(q: PortQueue, lsdb: Arc<Mutex<LinkStateDatabase>>) -> impl Pipeline {
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
                    GdpAction::LSA => |group| {
                        group.inspect(|disp| {
                            if let Disposition::Act(packet) = disp {
                                println!("Received LSA...");
                                let message = get_payload(packet).unwrap();
                                println!("{:?}", message);
                                lsdb.lock().unwrap().update_state(packet.src(), message);
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



pub fn start_switch(access_point_addr: Option<String>, target: Option<String>) -> Result<()>{
     // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;

    // Initialize OSPF state
    let link_state = Arc::new(Mutex::new(LinkStateDatabase::new()));
    // Test
    link_state.lock().unwrap().add_neighbor("1.1.1.1".parse::<Ipv4Addr>()?);


    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;


    runtime.add_pipeline_to_port("eth1", move |q| {
        // send_register_request(q.clone(), access_point_addr);
        match &access_point_addr {
            // Add neighbor if given, exchange routing info
            None => println!("No neighbor specified."),
            Some(ip_as_string) => {
                println!("sent neighbor request");
                let ip = ip_as_string.parse::<Ipv4Addr>().unwrap();
                send_neighbor_request(q.clone(), link_state.clone(), ip);
                link_state.lock().unwrap().add_neighbor(ip);
            }
        }
        // Add delay?
        match &target {
            None => println!("No ping action."),
            Some(_target_address) => {
                println!("Pinging {}", _target_address);
                let target_address = _target_address.parse::<Ipv4Addr>().unwrap();
                send_test_packet(&q, target_address)
            }
        }

        // Listen to incoming packets
        switch_pipeline(q, link_state.clone())

    })?
    
    .execute()
}
