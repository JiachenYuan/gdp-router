use std::{fs, process::Command, net::Ipv4Addr, time::Duration, thread::sleep, str};
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

    /* 
     * Sends local memtable to access_point_addr.
     * Specify whether packet is an ack with is_ack.
     */
pub fn send_neighbor_request(q: PortQueue, lsdb: &'static Arc<Mutex<LinkStateDatabase>>, access_point_addr: Ipv4Addr, is_ack: bool) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    // Broadcasting the packet
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = access_point_addr;
    let table_str = serde_json::to_string(&(lsdb.lock().unwrap().routing_table)).unwrap();
    let table_ser = table_str.as_bytes();
    let packet_type = if is_ack { GdpAction::LSA_ACK } else { GdpAction::LSA };

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |reply| {
            prepare_packet(reply, src_mac, src_ip, dst_mac, dst_ip, &table_ser, packet_type)
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

fn handle_incoming_packet(q: &PortQueue, packet: &Gdp<Udp<Ipv4>>, lsdb: &'static Arc<Mutex<LinkStateDatabase>>) -> bool {
    if packet.dst() == query_local_ip_address() { 
        // Temporary additional LSA as workaround for PortQueue issue.
        match packet.action().unwrap() {
            GdpAction::LSA => {
                println!("Received LSA...");
                let message = match str::from_utf8(get_payload(packet).unwrap()) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                println!("{:?}", message);
                lsdb.lock().unwrap().update_state(packet.src(), message);
                lsdb.lock().unwrap().print_table();
                // Send back ACK including own table
                send_neighbor_request(q.clone(), &lsdb, packet.src(), true);
            }
            // Same as above, except we do not send an ack. TODO: Remove code duplication
            GdpAction::LSA_ACK => {
                println!("Received LSA ACK...");
                let message = match str::from_utf8(get_payload(packet).unwrap()) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                println!("{:?}", message);
                lsdb.lock().unwrap().update_state(packet.src(), message);
                lsdb.lock().unwrap().print_table();
            }
            _ => println!("Other packet type not handled in handle_incoming_packet..."),

        }
        return true;
    } else {
        batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
            .map(move |reply| {
                prepare_redirect_packet(packet, lsdb)
            })
            .send(q.clone())
            .run_once();
        return false;
    }
}

fn prepare_redirect_packet(packet: &Gdp<Udp<Ipv4>>, lsdb: &'static Arc<Mutex<LinkStateDatabase>>) -> Result<Gdp<Udp<Ipv4>>> {
    let udp = packet.envelope();
    let ipv4 = udp.envelope();
    let ethernet = ipv4.envelope();
    let curr_ip = query_local_ip_address();

    // If packet destination is current router, continue.
    let next_jump = match lsdb.lock().unwrap().get_next_hop(packet.dst()) {
        Some(v) => v,
        None => panic!("Unable to route") 
    };
    
    // Create new packet, redirect.
    let out = Mbuf::new()?;
    let mut out = out.push::<Ethernet>()?;
    out.set_src(ethernet.src());
    out.set_dst(ethernet.dst());

    // Change IP with current switch IP, next hop destination
    let mut out = out.push::<Ipv4>()?;
    out.set_src(curr_ip);
    out.set_dst(next_jump);

    let mut out = out.push::<Udp<Ipv4>>()?;
    out.set_src_port(udp.src_port());
    out.set_dst_port(udp.dst_port());

    // Keep GDP address the same
    let mut out = out.push::<Gdp<Udp<Ipv4>>>()?;
    out.set_action(packet.action()?);
    out.set_data_len(packet.payload_len());
    out.set_src(packet.src());
    out.set_dst(packet.dst());

    out.reconcile_all();
    
    return Ok(out);
}

fn switch_pipeline<'a>(q: PortQueue, lsdb: &'static Arc<Mutex<LinkStateDatabase>>) -> impl Pipeline {
    let local_ip_address = query_local_ip_address();

    let closure_q = q.clone();

    Poll::new(q.clone())
        .map(|packet| packet.parse::<Ethernet>()?.parse::<Ipv4>())
        .filter(move |packet| packet.dst() == local_ip_address)
        .map(|packet| packet.parse::<Udp<Ipv4>>()?.parse::<Gdp<Udp<Ipv4>>>())
        .filter(move |packet| handle_incoming_packet(&closure_q, packet, &lsdb))
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
                                // packet.get
                                println!("{:?}", message);
                            }
                        })
                    }
                    // Update local routing table with neighbor's table
                    GdpAction::LSA => |group| {
                        group.inspect(|disp| {
                            if let Disposition::Act(packet) = disp {
                                println!("Received LSA...");
                                /*
                                let message = match str::from_utf8(get_payload(packet).unwrap()) {
                                    Ok(v) => v,
                                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                                };
                                println!("{:?}", message);
                                lsdb.lock().unwrap().update_state(packet.src(), message);
                                lsdb.lock().unwrap().print_table();
                                // Send back ACK including own table
                                send_neighbor_request(q.clone(), &lsdb, packet.src(), true);
                                */
                            }
                        })
                    }
                    // Same as above, except we do not send an ack. TODO: Remove code duplication
                    GdpAction::LSA_ACK => |group| {
                        group.inspect(|disp| {
                            if let Disposition::Act(packet) = disp {
                                println!("Received LSA Ack...");
                                /*
                                let message = match str::from_utf8(get_payload(packet).unwrap()) {
                                    Ok(v) => v,
                                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                                };
                                println!("{:?}", message);
                                lsdb.lock().unwrap().update_state(packet.src(), message);
                                lsdb.lock().unwrap().print_table();
                                */
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
    let link_state: &'static Arc<Mutex<LinkStateDatabase>> = Box::leak(Box::new(Arc::new(Mutex::new(LinkStateDatabase::new()))));
    // Test
    // link_state.lock().unwrap().add_neighbor("1.1.1.1".parse::<Ipv4Addr>()?);


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
                send_neighbor_request(q.clone(), &link_state, ip, false);
                link_state.lock().unwrap().add_neighbor(ip);
                link_state.lock().unwrap().print_table();
            }
        }
        // Add delay?
        // Send ping packet to target if specified from args.
        match &target {
            None => println!("No ping action."),
            Some(_target_address) => {
                println!("Pinging {}", _target_address);
                let target_address = _target_address.parse::<Ipv4Addr>().unwrap();
                send_test_packet(&q, target_address)
            }
        }

        // Listen to incoming packets
        switch_pipeline(q, &link_state)

    })?
    
    .execute()
}
