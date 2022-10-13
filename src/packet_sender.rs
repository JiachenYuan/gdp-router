
use crate::{schedule::Schedule, utils::query_local_ip_address, network_protocols::gdp::Gdp, structs::{GdpAction, GdpName}};
use std::{net::{Ipv4Addr}, fs, process::Command, time::Duration};

use anyhow::Result;
use capsule::{batch::{self, Batch, Pipeline}, Mbuf, packets::{Udp, ip::v4::Ipv4, Packet, Ethernet}, net::MacAddr, Runtime, PortQueue};
use tokio_timer::delay_for;







// pub fn send_packet_to(q: PortQueue, target_address: Ipv4Addr, num_packets: usize){
//     let src_mac = q.mac_addr();
//     let src_ip = query_local_ip_address();
//     // TODO: this is hardcoded mac address for broadcasting purposes
//     let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
//     let dst_ip = target_address;
//     // TODO: this is hardcoded payload size, not sure how to change it
//     let payload_size = 25;

//     batch::poll_fn(|| Mbuf::alloc_bulk(num_packets).unwrap())
//         .map(move |packet| {
//             prepare_ping_packet(packet, src_mac, src_ip, dst_mac, dst_ip, payload_size)
//         })
//         .send(q)
//         .run_once();
// }

fn send_test_packet(q: &PortQueue, access_point_addr: Ipv4Addr, target: GdpName) {
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_gdpname = target;
    let payload_size = 25;

    batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
        .map(move |packet| {
            prepare_test_packet(packet, src_mac, src_ip, dst_mac, dst_gdpname, access_point_addr, payload_size)
        })
        .send(q.clone())
        .run_once();
}

// fn prepare_ping_packet(
//     reply: Mbuf,
//     src_mac: MacAddr,
//     src_ip: Ipv4Addr,
//     dst_mac: MacAddr,
//     dst_ip: Ipv4Addr,
//     payload_size: usize
// ) -> Result<Gdp<Udp<Ipv4>>> {

//     let mut reply = reply.push::<Ethernet>()?;
//     reply.set_src(src_mac);
//     reply.set_dst(dst_mac);

//     let mut reply = reply.push::<Ipv4>()?;
//     reply.set_src(src_ip);
//     reply.set_dst(dst_ip);

//     let mut reply = reply.push::<Udp<Ipv4>>()?;
//     reply.set_src_port(31415);
//     reply.set_dst_port(31415);

//     // Setting Gdp-related information in the GDP header
//     let mut reply = reply.push::<Gdp<Udp<Ipv4>>>()?;
//     reply.set_action(GdpAction::Ping);
//     reply.set_data_len(payload_size);
//     reply.set_src(src_ip);
//     reply.set_dst(dst_ip);

//     let offset = reply.payload_offset();

//     let message = "this is a ping message...".as_bytes(); // This message has length 25 bytes, == payload_size

//     reply.mbuf_mut().extend(offset, payload_size)?;
//     reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;
    
//     reply.reconcile_all();

//     Ok(reply)

// }


fn prepare_test_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_gdpname: GdpName,
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
    reply.set_src([255u8; 32]); // ! this packet sender always has gdpname [255u8; 32]
    reply.set_dst(dst_gdpname);

    let offset = reply.payload_offset();

    let message = "this is a ping message...".as_bytes(); // This message has length 25 bytes, == payload_size

    reply.mbuf_mut().extend(offset, payload_size)?;
    reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;
    
    reply.reconcile_all();

    Ok(reply)
}


// pub fn start_sender(target_address: Ipv4Addr) -> Result<()> {
//     // Reading Runtime configuration file
//     let path = "runtime_config.toml";
//     let content = fs::read_to_string(path)?;
//     let config = toml::from_str(&content)?;
//     // Build the Runtime
//     let mut runtime = Runtime::build(config)?;
    

//     // connect physical NICs to TAP interfaces
//     // Note:  only packet sent to port 31415 will be received
//     Command::new("./init_tuntap.sh").output()?;

//     runtime.add_pipeline_to_port("eth1", move |q| {
//         Schedule::new("initial_packet_schedule", async move {
//             delay_for(Duration::from_millis(1000)).await;
//             println!("sending initial packet 1");
//             send_packet_to(q.clone(), target_address, 1);
//             delay_for(Duration::from_millis(1000)).await;
//             println!("sending initial packet 2");
//             send_packet_to(q.clone(), target_address, 1);
//             delay_for(Duration::from_millis(1000)).await;
//             println!("sending initial packet 3");
//             send_packet_to(q.clone(), target_address, 1);
//             delay_for(Duration::from_millis(1000)).await;
//             println!("sending initial packet 4");
//             send_packet_to(q.clone(), target_address, 1);
//             delay_for(Duration::from_millis(1000)).await;
//             println!("sending initial packet 5");
//             send_packet_to(q.clone(), target_address, 1);
//         })

//     })?
//     .execute()
//     Ok(())

// }

pub fn test_forward(target: GdpName, access_point_address: Ipv4Addr) -> Result<()> {
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
        Schedule::new("initial_packet_schedule", async move {
            delay_for(Duration::from_millis(1000)).await;
            println!("sending initial packet 1");
            send_test_packet(&q, access_point_address, target);
            delay_for(Duration::from_millis(1000)).await;
            println!("sending initial packet 2");
            send_test_packet(&q, access_point_address, target);
            delay_for(Duration::from_millis(1000)).await;
            println!("sending initial packet 3");
            send_test_packet(&q, access_point_address, target);
            delay_for(Duration::from_millis(1000)).await;
            println!("sending initial packet 4");
            send_test_packet(&q, access_point_address, target);
            delay_for(Duration::from_millis(1000)).await;
            println!("sending initial packet 5");
            send_test_packet(&q, access_point_address, target);
        })

    })?
    .execute()

}

