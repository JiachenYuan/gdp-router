use std::{net::{Ipv4Addr, IpAddr}, fs, process::Command};

use anyhow::Result;
use capsule::{batch::{self, Batch, Pipeline, Poll}, Mbuf, packets::{Udp, ip::v4::Ipv4, Packet, Ethernet}, net::MacAddr, Runtime, PortQueue};
use local_ip_address::local_ip;

const MSG: &[u8] = &[b'A'; 10000];



pub fn start_sender(target_address: Ipv4Addr) -> Result<()> {
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
        send_packet_to(q, target_address, 1);

        // TODO: This following pipeline is useless, not sure how to only send a packet...
        // Poll::new(q.clone()).send(q)

    })?
    .execute()

}

fn send_packet_to(q: PortQueue, target_address: Ipv4Addr, num_packets: usize){
    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    // TODO: this is hardcoded mac address for broadcasting purposes
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = target_address;
    // TODO: this is hardcoded payload size, not sure how to change it
    let payload_size = 800;

    batch::poll_fn(|| Mbuf::alloc_bulk(num_packets).unwrap())
        .map(move |packet| {
            prepare_packet(packet, src_mac, src_ip, dst_mac, dst_ip, payload_size)
        })
        .send(q)
        .run_once();
}

fn prepare_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    payload_size: usize
) -> Result<Udp<Ipv4>> {
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(src_mac);
    reply.set_dst(dst_mac);

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(src_ip);
    reply.set_dst(dst_ip);

    let mut reply = reply.push::<Udp<Ipv4>>()?;
    reply.set_src_port(31415);
    reply.set_dst_port(31415);

    let offset = reply.payload_offset();

    let message = MSG;

    reply.mbuf_mut().extend(offset, payload_size)?;
    reply.mbuf_mut().write_data_slice(offset, &message[..payload_size])?;
    
    reply.reconcile_all();

    Ok(reply)

}


fn query_local_ip_address() -> Ipv4Addr {
    let my_local_ip = local_ip().unwrap();
    if let IpAddr::V4(ipv4_address) = my_local_ip {
        return ipv4_address;
    } else {
        panic!("Ipv6 address is not yet supported");
    }
}

