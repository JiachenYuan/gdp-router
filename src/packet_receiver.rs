use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{Mbuf, PortQueue, Runtime};
use tracing::debug;
use anyhow::Result;
use local_ip_address::local_ip;
use capsule::packets::icmp::v4::{EchoReply, EchoRequest};


#[allow(dead_code)]
fn reply_echo(packet: &Mbuf) -> Result<EchoReply> {
    // TODO: see if packet arrive at all...
    debug!(?packet);

    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;

    println!("{:?}", ethernet.src().octets());
    println!("{:?}", ethernet.dst().octets());

    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv4 = ethernet.peek::<Ipv4>()?;

    // println!("{:?}", ipv4.src());


    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(ipv4.dst());
    reply.set_dst(ipv4.src());
    reply.set_ttl(255);

    let request = ipv4.peek::<EchoRequest>()?;
    let mut reply = reply.push::<EchoReply>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.reconcile_all();

    debug!(?request);
    debug!(?reply);


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

fn pipeline_installer(q: PortQueue) -> impl Pipeline {
    // Get local ip address
    let local_ip_address = query_local_ip_address();
    
    println!("{:?}", local_ip_address);

    Poll::new(q.clone())
    // .replace(reply_echo)
        .map(|packet| {
            packet.parse::<Ethernet>()?.parse::<Ipv4>()
        })
        .filter(move |packet| {
            packet.dst() == local_ip_address
        })
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        .send(q)
}


pub fn start_receiver() -> Result<()> {
    // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;

    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;

    runtime.add_pipeline_to_port("eth1", pipeline_installer)?
        .execute()
}