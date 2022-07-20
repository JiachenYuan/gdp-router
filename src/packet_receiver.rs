use std::fs;
use std::process::Command;
use capsule::batch::{Batch, Pipeline, Poll, Disposition};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Udp};
use capsule::{PortQueue, Runtime};
use tracing::debug;
use anyhow::Result;


use crate::network_protocols::gdp::Gdp;
use crate::utils::query_local_ip_address;



fn pipeline_installer(q: PortQueue) -> impl Pipeline {
    // Get local ip address
    let local_ip_address = query_local_ip_address();
    
    println!("My own ip is {:?}", local_ip_address);

    Poll::new(q.clone())
        .map(|packet| {
            packet.parse::<Ethernet>()?.parse::<Ipv4>()
        })
        .filter(move |packet| {
            packet.dst() == local_ip_address
        })
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        // .inspect(|disp|{
        //     if let Disposition::Act(udp_packet) = disp {
        //         debug!("Incoming payload size: {}", udp_packet.payload_len());
        //         let offset = udp_packet.payload_offset();
        //         let msg:&[u8] = unsafe {udp_packet.mbuf().read_data_slice(offset, 800).unwrap().as_ref()};
        //         println!("{:?}", msg);
        //     }
        // })
        .map(|packet| packet.parse::<Gdp<Udp<Ipv4>>>())
        .inspect(|disp| {
            if let Disposition::Act(gdp_packet) = disp {
                debug!("GDP action is {:?}", gdp_packet);
            }
        })
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