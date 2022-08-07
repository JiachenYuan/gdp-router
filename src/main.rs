mod packet_receiver;
mod packet_sender;
mod schedule;
mod network_protocols;
mod structs;
mod utils;
mod access_point;
mod router_store;
mod switch;
mod certificates;

mod test_certificates;

use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;
use tracing::Level;
use tracing_subscriber::fmt;
use clap::Parser;

use crate::{switch::start_switch, access_point::start_access_point, packet_sender::test_forward, utils::gdpname_hex_to_byte_array};


/// GDP Switch
#[allow(non_snake_case)]
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Mode of operation: 0 to start a switch, 1 to start an access point, 2 to send a packet
    #[clap(short, long ,value_parser, default_value_t = 0)]
    mode: u8,

    /// Target switch if sending packet from current node
    #[clap(short, long, value_parser)]
    target: Option<String>,

    /// Access point's ipv4 address if sending packet from current switch
    #[clap(short, long, value_parser)]
    AP_ip: Option<String>,
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    println!("{:?}", args);
    
    // todo: Perform argument validation and cleaning
    match args.mode {
        0 => {
            let access_point_addr = Ipv4Addr::from_str(&args.AP_ip.unwrap()).unwrap();
            start_switch(access_point_addr)?;
        },
        
        1 => {
            start_access_point()?;
        },

        2 => {
            let target_gdpname = gdpname_hex_to_byte_array(&args.target.unwrap());
            println!("Parsed GdpName is {:?}", target_gdpname);
            let access_point_addr = Ipv4Addr::from_str(&args.AP_ip.unwrap()).unwrap();
            test_forward(target_gdpname, access_point_addr)?;
        }

        invalid => panic!("Mode {:?} is not recognized", invalid),
    }


    Ok(())



    
}
