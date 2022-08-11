mod packet_receiver;
mod packet_sender;
mod schedule;
mod network_protocols;
mod structs;
mod utils;
mod rib;
mod router_store;
mod ospf;
mod switch;

use std::net::Ipv4Addr;

use anyhow::Result;
use tracing::Level;
use tracing_subscriber::fmt;
use clap::Parser;


/// GDP Switch
#[allow(non_snake_case)]
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Mode of operation: 1 if sending packet, 0 if receiving packet
    #[clap(short, long ,value_parser, default_value_t = 0)]
    mode: u8,

    /// Target switch's ipv4 address if sending packet from current switch
    #[clap(short, long, value_parser)]
    target_ip: Option<String>,

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
    let mut _target_switch_address = Ipv4Addr::UNSPECIFIED;
    let mut _AP_ip = Ipv4Addr::UNSPECIFIED;
    if args.mode == 1 {
        match args.target_ip {
            None => panic!("Intend to send packet, but do not know the target ip. Check cargo run -- --help"),
            Some(ip_as_string) => {
                _target_switch_address = ip_as_string.parse::<Ipv4Addr>()?;
            }
        }
    } 
    else if args.mode == 4 {
        match args.target_ip {
            None => panic!("Intend to send packet, but do not know the target ip. Check cargo run -- --help"),
            Some(ip_as_string) => {
                _target_switch_address = ip_as_string.parse::<Ipv4Addr>()?;
            }
        }
        match args.AP_ip {
            None => panic!("Want to connect this switch to network, but missing access point ip. Check cargo run -- --help"),
            Some(ip_as_string) => {
                _AP_ip = ip_as_string.parse::<Ipv4Addr>()?;
            }
        }
    }


    match args.mode {
        // Receiver mode
        0 => packet_receiver::start_receiver(),

        // Sender mode
        1 => packet_sender::start_sender(_target_switch_address),
        2 => rib::start_rib(),
        3 => switch::start_switch(args.AP_ip, args.target_ip),
        4 => packet_sender::test_forward(_target_switch_address, _AP_ip),
        _ => {
            println!("Not a valid mode, please check --help");
            return Ok(());
        },
    }



    
}