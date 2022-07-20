use std::net::{Ipv4Addr, IpAddr};

use local_ip_address::local_ip;


pub fn query_local_ip_address() -> Ipv4Addr {
    let my_local_ip = local_ip().unwrap();
    if let IpAddr::V4(ipv4_address) = my_local_ip {
        return ipv4_address;
    } else {
        panic!("Ipv6 address is not yet supported");
    }
}