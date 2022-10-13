use std::{net::{Ipv4Addr, IpAddr}, collections::HashMap};
use anyhow::Result;

use capsule::{packets::{Packet, Udp, ip::v4::Ipv4}, batch::GroupByBatchBuilder};
use local_ip_address::local_ip;
use sha2::{Sha256, Digest};
use chrono::prelude::*;
use std::convert::TryInto;

use crate::{network_protocols::gdp::Gdp, structs::{GdpAction, GdpName, Uuid}};


pub type GdpGroupAction<U> = Box<GroupByBatchBuilder<U>>;
pub type GdpMap<T> = HashMap<Option<T>, GdpGroupAction<Gdp<Udp<Ipv4>>>>;
pub trait GdpPipeline: FnOnce(&mut GdpMap<GdpAction>) {}

impl<T: FnOnce(&mut GdpMap<GdpAction>)> GdpPipeline for T {}


pub fn query_local_ip_address() -> Ipv4Addr {
    let my_local_ip = local_ip().unwrap();
    if let IpAddr::V4(ipv4_address) = my_local_ip {
        return ipv4_address;
    } else {
        panic!("Ipv6 address is not yet supported");
    }
}



pub fn get_payload(packet: &impl Packet) -> Result<&[u8]> {
    let data = packet
        .mbuf()
        .read_data_slice(packet.payload_offset(), packet.payload_len())?;
    Ok(unsafe { data.as_ref() })
}

pub fn set_payload(packet: &mut impl Packet, data: &[u8]) -> Result<()> {
    packet.remove_payload()?;
    let payload_offset = packet.payload_offset();
    packet.mbuf_mut().extend(payload_offset, data.len())?;
    packet.mbuf_mut().write_data_slice(payload_offset, data)?;
    Ok(())
}


/**
 * Generate and print a 256 bit string using SHA-256 with information about current time and switch's IP
 */
pub fn generate_gdpname(address: &Ipv4Addr) -> GdpName {

    let now_utc: DateTime<Utc> = Utc::now();

    let hash = Sha256::new()
        .chain_update(address.to_string())
        .chain_update(now_utc.to_rfc2822())
        .finalize();

    println!("SHA256 generated GDPName: {:x}", hash);

    let val: [u8; 32] = hash.as_slice().try_into().expect("Wrong length");

    return val;
}


pub fn ipv4_addr_from_bytes(bytes: &[u8; 4]) -> Ipv4Addr {
    let mut first_four_octats: [u8; 4] = [0; 4];
    first_four_octats[0] = bytes[0];
    first_four_octats[1] = bytes[1];
    first_four_octats[2] = bytes[2];
    first_four_octats[3] = bytes[3];
    
    Ipv4Addr::from(first_four_octats)
}

pub fn gdpname_hex_to_byte_array(hex: &str) -> GdpName {
    let mut target_gdpname = [0u8; 32];
    hex::decode_to_slice(hex, &mut target_gdpname).expect("Decoding failed");
    target_gdpname
}

pub fn gdpname_byte_array_to_hex(gdpname: GdpName) -> String {
    hex::encode(gdpname)
}

pub fn uuid_byte_array_to_hex(uuid: Uuid) -> String {
    hex::encode(uuid)
}





#[doc(hidden)]
#[macro_export]
macro_rules! __move_compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $(
            $map.insert(Some($key), Box::new(move |$arg| Box::new($body)));
        )*
    }};
}


/// Composes the batch builders for the [`group_by`] combinator.
///
/// [`group_by`]: crate::batch::Batch::group_by
#[macro_export]
macro_rules! compose {
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ }) => {{
        $crate::__move_compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|group| Box::new(group)));
    }};
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ _ => |$_arg:tt| $_body:block }) => {{
        $crate::__move_compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block }) => {{
        $crate::compose!($map { $($key => |$arg| $body)+ });
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block _ => |$_arg:tt| $_body:block }) => {{
        $crate::compose!($map { $($key => |$arg| $body)+ _ => |$_arg| $_body });
    }};
    ($map:ident { _ => |$_arg:tt| $_body:block }) => {{
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
}


pub fn constrain<T, F>(f: F) -> F
where
    F: for<'a> FnOnce(&'a mut GdpMap<T>),
{
    f
}

#[macro_export]
macro_rules! pipeline {
    { $($key:expr => |$arg:tt| $body:block),+ $(,)? } => {$crate::utils::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|group| Box::new(group)));
    })};
    { $($key:expr => |$arg:tt| $body:block),+ $(,)? _ => |$_arg:tt| $_body:block } => {$crate::utils::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(move |$_arg| Box::new($_body)));
    })};
}