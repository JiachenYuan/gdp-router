use std::net::{Ipv4Addr, IpAddr};
use anyhow::Result;

use capsule::packets::Packet;
use local_ip_address::local_ip;


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
