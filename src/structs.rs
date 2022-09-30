use std::net::Ipv4Addr;
use anyhow::{Result, anyhow};
use capsule::{packets::types::u16be, SizeOf};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum GdpAction {
    Ping = 0,
    RibRegister = 1,
    RibRegisterAck = 2,
    PacketForward = 3,
    LSA = 4,
    LSA_ACK = 5,
}

impl TryFrom<u8> for GdpAction {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(GdpAction::Ping),
            1 => Ok(GdpAction::RibRegister),
            2 => Ok(GdpAction::RibRegisterAck),
            3 => Ok(GdpAction::PacketForward),
            4 => Ok(GdpAction::LSA),
            5 => Ok(GdpAction::LSA_ACK),
            unknown => Err(anyhow!("Unable to convert number {} into GDPAction. It is undefined", unknown)),
        }
    }
}

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
pub struct GDPHeader {
    pub action: u8,
    pub data_len: u16be,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}


