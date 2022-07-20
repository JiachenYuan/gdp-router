use std::net::Ipv4Addr;
use anyhow::{Result, anyhow};
use capsule::{packets::types::u16be, SizeOf};

#[derive(Debug)]
pub enum GDPAction {
    Ping = 0,
    RibRegister = 1,
    RibRegisterAck = 2,
}

impl TryFrom<u8> for GDPAction {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(GDPAction::Ping),
            1 => Ok(GDPAction::RibRegister),
            2 => Ok(GDPAction::RibRegisterAck),
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


