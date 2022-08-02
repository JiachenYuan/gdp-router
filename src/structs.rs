use anyhow::{Result, anyhow};
use capsule::{packets::types::u16be, SizeOf};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum GdpAction {
    Ping = 0,
    RibRegister = 1,
    RibRegisterAck = 2,
    PacketForward = 3,
    Noop = 4
}

impl TryFrom<u8> for GdpAction {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(GdpAction::Ping),
            1 => Ok(GdpAction::RibRegister),
            2 => Ok(GdpAction::RibRegisterAck),
            3 => Ok(GdpAction::PacketForward),
            4 => Ok(GdpAction::Noop),
            unknown => Err(anyhow!("Unable to convert number {} into GDPAction. It is undefined", unknown)),
        }
    }
}

pub type GdpName = [u8; 32];

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
pub struct GDPHeader {
    pub action: u8,
    pub data_len: u16be,
    pub src_gdpname: GdpName,
    pub dst_gdpname: GdpName,
}


