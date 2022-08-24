use anyhow::{Result, anyhow};
use capsule::SizeOf;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum GdpAction {
    Ping = 0,
    Register = 1,
    RegisterAck = 2,
    PacketForward = 3,
    Noop = 4
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct u16be(u16);

impl From<u16> for u16be {
    fn from(item: u16) -> Self {
        u16be(u16::to_be(item))
    }
}

impl From<u16be> for u16 {
    fn from(item: u16be) -> Self {
        u16::from_be(item.0)
    }
}

impl TryFrom<u16be> for GdpAction {
    type Error = anyhow::Error;

    fn try_from(v: u16be) -> Result<Self> {
        match v {
            u16be(0) => Ok(GdpAction::Ping),
            u16be(1) => Ok(GdpAction::Register),
            u16be(2) => Ok(GdpAction::RegisterAck),
            u16be(3) => Ok(GdpAction::PacketForward),
            u16be(4) => Ok(GdpAction::Noop),
            unknown => Err(anyhow!("Unable to convert number {:?} into GDPAction. It is undefined", unknown.0)),
        }
    }
}

pub type GdpName = [u8; 32];
pub type Uuid = [u8; 16];

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
pub struct GDPHeader {
    pub action: u16be,
    pub data_len: u16be,
    pub src_gdpname: GdpName,
    pub dst_gdpname: GdpName,
    pub num_packets: i32,
    pub packet_no: i32,
    pub uuid: Uuid // 128-bit uuid
}


