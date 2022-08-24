use anyhow::{Result, anyhow};
use capsule::{packets::types::u16be, SizeOf};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum GdpAction {
    Ping = 0,
    Register = 1,
    RegisterAck = 2,
    PacketForward = 3,
    Noop = 4
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
            unknown => Err(anyhow!("Unable to convert number {} into GDPAction. It is undefined", unknown)),
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


