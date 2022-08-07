use anyhow::{Result, anyhow};
use capsule::{packets::types::u16be, SizeOf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum GdpAction {
    Ping = 0,
    Register = 1,
    RegisterAck = 2,
    PacketForward = 3,
    Noop = 4
}

impl TryFrom<u8> for GdpAction {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(GdpAction::Ping),
            1 => Ok(GdpAction::Register),
            2 => Ok(GdpAction::RegisterAck),
            3 => Ok(GdpAction::PacketForward),
            4 => Ok(GdpAction::Noop),
            unknown => Err(anyhow!("Unable to convert number {} into GDPAction. It is undefined", unknown)),
        }
    }
}

pub type GdpName = [u8; 32];
pub type Uuid = [u8; 16];

#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
pub struct GDPHeader {
    pub src_gdpname: GdpName,
    pub dst_gdpname: GdpName,
    pub uuid: Uuid, // 128-bit uuid
    pub num_packets: i32,
    pub packet_no: i32,
    pub data_len: u16be,
    pub action: u8,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct GdpMeta {
    pub pub_key: [u8; 32], // TODO: compute hash on initialization
}

impl GdpMeta {
    // For now gdp name is just the hashed public key
    pub fn hash(&self) -> GdpName {
        let mut hasher = Sha256::new();
        hasher.update(self.pub_key);
        hasher.finalize().into()
    }
}
