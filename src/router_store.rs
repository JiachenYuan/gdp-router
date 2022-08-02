use std::{collections::{HashMap}, net::Ipv4Addr, sync::RwLock};

use crate::structs::GdpName;

pub struct GdpNameMapping(&'static RwLock<HashMap<GdpName, Ipv4Addr>>);

impl Copy for GdpNameMapping {}
impl Clone for GdpNameMapping {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
    



#[derive(Copy, Clone)]
pub struct Store {
    pub neighbors: GdpNameMapping,
}

impl Store {
    pub fn new() -> Store {
        Store {
            neighbors: GdpNameMapping(Box::leak(Box::new(RwLock::new(HashMap::new())))),
        }
    }

    pub fn get_neighbors(&self) -> &'static RwLock<HashMap<GdpName, Ipv4Addr>> {
        self.neighbors.0
    }
}