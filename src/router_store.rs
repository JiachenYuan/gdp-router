use std::{collections::{HashMap, HashSet}, net::Ipv4Addr, sync::RwLock};

use crate::structs::GdpName;

pub struct GdpNameMapping(&'static RwLock<HashMap<GdpName, Ipv4Addr>>);
pub struct TopicInfo(&'static RwLock<HashMap<GdpName, HashMap<String, HashSet<GdpName>>>>);

pub struct TopicNameMapping(&'static RwLock<HashMap<String, GdpName>>);

impl Copy for GdpNameMapping {}
impl Clone for GdpNameMapping {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Copy for TopicInfo {}
impl Clone for TopicInfo {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Copy for TopicNameMapping {}
impl Clone for TopicNameMapping {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
    



#[derive(Copy, Clone)]
pub struct Store {
    pub neighbors: GdpNameMapping,
    pub topic_info: TopicInfo,
    pub topic_name_map: TopicNameMapping,
}

impl Store {
    pub fn new() -> Store {

        Store {
            neighbors: GdpNameMapping(Box::leak(Box::new(RwLock::new(HashMap::new())))),
            topic_info: TopicInfo(Box::leak(Box::new(RwLock::new(HashMap::new())))),
            topic_name_map: TopicNameMapping(Box::leak(Box::new(RwLock::new(HashMap::new()))))
        }
    }

    pub fn get_neighbors(&self) -> &'static RwLock<HashMap<GdpName, Ipv4Addr>> {
        self.neighbors.0
    }

    pub fn get_topic_info(&self) -> &'static RwLock<HashMap<GdpName, HashMap<String, HashSet<GdpName>>>> {
        self.topic_info.0
    }

    pub fn get_topic_name_map(&self) -> &'static RwLock<HashMap<String, GdpName>> {
        self.topic_name_map.0
    }
}