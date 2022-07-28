use std::{collections::HashSet, net::Ipv4Addr};

pub struct Store {
    pub neighbors: HashSet<Ipv4Addr>,
}

impl Store {
    pub fn new() -> Store {
        Store {
            neighbors: HashSet::new(),
        }
    }
}