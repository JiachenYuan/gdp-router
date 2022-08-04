use std::{collections::HashMap, net::Ipv4Addr};

pub struct LinkStateDatabase {
    pub neighbors: Vec<Ipv4Addr>,
    pub routing_table: HashMap<Ipv4Addr, (Ipv4Addr, u8)>
}

impl LinkStateDatabase {
    pub fn new() -> LinkStateDatabase {
        LinkStateDatabase {
            neighbors: Vec::new(),
            routing_table: HashMap::new(),
        }
    }

    pub fn add_neighbor(&mut self, neighbor: Ipv4Addr) {
        self.neighbors.push(neighbor);
        // Insert to routing table with edge cost 1 (# jumps)
        self.routing_table.insert(
            neighbor,
            (
                neighbor,
                1,
            )
        );
    }

    pub fn update_state(&mut self, neighbor_table: &[u8]) {
        // Deserialize
        // Update routing table
    }

    pub fn get_next_hop(&mut self, dest: Ipv4Addr) -> Option<Ipv4Addr> {
        // Search routing table
        match self.routing_table.get(&dest) {
            Some(result) => {
                let next_hop = result.0;
                println!("Next hop: {next_hop}");
                return Some(next_hop);
            }
            None => {
                println!("No path to {:?}.", dest);
                return None;
            }
        }
    }
}
