use std::{collections::Vec, collections::HashMap, net::Ipv4Addr};

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

    pub fn add_neighbor(neighbor: Ipv4Addr) {
        neighbors.push(neighbor);
        // Insert to routing table with edge cost 1 (# jumps)
        routing_table.insert(
            neighbor,
            1,
        );
    }

    pub fn update_state(neighbor_table: &[u8]) {
        // Deserialize
        // Update routing table
    }

    pub fn get_next_hop(dest: Ipv4Addr) -> Ipv4Addr {
        // Search routing table
        match routing_table.get(dest) {
            Some(result) => {
                println!("Next hop: {result.0}");
                return result.0;
            }
            None => println!("No path to {dest}.")
        }
    }
}