use std::{collections::HashMap, net::Ipv4Addr};
use crate::utils::query_local_ip_address;
use serde::{Deserialize, Serialize};
use serde_json::Result;

#[derive(Clone)]
pub struct LinkStateDatabase {
    pub neighbors: Vec<Ipv4Addr>,
    pub routing_table: HashMap<Ipv4Addr, (Ipv4Addr, u8)>
}

impl LinkStateDatabase {
    pub fn new() -> LinkStateDatabase {
        LinkStateDatabase {
            neighbors: Vec::new(),
            routing_table: HashMap::from([
                (query_local_ip_address(), (query_local_ip_address(), 0)),
            ])
        }
    }

    pub fn add_neighbor(&mut self, neighbor_ip: Ipv4Addr) {
        self.neighbors.push(neighbor_ip);
        // Insert to routing table with edge cost 1 (# jumps)
        self.routing_table.insert(
            neighbor_ip,
            (
                neighbor_ip,
                1,
            )
        );
    }

    pub fn update_state(&mut self, neighbor_ip: Ipv4Addr, neighbor_table: &str) {
        // Deserialize
        let table = serde_json::from_str::<HashMap<Ipv4Addr, (Ipv4Addr, u8)>>(neighbor_table).unwrap();

        // Update routing table
        for (dest, (next, cost)) in table {
            if !self.routing_table.contains_key(&dest) {
                self.routing_table.insert(
                    dest,
                    (
                        neighbor_ip,
                        cost + 1,
                    )
                );
            }   
        }

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

    pub fn table_as_str(self) -> String {
        return serde_json::to_string(&(self.routing_table)).unwrap();
    }
}
