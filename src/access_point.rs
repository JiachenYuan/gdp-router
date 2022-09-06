use std::{fs, process::Command, net::Ipv4Addr, collections::{HashMap, HashSet}, hash::Hash};
use anyhow::Result;
use tracing::debug;
use capsule::{batch::{Pipeline, Poll, Batch, Either, self}, PortQueue, Runtime, packets::{Ethernet, Packet, ip::v4::Ipv4, Udp}, Mbuf, net::MacAddr};
use ethereum_types::U256;
use serde::{Deserialize, Serialize};
use crate::{utils::{query_local_ip_address, get_payload, ipv4_addr_from_bytes, generate_gdpname}, network_protocols::gdp::Gdp, structs::{GdpAction, GdpName}, router_store::Store,};
use crate::pipeline;


fn register_neighbor(src_gdpname: [u8; 32], ip_addr: Ipv4Addr, store: Store) {
    store.get_neighbors().write().unwrap().insert(src_gdpname, ip_addr);
    // printing current registered switch's ip
    println!("Current registered switch: {:?}", store.get_neighbors().read().unwrap());
}

fn prepare_ack_packet(
    reply: Mbuf,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    dst_gdpname: GdpName) -> Result<Gdp<Udp<Ipv4>>> {

        let mut reply = reply.push::<Ethernet>()?;
        reply.set_src(src_mac);
        reply.set_dst(dst_mac);
    
        let mut reply = reply.push::<Ipv4>()?;
        reply.set_src(src_ip);
        reply.set_dst(dst_ip);
    
        let mut reply = reply.push::<Udp<Ipv4>>()?;
        reply.set_src_port(31415);
        reply.set_dst_port(31415);
    
        // Setting Gdp-related information in the GDP header
        let mut reply = reply.push::<Gdp<Udp<Ipv4>>>()?;
        reply.set_action(GdpAction::RegisterAck);
        reply.set_data_len(4);

        reply.set_dst(dst_gdpname);
    
        let offset = reply.payload_offset();
    
        let message = src_ip.octets();
    
        reply.mbuf_mut().extend(offset, message.len())?;
        reply.mbuf_mut().write_data_slice(offset, &message[..message.len()])?;
        
        reply.reconcile_all();
    
        Ok(reply)
    }


fn register_and_ack(q: &PortQueue, packet: &Gdp<Udp<Ipv4>>, store: Store) -> Result<()> {
    let message:&[u8] = get_payload(packet)?;
    let sender_ip = ipv4_addr_from_bytes(message.try_into().unwrap());
    let src_gdpname = packet.src();
    println!("{:?} wants to register", sender_ip);

    register_neighbor(src_gdpname, sender_ip, store);


    let src_mac = q.mac_addr();
    let src_ip = query_local_ip_address();
    let packet_ip_layer = packet.envelope().envelope();
    let dst_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let dst_ip = packet_ip_layer.src();

    println!("sending back the acknowledgement");

    // batch::poll_fn(|| Mbuf::alloc_bulk(1).unwrap())
    //     .map(move |reply| {
    //         prepare_ack_packet(reply, src_mac, src_ip, dst_mac, dst_ip, src_gdpname)
    //     })
    //     .send(q.clone())
    //     .run_once();

    Ok(())
}


fn prepare_packet_forward_if_needed(q: &PortQueue, local_gdpname: GdpName, mut packet: Gdp<Udp<Ipv4>>, store: Store) -> Result<Gdp<Udp<Ipv4>>> {
    let intended_gdpname = packet.dst();
    let local_ip = query_local_ip_address();
    // println!("Forwarding... Inteded target: {:?}", intended_gdpname);
    // Currently only supports one level forward
    if intended_gdpname != local_gdpname {
        let gdpname_hash_map = store.get_neighbors().read().unwrap();
        
        // println!("Current neighbors: {:?}", *gdpname_hash_map);
        let ip_layer = packet.envelope_mut().envelope_mut();
        ip_layer.set_src(local_ip);
        // Query local router store to get neighbor's ip
        let new_dst_ip = gdpname_hash_map.get(&intended_gdpname);
        match new_dst_ip {
            Some(target_switch_ip) => {
                println!("Forwarding to {:?}", intended_gdpname);
                // println!("Adjusting destination");
                ip_layer.set_dst(*target_switch_ip);
                let ether_layer = ip_layer.envelope_mut();
                ether_layer.set_src(q.mac_addr());
                ether_layer.set_dst(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            },
            None => {
                // Just do broadcasting... Very wasteful
                println!("Didn't find recipient on my side, broadcasting");
                ip_layer.set_dst(Ipv4Addr::BROADCAST);
                let ether_layer = ip_layer.envelope_mut();
                ether_layer.set_src(q.mac_addr());
                ether_layer.set_dst(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
            }
        }
    }
    // It's broadcasting the forwarded packet, letting switch filtering the packet themselves...

    Ok(packet)
}



#[derive(Debug, Deserialize, Serialize)]
struct TopicAdvertise {
    topic_name: String,
    topic_gdpname: Vec<u8>,
    is_pub: String,
}

fn register_topic(client_gdpname: GdpName, topic_request: TopicAdvertise, store: Store) -> Result<()>{
    let mut topic_gdpname: [u8; 32] = [0; 32];
    for i in 0..32 {
        topic_gdpname[i] = *topic_request.topic_gdpname.get(i).unwrap();
    }
    
    let mut router_info = store.get_topic_info().write().unwrap();
    let mut topic_name_map = store.get_topic_name_map().write().unwrap();

    if topic_request.topic_name != "__" {
        topic_name_map.insert(topic_request.topic_name.clone(), topic_gdpname);
        let hashset_pub: HashSet<GdpName> = HashSet::new();
        let hashset_sub: HashSet<GdpName> = HashSet::new();
        let mut pub_sub_map = HashMap::new();
        pub_sub_map.insert("publisher".to_string(), hashset_pub);
        pub_sub_map.insert("subscriber".to_string(), hashset_sub);
        router_info.insert(topic_gdpname, pub_sub_map);
    }

    if topic_request.is_pub == "1".to_string() {
        let set = router_info.get_mut(&topic_gdpname).unwrap().get_mut("publisher").unwrap();
        set.insert(client_gdpname);
    } else {
        let set = router_info.get_mut(&topic_gdpname).unwrap().get_mut("subscriber").unwrap();
        set.insert(client_gdpname);
    }

    
    println!("topic_name_map is = {:?}\n", topic_name_map);
    println!("router_info is = {:?}\n\n", router_info);

    Ok(())
}




fn pipeline_installer(q: PortQueue, gdpname: GdpName, store: Store) -> impl Pipeline {
    let local_ip_address = query_local_ip_address();
    let locao_ip_address_clone = local_ip_address.clone();
    let q_clone_for_closure1 = q.clone();
    let q_clone_for_closure2 = q.clone();
    let local_mac_addr = q.mac_addr();

    Poll::new(q.clone())
        .map(|packet| {
            packet.parse::<Ethernet>()?.parse::<Ipv4>()
        })
        .filter(move |packet| {
            packet.dst() == local_ip_address
        })
        .map(|packet| packet.parse::<Udp<Ipv4>>())
        .map(|packet| packet.parse::<Gdp<Udp<Ipv4>>>())
      
        .group_by(
             move |packet| packet.action().unwrap_or(GdpAction::Noop), 
                pipeline! {
                            GdpAction::Register => |group| {
                                group.for_each(move |register_packet| {
                                    println!("processing switch register request");
                                    register_and_ack(&q_clone_for_closure1, register_packet, store)
                                })
                            }
                            ,
                            GdpAction::TopicAdvertise => |group| {
                                group.for_each(move |packet| {
                                    let payload = get_payload(packet).unwrap();
                                    let json_string = std::str::from_utf8(payload).unwrap();
                                    let topic_request:TopicAdvertise = serde_json::from_str(json_string).unwrap();
                                    register_topic(packet.src(), topic_request, store)
                                })
                            }
                            ,
                            GdpAction::TopicMessage => |group| {
                                group.map(move |mut packet| {
                                    let topic_gdpname = packet.dst();
                                    // let router_info = store.get_topic_info().read().unwrap();
                                    // let subscriber_gdpnames = router_info.get(&topic_gdpname).unwrap().get("subscriber").unwrap();
                                    // todo: Currently not using subscriber gdpnames, just broadcasting. 
                                    // let payload = get_payload(&packet).unwrap();
                                    debug!("Received topic message, broadcasting...");
                                    packet.set_src(topic_gdpname.clone());
                                    packet.set_dst([0u8;32]);
                                    let ip_layer = packet.envelope_mut().envelope_mut();
                                    ip_layer.set_src(locao_ip_address_clone);
                                    ip_layer.set_dst(Ipv4Addr::BROADCAST);
                                    let ether_layer = ip_layer.envelope_mut();
                                    ether_layer.set_src(local_mac_addr.clone());
                                    ether_layer.set_dst(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                                    debug!("Message broadcasted..");
                                    Ok(packet)
                                })
                            }
                            ,
                            _ => |group| {
                                group.map(move |packet| {
                                    prepare_packet_forward_if_needed(&q_clone_for_closure2, gdpname, packet, store)
                                })
                            }
                        }
                    
        )
        .send(q)
}



pub fn start_access_point() -> Result<()> {
    // Reading Runtime configuration file
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    // Build the Runtime
    let mut runtime = Runtime::build(config)?;

    println!("I'm a public access point, my ip is: {:?}", query_local_ip_address());

    // connect physical NICs to TAP interfaces
    // Note:  only packet sent to port 31415 will be received
    Command::new("./init_tuntap.sh").output()?;

    // Obtain local IPv4 address
    let local_ip = query_local_ip_address();

    // Obtain GDPName
    let gdpname = generate_gdpname(&local_ip);

    // Initialize shared information store
    let store = Store::new();

    runtime.add_pipeline_to_port("eth1", move |q|{
        pipeline_installer(q.clone(), gdpname, store)
    })?
        .execute()
}