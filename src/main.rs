use anyhow::Result;
use capsule::batch::{Batch, Pipeline, Poll};
use capsule::config::load_config;
use capsule::packets::icmp::v4::{EchoReply, EchoRequest};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet};
use capsule::{Mbuf, PortQueue, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: &Mbuf) -> Result<EchoReply> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv4 = ethernet.peek::<Ipv4>()?;
    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(ipv4.dst());
    reply.set_dst(ipv4.src());
    reply.set_ttl(255);

    let request = ipv4.peek::<EchoRequest>()?;
    let mut reply = reply.push::<EchoReply>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.reconcile_all();

    debug!(?request);
    debug!(?reply);

    Ok(reply)
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q.clone()).replace(reply_echo).send(q)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", install)?
        .execute()
}