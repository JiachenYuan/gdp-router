use std::{ptr::NonNull, net::Ipv4Addr, fmt};
use anyhow::Result;
use capsule::{packets::{Packet, Internal, Udp, ip::v4::Ipv4, types::u16be}, SizeOf};

use crate::structs::{GDPHeader, GDPAction};

pub struct Gdp<T: Packet> {
    envelope: T,
    header: NonNull<GDPHeader>,
    offset: usize,
}

impl<T: Packet> Gdp<T> {
    #[inline]
    fn header(&self) -> &GDPHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut GDPHeader {
        unsafe { self.header.as_mut() }
    }

    #[inline]
    pub fn action(&self) -> Result<GDPAction> {
        self.header().action.try_into()
    }

    #[inline]
    pub fn set_action(&mut self, action: GDPAction) {
        self.header_mut().action = action as u8;
    }

    #[inline]
    pub fn src(&self) -> Ipv4Addr {
        self.header().src
    }

    #[inline]
    pub fn set_src(&mut self, src: Ipv4Addr) {
        self.header_mut().src = src;
    }

    #[inline]
    pub fn dst(&self) -> Ipv4Addr {
        self.header().dst
    }

    #[inline]
    pub fn set_dst(&mut self, dst: Ipv4Addr) {
        self.header_mut().dst = dst;
    }

    #[inline]
    pub fn data_len(&self) -> usize {
        u16::from(self.header().data_len) as usize
    }

    #[inline]
    pub fn set_data_len(&mut self, payload_size: usize) {
        self.header_mut().data_len = (payload_size as u16).into();
    }

}










/* Override methods that all Packet objects should have */

impl<T: Packet> Packet for Gdp<T> {
    type Envelope = T;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn header_len(&self) -> usize {
        GDPHeader::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Gdp {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let out = Gdp {
            envelope,
            header,
            offset,
        };

        Ok(out)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, GDPHeader::size_of())?;
        let header = mbuf.write_data(offset, &GDPHeader { action: 0, data_len: u16be::MIN, src: Ipv4Addr::LOCALHOST, dst: Ipv4Addr::LOCALHOST })?;

        Ok(Gdp {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    #[inline]
    fn reconcile(&mut self) {
        
    }
}



impl fmt::Debug for Gdp<Udp<Ipv4>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let udp = self.envelope().envelope();
        let ipv4 = udp.envelope();
        let ethernet = ipv4.envelope();
        f.debug_struct("gdp")
            .field("src", &self.src())
            .field("dst", &self.dst())
            .field("data_len", &self.data_len())
            .field("udp_frame", udp)
            .field("ipv4_frame", ipv4)
            .field("eth_frame", ethernet)
            .finish()
    }
}