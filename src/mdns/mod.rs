use std::net::UdpSocket;

use crate::debug;

mod socket;
mod mdns_error;
mod dns;

use mdns_error::MdnsError;
use socket::{ join_multicast, MULTICAST_IPV4_SOCKET, MULTICAST_IPV6_SOCKET };

pub enum IpVersion
{
    IPV4,
    IPV6
}

pub struct MDnsListener
{
    socket: UdpSocket,
    buffer: [u8; 4096],
}

impl MDnsListener
{
    pub fn new(ip_version: IpVersion) -> Result<Self, MdnsError>
    {
        let socket = match ip_version
        {
            IpVersion::IPV6 => join_multicast(&MULTICAST_IPV6_SOCKET),
            IpVersion::IPV4 => join_multicast(&MULTICAST_IPV4_SOCKET)
        }?;

        let buffer = [0u8; 4096];

        Ok(Self
        {
            socket,
            buffer
        })
    }

    pub fn recv_packet(&mut self) -> Result<(), MdnsError>
    {
        let (count, addr) = self.socket.recv_from(&mut self.buffer)?;
        println!("\nFrom {}", addr);
        let mdns_packet = dns::Mdns::from(self.buffer, count);
        Ok(())
    }
}
