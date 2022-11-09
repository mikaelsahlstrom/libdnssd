#[macro_use]
extern crate lazy_static;
extern crate socket2;

use std::{ net::{ IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr }, io::Read };
use socket2::{ Socket, Domain, Type, Protocol, SockAddr };

mod hex;

const MULTICAST_PORT: u16 = 5353;
lazy_static!
{
    pub static ref MULTICAST_ADDR_IPV4: IpAddr = Ipv4Addr::new(224, 0, 0, 251).into();
    pub static ref MULTICAST_ADDR_IPV6: IpAddr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB).into();
}

fn main()
{
    let addr = SocketAddr::new(*MULTICAST_ADDR_IPV4, MULTICAST_PORT);
    let ip_addr = addr.ip();

    let mut socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.set_reuse_port(true).unwrap();

    match ip_addr
    {
        IpAddr::V4(ref mdns_v4) =>
        {
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0)).unwrap();
        },
        IpAddr::V6(ref mdns_v6) =>
        {
            socket.join_multicast_v6(mdns_v6, 0).unwrap();
            socket.set_only_v6(true).unwrap();
        }
    }

    socket.bind(&SockAddr::from(addr)).unwrap();

    let mut buf = [0u8; 1500];

    loop
    {
        match socket.read(&mut buf)
        {
            Ok(len) =>
            {

                println!("{}\n", hex::Hex::new(&buf, len));
            },
            Err(e) =>
            {
                    println!("{}", e);
            }
        }
    }
}
