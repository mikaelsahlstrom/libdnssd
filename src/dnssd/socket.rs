extern crate socket2;

use std::{ net::{ IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket }, io };
use socket2::{ Socket, Domain, Type, SockAddr, Protocol };
use default_net;

use super::dnssd_error::DnsSdError;

pub const MULTICAST_PORT: u16 = 5353;
pub const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

lazy_static!
{
    pub(crate) static ref MULTICAST_IPV4_SOCKET: SocketAddr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR_IPV4), MULTICAST_PORT);
    pub(crate) static ref MULTICAST_IPV6_SOCKET: SocketAddr = SocketAddr::new(IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT);
}

fn create_socket(addr: &SocketAddr) -> io::Result<Socket>
{
    let domain = if addr.is_ipv4()
    {
        Domain::IPV4
    }
    else
    {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    Ok(socket)
}

fn get_default_ipv6_interface() -> u32
{
    let default_interface = match default_net::get_default_interface()
    {
        Ok(interface) => interface.index,
        Err(_) => 0 // TODO: Improve error handling.
    };

    default_interface
}

pub fn join_multicast(addr: &SocketAddr) -> Result<UdpSocket, DnsSdError>
{
    let ip_addr = addr.ip();
    let socket = convert_error(create_socket(addr))?;

    match ip_addr
    {
        IpAddr::V4(ref mdns_v4) =>
        {
            convert_error(socket.join_multicast_v4(mdns_v4, &Ipv4Addr::UNSPECIFIED))?;
        },
        IpAddr::V6(ref mdns_v6) =>
        {
            convert_error(socket.join_multicast_v6(mdns_v6, get_default_ipv6_interface()))?;
            convert_error(socket.set_only_v6(true))?;
        }
    };

    let socket = convert_error(bind_multicast(socket, addr))?;

    Ok(socket.into())
}

#[cfg(unix)]
fn bind_multicast(socket: Socket, addr: &SocketAddr) -> io::Result<Socket>
{
    socket.bind(&SockAddr::from(*addr))?;
    Ok(socket)
}

#[cfg(windows)]
fn bind_multicast(socket: Socket, addr: &SocketAddr) -> io::Result<Socket>
{
    let addr = match addr
    {
        SocketAddr::V4(addr) =>
        {
            SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), addr.port()))
        },
        SocketAddr::V6(addr) =>
        {
            SockAddr::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port()))
        }
    };

    socket.bind(&addr)?;
    Ok(socket)
}

pub fn create_sender_socket() -> Result<UdpSocket, DnsSdError>
{
    let socket = convert_error(Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)))?;

    convert_error(socket.bind(&SockAddr::from(SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        0,
    ))))?;

    Ok(socket.into())
}

pub fn convert_error<T>(result: Result<T, io::Error>) -> Result<T, DnsSdError>
{
    match result
    {
        Ok(value) => Ok(value),
        Err(err) =>
        {
            match err.kind()
            {
                io::ErrorKind::TimedOut => Err(DnsSdError::Timeout),
                io::ErrorKind::WouldBlock => Err(DnsSdError::Timeout),
                io::ErrorKind::AddrNotAvailable => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::AddrInUse => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::AlreadyExists => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::ConnectionRefused => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::ConnectionReset => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::ConnectionAborted => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::NotConnected => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::Interrupted => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::PermissionDenied => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::InvalidInput => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::InvalidData => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::UnexpectedEof => Err(DnsSdError::UdpSocketError),
                io::ErrorKind::Other => Err(DnsSdError::UdpSocketError),
                _ => Err(DnsSdError::UdpSocketError)
            }
        }
    }
}
