use std::{ error::Error, fmt::Display };

#[derive(Copy, Clone, Debug)]
pub enum DnsSdError
{
    Timeout,
    UdpSocketError,
    InvalidDnsSdHeader,
    NotDnsSdResponse,
    NoAnswers,
    InvalidMdnsType,
    LabelToLong,
    InvalidUtf8,
    LabelCompressionLoop,
    LabelPtrForward,
    LabelInvalid,
    InvalidDnsSdResponse
}

impl Error for DnsSdError
{
}

impl From<std::io::Error> for DnsSdError
{
    fn from(err: std::io::Error) -> Self
    {
        match err.kind()
        {
            std::io::ErrorKind::TimedOut => DnsSdError::Timeout,
            std::io::ErrorKind::WouldBlock => DnsSdError::Timeout,
            std::io::ErrorKind::AddrNotAvailable => DnsSdError::UdpSocketError,
            std::io::ErrorKind::AddrInUse => DnsSdError::UdpSocketError,
            std::io::ErrorKind::AlreadyExists => DnsSdError::UdpSocketError,
            std::io::ErrorKind::ConnectionRefused => DnsSdError::UdpSocketError,
            std::io::ErrorKind::ConnectionReset => DnsSdError::UdpSocketError,
            std::io::ErrorKind::ConnectionAborted => DnsSdError::UdpSocketError,
            std::io::ErrorKind::NotConnected => DnsSdError::UdpSocketError,
            std::io::ErrorKind::Interrupted => DnsSdError::UdpSocketError,
            std::io::ErrorKind::PermissionDenied => DnsSdError::UdpSocketError,
            std::io::ErrorKind::InvalidInput => DnsSdError::UdpSocketError,
            std::io::ErrorKind::InvalidData => DnsSdError::UdpSocketError,
            std::io::ErrorKind::UnexpectedEof => DnsSdError::UdpSocketError,
            std::io::ErrorKind::Other => DnsSdError::UdpSocketError,
            _ => DnsSdError::UdpSocketError
        }
    }
}

impl Display for DnsSdError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        match self
        {
            DnsSdError::Timeout =>
            {
                write!(f, "DNS-SD error: Timeout")
            },
            DnsSdError::UdpSocketError =>
            {
                write!(f, "DNS-SD error: UDP socket error")
            },
            DnsSdError::InvalidDnsSdHeader =>
            {
                write!(f, "DNS-SD error: Invalid mDNS header")
            },
            DnsSdError::NotDnsSdResponse =>
            {
                write!(f, "DNS-SD error: Not mDNS response")
            },
            DnsSdError::NoAnswers =>
            {
                write!(f, "DNS-SD error: No answers")
            },
            DnsSdError::InvalidMdnsType =>
            {
                write!(f, "DNS-SD error: Invalid mDNS type")
            },
            DnsSdError::LabelToLong =>
            {
                write!(f, "DNS-SD error: Label to long")
            },
            DnsSdError::InvalidUtf8 =>
            {
                write!(f, "DNS-SD error: Invalid UTF-8")
            },
            DnsSdError::LabelCompressionLoop =>
            {
                write!(f, "DNS-SD error: Label compression loop")
            },
            DnsSdError::LabelPtrForward =>
            {
                write!(f, "DNS-SD error: Label pointer pointing forward")
            },
            DnsSdError::LabelInvalid =>
            {
                write!(f, "DNS-SD error: Label invalid")
            },
            DnsSdError::InvalidDnsSdResponse =>
            {
                write!(f, "DNS-SD error: Invalid mDNS response")
            }
        }
    }
}
