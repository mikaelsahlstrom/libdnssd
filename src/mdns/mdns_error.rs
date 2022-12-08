use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum MdnsError
{
    UdpSocketError(std::io::Error)
}

impl Error for MdnsError
{}

impl Display for MdnsError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        match self
        {
            MdnsError::UdpSocketError(err) =>
            {
                write!(f, "mDNS UDP socket error: {}", err)
            }
        }
    }
}

impl From<std::io::Error> for MdnsError
{
    fn from(err: std::io::Error) -> Self
    {
        Self::UdpSocketError(err)
    }
}
