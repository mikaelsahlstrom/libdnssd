use std::{error::Error, fmt::Display, array::TryFromSliceError};

#[derive(Debug)]
pub enum MdnsParsingErrorType
{
    HeaderToShort
}

#[derive(Debug)]
pub enum MdnsError
{
    UdpSocketError(std::io::Error),
    Ipv6DefaultInterfaceError,
    MdnsParsingError(MdnsParsingErrorType)
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
            },
            MdnsError::Ipv6DefaultInterfaceError =>
            {
                write!(f, "mDNS socket error: Could not get default IPv6 interface")
            },
            MdnsError::MdnsParsingError(err) =>
            {
                match err
                {
                    MdnsParsingErrorType::HeaderToShort =>
                    {
                        write!(f, "mDNS parsing error: header to short")
                    }
                }
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
