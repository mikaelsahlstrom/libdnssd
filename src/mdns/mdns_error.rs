use std::{error::Error, fmt::Display };

#[derive(Debug)]
pub enum MdnsParsingErrorType
{
    HeaderToShort,
    LabelToLong,
    LabelCompressionLoop,
    OutOfBuffer,
    Reserved,
    Uft8ParsingFailed,
    LabelPtrForward,
    UnknownRrType,
    UnknownRrClass
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
                        write!(f, "mDNS parsing error: Header to short")
                    },
                    MdnsParsingErrorType::LabelToLong =>
                    {
                        write!(f, "mDNS parsing error: Label to short")
                    },
                    MdnsParsingErrorType::LabelCompressionLoop =>
                    {
                        write!(f, "mDNS parsing error: Label compression loop")
                    },
                    MdnsParsingErrorType::OutOfBuffer =>
                    {
                        write!(f, "mDNS parsing error: Out of buffer")
                    },
                    MdnsParsingErrorType::Reserved =>
                    {
                        write!(f, "mDNS parsing error: Reserved bytes")
                    },
                    MdnsParsingErrorType::Uft8ParsingFailed =>
                    {
                        write!(f, "mDNS parsing error: UTF-8 parsing failed")
                    },
                    MdnsParsingErrorType::LabelPtrForward =>
                    {
                        write!(f, "mDNS parsing error: Forward label pointer")
                    },
                    MdnsParsingErrorType::UnknownRrType =>
                    {
                        write!(f, "mDNS parsing error: Unknown resource record type")
                    },
                    MdnsParsingErrorType::UnknownRrClass =>
                    {
                        write!(f, "mDNS parsing error: Unknown resource record class")
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
