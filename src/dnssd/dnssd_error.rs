use std::{ error::Error, fmt::Display };

#[derive(Copy, Clone, Debug)]
pub enum DnsSdError
{
    Timeout,
    UdpSocketError,
    ThreadError,
    InvalidDnsSdHeader,
    NotDnsSdResponse,
    NoAnswers,
    InvalidMdnsType,
    LabelToLong,
    InvalidUtf8,
    LabelCompressionLoop,
    LabelPtrForward,
    LabelInvalid,
    InvalidDnsSdResponse,
    NotWantedService,
    ThreadAlreadyStarted
}

impl Error for DnsSdError
{
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
            DnsSdError::ThreadError =>
            {
                write!(f, "DNS-SD error: Thread error")
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
            },
            DnsSdError::NotWantedService =>
            {
                write!(f, "DNS-SD error: Not wanted service")
            },
            DnsSdError::ThreadAlreadyStarted =>
            {
                write!(f, "DNS-SD error: Thread already started")
            }
        }
    }
}
