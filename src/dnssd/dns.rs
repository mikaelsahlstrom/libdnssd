use std::fmt::Display;
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };
use std::str;

use crate::dnssd::dnssd_error::DnsSdError;

const FLAGS_QR_MASK: u16 = 0x8000;
const FLAGS_QR_RESPONSE: u16 = 0x8000;

const MAX_COMPRESSION_POINTERS: u8 = 126;
const MAX_LABEL_OCTETS: u8 = 255;

pub struct DnsSdResponse
{
    pub answers: Vec<Answer>
}

pub struct Answer
{
    pub label: String,
    pub address: IpAddr,
    pub port: u16
}

pub struct DnsSdHeader
{
    id: u16,
    flags: u16,
    queries_len: u16,
    answers_len: u16,
    authorities_len: u16,
    additional_len: u16
}

enum Type
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    NSEC = 47,
    ANY = 255
}

impl DnsSdHeader
{
    pub fn from(buffer: &[u8], count: usize) -> Result<DnsSdHeader, DnsSdError>
    {
        if count < 12
        {
            return Err(DnsSdError::InvalidDnsSdHeader);
        }

        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        if id != 0
        {
            return Err(DnsSdError::InvalidDnsSdHeader);
        }

        let flags = u16::from_be_bytes([buffer[2], buffer[3]]);
        let queries_len = u16::from_be_bytes([buffer[4], buffer[5]]);
        let answers_len = u16::from_be_bytes([buffer[6], buffer[7]]);
        let authorities_len = u16::from_be_bytes([buffer[8], buffer[9]]);
        let additional_len = u16::from_be_bytes([buffer[10], buffer[11]]);

        Ok(DnsSdHeader
        {
            id,
            flags,
            queries_len,
            answers_len,
            authorities_len,
            additional_len
        })
    }

    pub fn to_bytes(&self) -> Vec<u8>
    {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.queries_len.to_be_bytes());
        buffer.extend_from_slice(&self.answers_len.to_be_bytes());
        buffer.extend_from_slice(&self.authorities_len.to_be_bytes());
        buffer.extend_from_slice(&self.additional_len.to_be_bytes());

        buffer
    }
}

impl DnsSdResponse
{
    pub fn from(buffer: &[u8], count: usize) -> Result<DnsSdResponse, DnsSdError>
    {
        let mut answers: Vec<Answer> = Vec::new();
        let header = DnsSdHeader::from(buffer, count)?;

        if header.flags & FLAGS_QR_MASK != FLAGS_QR_RESPONSE
        {
            return Err(DnsSdError::NotDnsSdResponse);
        }

        if header.answers_len == 0
        {
            return Err(DnsSdError::NoAnswers);
        }

        let mut offset: usize = 12;

        for _ in 0..header.answers_len
        {
            // Parse DNS label.
            let (label, label_end) = DnsSdResponse::label_to_string(buffer, offset)?;
            offset = label_end;

            let answer_type = Type::from(u16::from_be_bytes([buffer[offset], buffer[offset + 1]]))?;
            let answer_data_len = u16::from_be_bytes([buffer[offset + 8], buffer[offset + 9]]);
            offset += 10;

            match answer_type
            {
                Type::A =>
                {
                    // We got an IPv4 address. Parse and return it.

                    if answer_data_len != 4
                    {
                        return Err(DnsSdError::InvalidDnsSdResponse);
                    }

                    let data = Ipv4Addr::new(buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]);
                    offset += 4;

                    answers.push(Answer
                    {
                        label: label,
                        address: IpAddr::V4(data),
                        port: 0
                    });
                },
                Type::AAAA =>
                {
                    // We got an IPv6 address. Parse and return it.

                    if answer_data_len != 16
                    {
                        return Err(DnsSdError::InvalidDnsSdResponse);
                    }

                    let data = Ipv6Addr::new(
                        u16::from_be_bytes([buffer[offset], buffer[offset + 1]]),
                        u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]),
                        u16::from_be_bytes([buffer[offset + 4], buffer[offset + 5]]),
                        u16::from_be_bytes([buffer[offset + 6], buffer[offset + 7]]),
                        u16::from_be_bytes([buffer[offset + 8], buffer[offset + 9]]),
                        u16::from_be_bytes([buffer[offset + 10], buffer[offset + 11]]),
                        u16::from_be_bytes([buffer[offset + 12], buffer[offset + 13]]),
                        u16::from_be_bytes([buffer[offset + 14], buffer[offset + 15]])
                    );
                    offset += 16;

                    answers.push(Answer
                    {
                        label: label,
                        address: IpAddr::V6(data),
                        port: 0
                    });
                },
                _ =>
                {
                    // We got an answer we don't care about. Skip it.
                    offset += answer_data_len as usize;
                }
            }
        }

        return Ok(DnsSdResponse
        {
            answers
        });
    }

    fn label_to_string(buffer: &[u8], start_offset: usize) -> Result<(String, usize), DnsSdError>
    {
        let mut name = String::new();
        let mut offset = start_offset;
        let mut ptr_budget = MAX_COMPRESSION_POINTERS;
        let mut ptr_taken = false;
        let mut end_offset: usize = start_offset;

        loop
        {
            match buffer[offset] & 0xc0
            {
                0x00 =>
                {
                    if buffer[offset] == 0x00
                    {
                        // End of name, set offset to next thing.
                        if !ptr_taken
                        {
                            end_offset = offset + 1;
                        }

                        break;
                    }

                    let label_len = buffer[offset] as usize;
                    offset += 1;

                    if offset + label_len >= buffer.len()
                    {
                        return Err(DnsSdError::LabelToLong);
                    }

                    if label_len + 1 > MAX_LABEL_OCTETS as usize
                    {
                        return Err(DnsSdError::LabelToLong);
                    }

                    name += match str::from_utf8(&buffer[offset..offset + label_len])
                    {
                        Ok(s) => s,
                        Err(_) => return Err(DnsSdError::InvalidUtf8)
                    };

                    offset += label_len;
                    if buffer[offset] != 0x00
                    {
                        name += ".";
                    }
                }
                0xc0 =>
                {
                    // Pointer.
                    if ptr_budget == 0
                    {
                        return Err(DnsSdError::LabelCompressionLoop);
                    }

                    ptr_budget -= 1;

                    let ptr = (u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) ^ 0xc000) as usize;
                    if ptr >= offset
                    {
                        return Err(DnsSdError::LabelPtrForward);
                    }

                    if !ptr_taken
                    {
                        end_offset = offset + 2;
                        ptr_taken = true;
                    }

                    offset = ptr;
                },
                _ =>
                {
                    return Err(DnsSdError::LabelInvalid);
                }
            }
        }

        Ok((name, end_offset))
    }
}

pub fn new_query(service: &str) -> Result<Vec<u8>, DnsSdError>
{
    if service.len() == 0
    {
        return Err(DnsSdError::LabelInvalid);
    }

    let mut buffer = Vec::new();

    let header = DnsSdHeader
    {
        id: 0,
        flags: 0x0000,
        queries_len: 1,
        answers_len: 0,
        authorities_len: 0,
        additional_len: 0
    };

    buffer.extend(header.to_bytes());

    let labels: Vec<&str> = service.split(".").collect();
    for label in labels
    {
        if label.len() > MAX_LABEL_OCTETS as usize
        {
            return Err(DnsSdError::LabelToLong);
        }

        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }
    buffer.push(0x00);

    // Query type ANY
    buffer.extend_from_slice(&0x00ff_u16.to_be_bytes());

    // Query class IN
    buffer.extend_from_slice(&0x8001_u16.to_be_bytes());

    Ok(buffer)
}

impl Type
{
    pub fn from(value: u16) -> Result<Type, DnsSdError>
    {
        match value
        {
            1 => Ok(Type::A),
            2 => Ok(Type::NS),
            5 => Ok(Type::CNAME),
            6 => Ok(Type::SOA),
            12 => Ok(Type::PTR),
            15 => Ok(Type::MX),
            16 => Ok(Type::TXT),
            28 => Ok(Type::AAAA),
            33 => Ok(Type::SRV),
            41 => Ok(Type::OPT),
            47 => Ok(Type::NSEC),
            255 => Ok(Type::ANY),
            _ => Err(DnsSdError::InvalidMdnsType)
        }
    }
}

impl Display for Type
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        match self
        {
            Type::A => write!(f, "A"),
            Type::NS => write!(f, "NS"),
            Type::CNAME => write!(f, "CNAME"),
            Type::SOA => write!(f, "SOA"),
            Type::PTR => write!(f, "PTR"),
            Type::MX => write!(f, "MX"),
            Type::TXT => write!(f, "TXT"),
            Type::AAAA => write!(f, "AAAA"),
            Type::SRV => write!(f, "SRV"),
            Type::OPT => write!(f, "OPT"),
            Type::NSEC => write!(f, "NSEC"),
            Type::ANY => write!(f, "ANY")
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_label_to_string_1()
    {
        let packet: [u8; 17] =
        [
            0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63,
            0x61, 0x6c, 0x00,
        ];

        let (label, offset) = DnsSdResponse::label_to_string(&packet, 0).unwrap();

        assert_eq!(label, "_hap._tcp.local");
        assert_eq!(offset, 17);
    }

    #[test]
    fn test_label_to_string_2()
    {
        let packet: [u8; 28] =
        [
            0x0f, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69,
            0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
        ];

        let (label, offset) = DnsSdResponse::label_to_string(&packet, 0).unwrap();

        assert_eq!(label, "_companion-link._tcp.local");
        assert_eq!(offset, 28);
    }

    #[test]
    fn test_label_to_string_3()
    {
        let packet: [u8; 229] =
        [
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x68, 0x61,
            0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00,
            0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x0b, 0x08, 0x44, 0x49, 0x52, 0x49, 0x47, 0x45, 0x52, 0x41,
            0xc0, 0x0c, 0xc0, 0x27, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x66, 0x05, 0x63,
            0x23, 0x3d, 0x32, 0x32, 0x04, 0x66, 0x66, 0x3d, 0x31, 0x14, 0x69, 0x64, 0x3d, 0x42, 0x35, 0x3a,
            0x42, 0x30, 0x3a, 0x41, 0x30, 0x3a, 0x36, 0x37, 0x3a, 0x42, 0x34, 0x3a, 0x36, 0x39, 0x22, 0x6d,
            0x64, 0x3d, 0x44, 0x49, 0x52, 0x49, 0x47, 0x45, 0x52, 0x41, 0x20, 0x48, 0x75, 0x62, 0x20, 0x66,
            0x6f, 0x72, 0x20, 0x73, 0x6d, 0x61, 0x72, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
            0x73, 0x06, 0x70, 0x76, 0x3d, 0x31, 0x2e, 0x31, 0x05, 0x73, 0x23, 0x3d, 0x32, 0x30, 0x04, 0x73,
            0x66, 0x3d, 0x30, 0x04, 0x63, 0x69, 0x3d, 0x32, 0x0b, 0x73, 0x68, 0x3d, 0x6b, 0x37, 0x50, 0x76,
            0x43, 0x67, 0x3d, 0x3d, 0xc0, 0x27, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x19,
            0x00, 0x00, 0x00, 0x00, 0x1f, 0x40, 0x10, 0x67, 0x77, 0x32, 0x2d, 0x38, 0x66, 0x66, 0x36, 0x65,
            0x64, 0x32, 0x31, 0x30, 0x61, 0x34, 0x38, 0xc0, 0x16, 0xc0, 0xb6, 0x00, 0x1c, 0x80, 0x01, 0x00,
            0x00, 0x00, 0x78, 0x00, 0x10, 0xfd, 0x05, 0x0b, 0x30, 0x32, 0x24, 0x4a, 0x5c, 0x6a, 0xec, 0x8a,
            0xff, 0xfe, 0x00, 0xd0, 0xed
        ];

        let (label, offset) = DnsSdResponse::label_to_string(&packet, 39).unwrap();

        assert_eq!(label, "DIRIGERA._hap._tcp.local");
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_header_to_bytes()
    {
        let header = DnsSdHeader
        {
            id: 0,
            flags: 0x0000,
            queries_len: 1,
            answers_len: 0,
            authorities_len: 0,
            additional_len: 0
        };

        let buffer = header.to_bytes();

        assert_eq!(buffer.len(), 12);
        assert_eq!(buffer[0], 0x00);
        assert_eq!(buffer[1], 0x00);
        assert_eq!(buffer[2], 0x00);
        assert_eq!(buffer[3], 0x00);
        assert_eq!(buffer[4], 0x00);
        assert_eq!(buffer[5], 0x01);
        assert_eq!(buffer[6], 0x00);
        assert_eq!(buffer[7], 0x00);
        assert_eq!(buffer[8], 0x00);
        assert_eq!(buffer[9], 0x00);
        assert_eq!(buffer[10], 0x00);
        assert_eq!(buffer[11], 0x00);
    }

    #[test]
    fn test_new_query()
    {
        let query = new_query("_hap._tcp.local").unwrap();

        assert_eq!(query.len(), 33);
        assert_eq!(query[0], 0x00);
        assert_eq!(query[1], 0x00);
        assert_eq!(query[2], 0x00);
        assert_eq!(query[3], 0x00);
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
        assert_eq!(query[6], 0x00);
        assert_eq!(query[7], 0x00);
        assert_eq!(query[8], 0x00);
        assert_eq!(query[9], 0x00);
        assert_eq!(query[10], 0x00);
        assert_eq!(query[11], 0x00);
        assert_eq!(query[12], 0x04);
        assert_eq!(query[13], 0x5f);
        assert_eq!(query[14], 0x68);
        assert_eq!(query[15], 0x61);
        assert_eq!(query[16], 0x70);
        assert_eq!(query[17], 0x04);
        assert_eq!(query[18], 0x5f);
        assert_eq!(query[19], 0x74);
        assert_eq!(query[20], 0x63);
        assert_eq!(query[21], 0x70);
        assert_eq!(query[22], 0x05);
        assert_eq!(query[23], 0x6c);
        assert_eq!(query[24], 0x6f);
        assert_eq!(query[25], 0x63);
        assert_eq!(query[26], 0x61);
        assert_eq!(query[27], 0x6c);
        assert_eq!(query[28], 0x00);
        assert_eq!(query[29], 0x00);
        assert_eq!(query[30], 0xff);
        assert_eq!(query[31], 0x80);
        assert_eq!(query[32], 0x01);
    }
}
