use std::str;
use std::net::{ Ipv4Addr, Ipv6Addr };

use super::mdns_error;

const FLAGS_QR_MASK: u16 = 0x8000;
const FLAGS_QR_QUERY: u16 = 0x0000;
const FLAGS_QR_RESPONSE: u16 = 0x8000;
const MAX_COMPRESSION_POINTERS: u8 = 126;
const MAX_LABEL_OCTETS: u8 = 255;

pub struct Mdns
{
    header: MdnsHeader,
    queries: Vec<ResourceRecord>,
    answers: Vec<ResourceRecord>,
    // Keep track of offset used.
    offset: usize
}

struct MdnsHeader
{
    id: u16, // 0x0000
    answer: bool,
    queries_len: u16,
    answers_len: u16,
    authorities_len: u16,
    additional_len: u16,
    // Keep track of offset used.
    offset: usize
}

enum ResourceRecord
{
    A(ARecord),
    AAAA(AAAARecord),
    PTR(PTRRecord),
    TXT(TXTRecord),
    SRV(SRVRecord)
}

struct ARecord
{
    name: String,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Ipv4Addr,
    // Keep track of offset used.
    offset: usize
}

struct AAAARecord
{
    name: String,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Ipv6Addr,
    // Keep track of offset used.
    offset: usize
}

struct PTRRecord
{
    name: String,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: String,
    // Keep track of offset used.
    offset: usize
}

struct TXTRecord
{
    name: String,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Vec<String>,
    // Keep track of offset used.
    offset: usize
}

struct SRVRecord
{
    name: String,
    class: u16,
    ttl: u32,
    data_len: u16,
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
    // Keep track of offset used.
    offset: usize
}

impl MdnsHeader
{
    fn from(&mut self, buffer: [u8; 4096], len: usize) -> Result<(), mdns_error::MdnsError>
    {
        if len < 12
        {
            return Err(mdns_error::MdnsError::MdnsParsingError(
                mdns_error::MdnsParsingErrorType::HeaderToShort,
            ));
        }

        let flags = u16::from_be_bytes([buffer[2], buffer[3]]);

        self.id = u16::from_be_bytes([buffer[0], buffer[1]]);
        self.answer = flags & FLAGS_QR_MASK == FLAGS_QR_RESPONSE;
        self.queries_len = u16::from_be_bytes([buffer[4], buffer[5]]);
        self.answers_len = u16::from_be_bytes([buffer[6], buffer[7]]);
        self.authorities_len = u16::from_be_bytes([buffer[8], buffer[9]]);
        self.additional_len = u16::from_be_bytes([buffer[10], buffer[11]]);
        self.offset = 13;

        Ok(())
    }

    fn new() -> MdnsHeader
    {
        MdnsHeader
        {
            id: 0,
            answer: false,
            queries_len: 0,
            answers_len: 0,
            authorities_len: 0,
            additional_len: 0,
            offset: 0
        }
    }
}

impl ResourceRecord
{
    fn label_to_string(buffer: [u8; 4096], len: usize, start_offset: usize) -> Result<(String, usize), mdns_error::MdnsError>
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

                    let length = buffer[offset];
                    offset += 1;

                    if offset + length as usize >= 4096
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::OutOfBuffer));
                    }

                    if length + 1 >= MAX_LABEL_OCTETS
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::LabelToLong));
                    }

                    name += match str::from_utf8(&buffer[offset..(offset + length as usize)])
                    {
                        Ok(s) => s,
                        Err(_) =>
                        {
                            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::Uft8ParsingFailed));
                        }
                    };

                    offset += length as usize;
                    if buffer[offset] != 0x00
                    {
                        name += ".";
                    }
                },
                0xc0 =>
                {
                    // Pointer.
                    if ptr_budget == 0
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::LabelCompressionLoop));
                    }
                    ptr_budget -= 1;

                    let ptr = (u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) ^ 0xc000) as usize;
                    if ptr >= offset
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::LabelPtrForward));
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
                    return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::Reserved));
                }
            }
        }

        return Ok((name, end_offset));
    }

    fn parse_txt(buffer: [u8; 4096], len: usize, start_offset: usize, txt_length: usize) -> Result<(Vec<String>, usize), mdns_error::MdnsError>
    {
        let mut offset = start_offset;
        let mut txts: Vec<String> = Vec::new();

        if offset + txt_length > len
        {
            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::TxtToLong));
        }

        while offset < start_offset + txt_length
        {
            let len = buffer[offset] as usize;
            offset += 1;

            let txt = match str::from_utf8(&buffer[offset..(offset + len)])
            {
                Ok(s) => s,
                Err(_) =>
                {
                    return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::Uft8ParsingFailed));
                }
            };
            offset += len;

            txts.push(txt.to_string());
        }

        return Ok((txts, offset));
    }

    fn new_from(buffer: [u8; 4096], len: usize, offset: usize) -> Result<ResourceRecord, mdns_error::MdnsError>
    {
        let (name, mut next_offset) = ResourceRecord::label_to_string(buffer, len, offset)?;
        let rr_type = u16::from_be_bytes([buffer[next_offset], buffer[next_offset + 1]]);
        next_offset += 2;

        let class = u16::from_be_bytes([buffer[next_offset + 3], buffer[next_offset + 4]]);
        if class != 0x0001
        {
            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::UnknownRrClass));
        }
        next_offset += 2;

        let ttl = u32::from_be_bytes([buffer[next_offset + 5], buffer[next_offset + 6], buffer[next_offset + 7], buffer[next_offset + 8]]);
        next_offset += 4;

        let data_len = u16::from_be_bytes([buffer[next_offset + 10], buffer[next_offset + 11]]);
        next_offset += 2;

        match rr_type
        {
            // A record
            0x0001 =>
            {
                if data_len != 4
                {
                    return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::Ipv4AddrError));
                }

                let mut data = Ipv4Addr::new(buffer[next_offset], buffer[next_offset + 1], buffer[next_offset + 2], buffer[next_offset + 3]);
                next_offset += 4;

                return Ok(ResourceRecord::A(
                    ARecord
                    {
                        name: name,
                        class: class,
                        ttl: ttl,
                        data_len: data_len,
                        data: data,
                        offset: next_offset
                    }
                ));
            },
            // AAAA record
            0x001c =>
            {
                if data_len != 16
                {
                    return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::Ipv4AddrError));
                }

                let ip6addr: [u8; 16] = buffer[next_offset..(next_offset + 16)].try_into().unwrap();
                let data = Ipv6Addr::from(ip6addr);
                next_offset += 16;

                return Ok(ResourceRecord::AAAA(
                    AAAARecord
                    {
                        name: name,
                        class: class,
                        ttl: ttl,
                        data_len: data_len,
                        data: data,
                        offset: next_offset
                    }
                ));
            },
            // PTR record
            0x000c =>
            {
                let (domain, new_offset) = ResourceRecord::label_to_string(buffer, len, next_offset)?;

                return Ok(ResourceRecord::PTR(
                    PTRRecord
                    {
                        name: name,
                        class: class,
                        ttl: ttl,
                        data_len: data_len,
                        data: domain,
                        offset: new_offset
                    }
                ));
            },
            // TXT record
            0x0010 =>
            {
                let (txts, new_offset) = ResourceRecord::parse_txt(buffer, len, next_offset, data_len as usize)?;

                return Ok(ResourceRecord::TXT(
                    TXTRecord
                    {
                        name: name,
                        class: class,
                        ttl: ttl,
                        data_len: data_len,
                        data: txts,
                        offset: new_offset
                    }
                ));
            },
            // SRV record
            0x0021 =>
            {
                let priority = u16::from_be_bytes([buffer[next_offset], buffer[next_offset + 1]]);
                next_offset += 2;

                let weight = u16::from_be_bytes([buffer[next_offset], buffer[next_offset + 1]]);
                next_offset += 2;

                let port = u16::from_be_bytes([buffer[next_offset], buffer[next_offset + 1]]);
                next_offset += 2;

                let (target, new_offset) = ResourceRecord::label_to_string(buffer, len, next_offset)?;

                return Ok(ResourceRecord::SRV(
                    SRVRecord
                    {
                        name: name,
                        class: class,
                        ttl: ttl,
                        data_len: data_len,
                        priority: priority,
                        weight: weight,
                        port: port,
                        target: target,
                        offset: new_offset
                    }
                ));
            },
            _ =>
            {
                return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::UnknownRrType));
            }
        };
    }
}

impl Mdns
{
    pub fn from(&mut self, buffer: [u8; 4096], len: usize) -> Result<(), mdns_error::MdnsError>
    {
        self.header.from(buffer, len)?;

        if !self.header.answer && self.header.queries_len > 0
        {
            // Parse queries.
            for _ in 0..self.header.queries_len
            {

            }
        }

        if self.header.answer && self.header.answers_len > 0
        {
            // Parse answers.
            for _ in 0..self.header.answers_len
            {

            }
        }

        return Ok(());
    }

    pub fn new(buffer: [u8; 4096], len: usize) -> Result<Mdns, mdns_error::MdnsError>
    {
        let mut mdns = Mdns
        {
            header: MdnsHeader::new(),
            queries: Vec::new(),
            answers: Vec::new(),
            offset: 0
        };

        mdns.from(buffer, len)?;

        return Ok(mdns);
    }
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_label_to_string_1()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 17] =
        [
            0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63,
            0x61, 0x6c, 0x00,
        ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        let (label, offset) = ResourceRecord::label_to_string(buffer, 17, 0).unwrap();

        assert_eq!(label, "_hap._tcp.local");
        assert_eq!(offset, 17);
    }

    #[test]
    fn test_label_to_string_2()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 28] =
        [
            0x0f, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69,
            0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
        ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        let (label, offset) = ResourceRecord::label_to_string(buffer, 28, 0).unwrap();

        assert_eq!(label, "_companion-link._tcp.local");
        assert_eq!(offset, 28);
    }

    #[test]
    fn test_label_to_string_3()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
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

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        let (label, offset) = ResourceRecord::label_to_string(buffer, 229, 39).unwrap();

        assert_eq!(label, "DIRIGERA._hap._tcp.local");
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_parse_txt()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 114] =
        [
            0xc0, 0x27, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x66, 0x05, 0x63, 0x23, 0x3d,
            0x32, 0x32, 0x04, 0x66, 0x66, 0x3d, 0x31, 0x14, 0x69, 0x64, 0x3d, 0x42, 0x35, 0x3a, 0x42, 0x30,
            0x3a, 0x41, 0x30, 0x3a, 0x36, 0x37, 0x3a, 0x42, 0x34, 0x3a, 0x36, 0x39, 0x22, 0x6d, 0x64, 0x3d,
            0x44, 0x49, 0x52, 0x49, 0x47, 0x45, 0x52, 0x41, 0x20, 0x48, 0x75, 0x62, 0x20, 0x66, 0x6f, 0x72,
            0x20, 0x73, 0x6d, 0x61, 0x72, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73, 0x06,
            0x70, 0x76, 0x3d, 0x31, 0x2e, 0x31, 0x05, 0x73, 0x23, 0x3d, 0x32, 0x30, 0x04, 0x73, 0x66, 0x3d,
            0x30, 0x04, 0x63, 0x69, 0x3d, 0x32, 0x0b, 0x73, 0x68, 0x3d, 0x6b, 0x37, 0x50, 0x76, 0x43, 0x67,
            0x3d, 0x3d
        ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        let (txts, next_offset) = ResourceRecord::parse_txt(buffer, 114, 12, 102).unwrap();

        assert_eq!(txts.len(), 9);
        assert_eq!(txts[0], "c#=22");
        assert_eq!(txts[1], "ff=1");
        assert_eq!(txts[2], "id=B5:B0:A0:67:B4:69");
        assert_eq!(txts[3], "md=DIRIGERA Hub for smart products");
        assert_eq!(txts[4], "pv=1.1");
        assert_eq!(txts[5], "s#=20");
        assert_eq!(txts[6], "sf=0");
        assert_eq!(txts[7], "ci=2");
        assert_eq!(txts[8], "sh=k7PvCg==");
    }
}
