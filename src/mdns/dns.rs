use std::str;

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

enum Types
{
    A = 0x0001,     // IPv4 address associated with domain
    AAAA = 0x001c,  // IPv6 address associated with domain
    PTR = 0x000c,   // Domains associated with IP address
    TXT = 0x0010,   // Text strings
    SRV = 0x0021,   // Service record
    ANY = 0x00ff
}

struct ResourceRecord
{
    name: String,
    rr_type: Types,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Vec<u8>,
    // Keep track of offset used.
    offset: usize
}

impl TryFrom<[u8; 2]> for Types
{
    type Error = ();

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error>
    {
        match u16::from_be_bytes(value)
        {
            0x0001 => Ok(Types::A),
            0x001c => Ok(Types::AAAA),
            0x000c => Ok(Types::PTR),
            0x0010 => Ok(Types::TXT),
            0x0021 => Ok(Types::SRV),
            0x00ff => Ok(Types::ANY),
            _ => Err(())
        }
    }
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
    fn label_to_string(&mut self, buffer: [u8; 4096]) -> Result<String, mdns_error::MdnsError>
    {
        let mut name = String::new();
        let mut offset = self.offset;
        let mut ptr_budget = MAX_COMPRESSION_POINTERS;
        let mut ptr_taken = false;

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
                            self.offset = offset + 1;
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
                            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::LabelToLong));
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
                        self.offset = offset + 2;
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

        return Ok(name);
    }

    fn from(&mut self, buffer: [u8; 4096]) -> Result<(), mdns_error::MdnsError>
    {
        self.name = self.label_to_string(buffer)?;

        self.rr_type = match Types::try_from([buffer[self.offset], buffer[self.offset + 1]])
        {
            Ok(rr_type) => rr_type,
            Err(_) =>
            {
                return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::UnknownRrType));
            }
        };
        self.offset += 2;

        let class = u16::from_be_bytes([buffer[self.offset], buffer[self.offset + 1]]);
        if class != 0x0001
        {
            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::UnknownRrClass));
        }
        self.class = class;
        self.offset += 2;

        self.ttl = u32::from_be_bytes([buffer[self.offset], buffer[self.offset + 1], buffer[self.offset + 2], buffer[self.offset + 3]]);
        self.offset += 4;

        return Ok(());
    }

    fn new() -> ResourceRecord
    {
        ResourceRecord
        {
            name: String::new(),
            rr_type: Types::ANY,
            class: 0,
            ttl: 0,
            data_len: 0,
            data: Vec::new(),
            offset: 0
        }
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

        let mut rr = ResourceRecord::new();
        rr.from(buffer).unwrap();

        assert_eq!(rr.name, "_hap._tcp.local");
        assert_eq!(rr.offset, 17);
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

        let mut rr = ResourceRecord::new();
        rr.from(buffer).unwrap();

        assert_eq!(rr.name, "_companion-link._tcp.local");
        assert_eq!(rr.offset, 28);
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

        let mut rr = ResourceRecord::new();
        rr.offset = 39;
        rr.from(buffer).unwrap();

        assert_eq!(rr.name, "DIRIGERA._hap._tcp.local");
        assert_eq!(rr.offset, 50);
    }
}
