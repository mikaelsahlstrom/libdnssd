use super::mdns_error;

const FLAGS_QR_MASK: u16 = 0x8000;
const FLAGS_QR_QUERY: u16 = 0x0000;
const FLAGS_QR_RESPONSE: u16 = 0x8000;

pub struct MdnsAnswer
{

}

pub struct MdnsResponse
{
    answers: Vec<MdnsAnswer>
}

pub struct MdnsHeader
{
    id: u16,                // 0x0000
    question: bool,
    questions_len: u16,
    answers_len: u16,
    authorities_len: u16,
    additional_len: u16,
    queries: Vec<Query>,
    answers: Vec<Answer>
}

enum Types
{
    A = 0x1,        // IPv4 address associated with domain
    AAAA = 0x1c,    // IPv6 address associated with domain
    PTR = 0xc2,     // Domains associated with IP address
    TXT = 0x10,     // Text strings
    ANY = 0xff
}

struct Query
{
    name: String,
    query_type: Types,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Vec<u8>
}

struct Answer
{
    name: String,
    answer_type: Types,
    class: u16,
    ttl: u32,
    data_len: u16,
    data: Vec<u8>
}

impl MdnsHeader
{
    fn name_to_string(buffer: [u8; 4096]) -> String
    {
        let mut string = String::new();
        let mut length: usize = buffer[0].into();
        let mut offset: usize = 0;

        // Read length.
        while length != 0 && offset + length < 4096
        {
            for i in 0..length
            {
                string.push(buffer[offset + i].try_into().unwrap());
            }

            length = buffer[offset + length].into();
            offset += length + 1;
        }

        string
    }

    pub fn from(buffer: [u8; 4096], len: usize) -> Result<MdnsHeader, mdns_error::MdnsError>
    {
        if len < 12
        {
            return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::HeaderToShort));
        }

        let flags = u16::from_be_bytes([buffer[2], buffer[3]]);

        let header = MdnsHeader
        {
            id: u16::from_be_bytes([buffer[0], buffer[1]]),
            question: flags & FLAGS_QR_MASK == FLAGS_QR_QUERY,
            questions_len: u16::from_be_bytes([buffer[4], buffer[5]]),
            answers_len: u16::from_be_bytes([buffer[6], buffer[7]]),
            authorities_len: u16::from_be_bytes([buffer[8], buffer[9]]),
            additional_len: u16::from_be_bytes([buffer[10], buffer[11]]),
            queries: Vec::new(),
            answers: Vec::new()
        };

        if header.questions_len > 0
        {
            println!("test: {}", MdnsHeader::name_to_string(buffer[13..].try_into().unwrap()));
        }

        Ok(header)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

/*
0000  00 00 00 00 00 05 00 00 00 01 00 01 0f 5f 63 6f
0010  6d 70 61 6e 69 6f 6e 2d 6c 69 6e 6b 04 5f 74 63
0020  70 05 6c 6f 63 61 6c 00 00 0c 80 01 04 5f 68 61
0030  70 c0 1c 00 0c 80 01 04 5f 68 61 70 04 5f 75 64
0040  70 c0 21 00 0c 80 01 0c 5f 73 6c 65 65 70 2d 70
0050  72 6f 78 79 c0 3c 00 0c 80 01 11 4d 69 6b 61 65
0060  6c 20 e2 80 93 20 69 50 68 6f 6e 65 07 5f 72 64
0070  6c 69 6e 6b c0 1c 00 ff 80 01 c0 5a 00 21 00 01
0080  00 00 00 78 00 17 00 00 00 00 c0 15 0e 4d 69 6b
0090  61 65 6c 2d 2d 69 50 68 6f 6e 65 c0 21 00 00 29
00a0  05 a0 00 00 11 94 00 12 00 04 00 0e 00 7d 92 11
00b0  4e 73 9e 01 42 d2 33 bb 43 b7
*/

    #[test]
    fn test_mdnsheader_from()
    {

    }
}
