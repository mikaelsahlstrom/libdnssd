use std::string;

use super::mdns_error;

const FLAGS_QR_MASK: u16 = 0x8000;
const FLAGS_QR_QUERY: u16 = 0x0000;
const FLAGS_QR_RESPONSE: u16 = 0x8000;
const MAX_COMPRESSION_POINTERS: u8 = 126;
const MAX_LABEL_OCTETS: u8 = 255;

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
    answer: bool,
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
    // Based on UnpackDomainName in https://github.com/miekg/dns/blob/master/msg.go
    fn name_to_string(buffer: [u8; 4096], pos: usize) -> Result<String, mdns_error::MdnsError>
    {
        let mut string: String = String::new();
        let mut jumps: u8 = 0;
        let mut offset = pos;

        loop
        {
            if offset >= 4096
            {
                return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::OutOfBuffer));
            }

            match buffer[offset] & 0xc0
            {
                0x00 =>
                {
                    if buffer[offset] == 0
                    {
                        // End of name.
                        break;
                    }

                    if offset + buffer[offset] as usize > 4096
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::OutOfBuffer));
                    }

                    if buffer[offset] + 1 >= MAX_LABEL_OCTETS  // + 1 due to label separator.
                    {
                        return Err(mdns_error::MdnsError::MdnsParsingError(mdns_error::MdnsParsingErrorType::LabelToLong));
                    }

                    for i in offset + 1..offset + 1 + buffer[offset] as usize
                    {
                        if Self::has_special_char(buffer[i])
                        {
                            string.push('\\');
                        }
                        else if buffer[i] < 32 || buffer[i] > 126
                        {

                        }
                    }
                },
                0xc0 =>
                {

                },
                _ =>
                {

                }
            }
        }

        Ok(string)
    }

    // Based on isDomainNameLabelSpecial in https://github.com/miekg/dns/blob/master/types.go
    fn has_special_char(c: u8) -> bool
    {
        if ['.', ' ', '\'', '@', ';', '(', ')', '"', '\\'].contains(&(c as char))
        {
            return true;
        }

        return false;
    }

    // Based on escapeByte in https://github.com/miekg/dns/blob/master/types.go
    fn escape_byte(c: u8) -> String
    {
        let mut offset: usize = c.into();

        let small_bytes: &str = "\\000\\001\\002\\003\\004\\005\\006\\007\\008\\009\
		                         \\010\\011\\012\\013\\014\\015\\016\\017\\018\\019\
		                         \\020\\021\\022\\023\\024\\025\\026\\027\\028\\029\
		                         \\030\\031";
        let large_bytes: &str = "\\127\\128\\129\\130\\131\\132\\133\\134\\135\\136\
                                 \\137\\138\\139\\140\\141\\142\\143\\144\\145\\146\
                                 \\147\\148\\149\\150\\151\\152\\153\\154\\155\\156\
                                 \\157\\158\\159\\160\\161\\162\\163\\164\\165\\166\
                                 \\167\\168\\169\\170\\171\\172\\173\\174\\175\\176\
                                 \\177\\178\\179\\180\\181\\182\\183\\184\\185\\186\
                                 \\187\\188\\189\\190\\191\\192\\193\\194\\195\\196\
                                 \\197\\198\\199\\200\\201\\202\\203\\204\\205\\206\
                                 \\207\\208\\209\\210\\211\\212\\213\\214\\215\\216\
                                 \\217\\218\\219\\220\\221\\222\\223\\224\\225\\226\
                                 \\227\\228\\229\\230\\231\\232\\233\\234\\235\\236\
                                 \\237\\238\\239\\240\\241\\242\\243\\244\\245\\246\
                                 \\247\\248\\249\\250\\251\\252\\253\\254\\255";

        let mut str: String = String::new();

        if offset < 32
        {
            offset = offset * 4;
            str.push(small_bytes.chars().nth(offset).unwrap());
            str.push(small_bytes.chars().nth(offset + 1).unwrap());
            str.push(small_bytes.chars().nth(offset + 2).unwrap());
            str.push(small_bytes.chars().nth(offset + 3).unwrap());
            return str;
        }

        offset -= 127;
        offset = offset * 4;

        str.push(large_bytes.chars().nth(offset).unwrap());
        str.push(large_bytes.chars().nth(offset + 1).unwrap());
        str.push(large_bytes.chars().nth(offset + 2).unwrap());
        str.push(large_bytes.chars().nth(offset + 3).unwrap());

        return str;
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
            answer: flags & FLAGS_QR_MASK == FLAGS_QR_RESPONSE,
            questions_len: u16::from_be_bytes([buffer[4], buffer[5]]),
            answers_len: u16::from_be_bytes([buffer[6], buffer[7]]),
            authorities_len: u16::from_be_bytes([buffer[8], buffer[9]]),
            additional_len: u16::from_be_bytes([buffer[10], buffer[11]]),
            queries: Vec::new(),
            answers: Vec::new()
        };

        if header.answer && header.answers_len > 0
        {
            for i in 0..header.answers_len
            {
                // Get answer and add to header.
            }
            // println!("test: {}", MdnsHeader::name_to_string(buffer, 13));
        }

        Ok(header)
    }
}

/* QUERY
0000   00 00 00 00 00 06 00 00 00 01 00 01 0f 5f 63 6f
0010   6d 70 61 6e 69 6f 6e 2d 6c 69 6e 6b 04 5f 74 63
0020   70 05 6c 6f 63 61 6c 00 00 0c 80 01 04 5f 68 61
0030   70 c0 1c 00 0c 80 01 04 5f 68 61 70 04 5f 75 64
0040   70 c0 21 00 0c 80 01 02 6c 62 07 5f 64 6e 73 2d
0050   73 64 c0 3c 00 0c 80 01 0c 5f 73 6c 65 65 70 2d
0060   70 72 6f 78 79 c0 3c 00 0c 80 01 11 4d 69 6b 61
0070   65 6c 20 e2 80 93 20 69 50 68 6f 6e 65 07 5f 72
0080   64 6c 69 6e 6b c0 1c 00 ff 80 01 c0 6b 00 21 00
0090   01 00 00 00 78 00 17 00 00 00 00 ee d0 0e 4d 69
00a0   6b 61 65 6c 2d 2d 69 50 68 6f 6e 65 c0 21 00 00
00b0   29 05 a0 00 00 11 94 00 12 00 04 00 0e 00 46 92
00c0   11 4e 73 9e 01 42 d2 33 bb 43 b7
*/

/* Dirigera response
0000   00 00 84 00 00 00 00 04 00 00 00 00 04 5f 68 61
0010   70 04 5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c 00
0020   01 00 00 11 94 00 0b 08 44 49 52 49 47 45 52 41
0030   c0 0c c0 27 00 10 80 01 00 00 11 94 00 65 05 63
0040   23 3d 31 34 04 66 66 3d 31 14 69 64 3d 42 35 3a
0050   42 30 3a 41 30 3a 36 37 3a 42 34 3a 36 39 22 6d
0060   64 3d 44 49 52 49 47 45 52 41 20 48 75 62 20 66
0070   6f 72 20 73 6d 61 72 74 20 70 72 6f 64 75 63 74
0080   73 06 70 76 3d 31 2e 31 04 73 23 3d 39 04 73 66
0090   3d 30 04 63 69 3d 32 0b 73 68 3d 6b 37 50 76 43
00a0   67 3d 3d c0 27 00 21 80 01 00 00 00 78 00 19 00
00b0   00 00 00 1f 40 10 67 77 32 2d 38 66 66 36 65 64
00c0   32 31 30 61 34 38 c0 16 c0 b5 00 1c 80 01 00 00
00d0   00 78 00 10 fd 05 0b 30 32 24 4a 5c 6a ec 8a ff
00e0   fe 00 d0 ed
*/

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_mdnsheader_from()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 203] =  [0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x0f, 0x5f, 0x63, 0x6f,
                                  0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69, 0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63,
                                  0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x80, 0x01, 0x04, 0x5f, 0x68, 0x61,
                                  0x70, 0xc0, 0x1c, 0x00, 0x0c, 0x80, 0x01, 0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x75, 0x64,
                                  0x70, 0xc0, 0x21, 0x00, 0x0c, 0x80, 0x01, 0x02, 0x6c, 0x62, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d,
                                  0x73, 0x64, 0xc0, 0x3c, 0x00, 0x0c, 0x80, 0x01, 0x0c, 0x5f, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x2d,
                                  0x70, 0x72, 0x6f, 0x78, 0x79, 0xc0, 0x3c, 0x00, 0x0c, 0x80, 0x01, 0x11, 0x4d, 0x69, 0x6b, 0x61,
                                  0x65, 0x6c, 0x20, 0xe2, 0x80, 0x93, 0x20, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x07, 0x5f, 0x72,
                                  0x64, 0x6c, 0x69, 0x6e, 0x6b, 0xc0, 0x1c, 0x00, 0xff, 0x80, 0x01, 0xc0, 0x6b, 0x00, 0x21, 0x00,
                                  0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0xee, 0xd0, 0x0e, 0x4d, 0x69,
                                  0x6b, 0x61, 0x65, 0x6c, 0x2d, 0x2d, 0x69, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0xc0, 0x21, 0x00, 0x00,
                                  0x29, 0x05, 0xa0, 0x00, 0x00, 0x11, 0x94, 0x00, 0x12, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x46, 0x92,
                                  0x11, 0x4e, 0x73, 0x9e, 0x01, 0x42, 0xd2, 0x33, 0xbb, 0x43, 0xb7];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        let mdnsheader = MdnsHeader::from(buffer, 186);
    }

    #[test]
    fn test_name_to_string_1()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 17] = [ 0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00 ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        assert_eq!(MdnsHeader::name_to_string(buffer, 0).unwrap(), "_hap._tcp.local");
    }

    #[test]
    fn test_name_to_string_2()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 28] = [ 0x0f, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69, 0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00 ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        assert_eq!(MdnsHeader::name_to_string(buffer, 0).unwrap(), "_companion-link._tcp.local");
    }

    #[test]
    fn test_name_to_string_3()
    {
        let mut buffer: [u8; 4096] = [0; 4096];
        let packet: [u8; 228] = [ 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x68, 0x61,
                                  0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00,
                                  0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x0b, 0x08, 0x44, 0x49, 0x52, 0x49, 0x47, 0x45, 0x52, 0x41,
                                  0xc0, 0x0c, 0xc0, 0x27, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x65, 0x05, 0x63,
                                  0x23, 0x3d, 0x31, 0x34, 0x04, 0x66, 0x66, 0x3d, 0x31, 0x14, 0x69, 0x64, 0x3d, 0x42, 0x35, 0x3a,
                                  0x42, 0x30, 0x3a, 0x41, 0x30, 0x3a, 0x36, 0x37, 0x3a, 0x42, 0x34, 0x3a, 0x36, 0x39, 0x22, 0x6d,
                                  0x64, 0x3d, 0x44, 0x49, 0x52, 0x49, 0x47, 0x45, 0x52, 0x41, 0x20, 0x48, 0x75, 0x62, 0x20, 0x66,
                                  0x6f, 0x72, 0x20, 0x73, 0x6d, 0x61, 0x72, 0x74, 0x20, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
                                  0x73, 0x06, 0x70, 0x76, 0x3d, 0x31, 0x2e, 0x31, 0x04, 0x73, 0x23, 0x3d, 0x39, 0x04, 0x73, 0x66,
                                  0x3d, 0x30, 0x04, 0x63, 0x69, 0x3d, 0x32, 0x0b, 0x73, 0x68, 0x3d, 0x6b, 0x37, 0x50, 0x76, 0x43,
                                  0x67, 0x3d, 0x3d, 0xc0, 0x27, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x19, 0x00,
                                  0x00, 0x00, 0x00, 0x1f, 0x40, 0x10, 0x67, 0x77, 0x32, 0x2d, 0x38, 0x66, 0x66, 0x36, 0x65, 0x64,
                                  0x32, 0x31, 0x30, 0x61, 0x34, 0x38, 0xc0, 0x16, 0xc0, 0xb5, 0x00, 0x1c, 0x80, 0x01, 0x00, 0x00,
                                  0x00, 0x78, 0x00, 0x10, 0xfd, 0x05, 0x0b, 0x30, 0x32, 0x24, 0x4a, 0x5c, 0x6a, 0xec, 0x8a, 0xff,
                                  0xfe, 0x00, 0xd0, 0xed ];

        for i in 0..packet.len()
        {
            buffer[i] = packet[i];
        }

        assert_eq!(MdnsHeader::name_to_string(buffer, 50).unwrap(), "DIRIGERA._hap._tcp.local");
    }
}
