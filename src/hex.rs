use std::fmt;

pub struct Hex<'a>(&'a [u8], usize);

impl<'a> Hex<'a>
{
    pub fn new<T>(data: &'a T, length: usize) -> Hex<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        Hex(data.as_ref(), length)
    }
}

impl fmt::Display for Hex<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        for i in 0..self.1
        {
            if i % 16 == 0
            {
                if i > 0
                {
                    write!(f, "\n")?;
                }

                write!(f, "{:04x}  ", i)?;
                write!(f, "{:02x}", self.0[i])?;
            }
            else
            {
                write!(f, " {:02x}", self.0[i])?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_length_0()
    {
        assert_eq!(format!("{}", Hex::new(&[], 0)), "");
    }

    #[test]
    fn test_length_1()
    {
        assert_eq!(format!("{}", Hex::new(&[0], 1)), "0000  00");
    }

    #[test]
    fn test_length_3()
    {
        assert_eq!(format!("{}", Hex::new(&[1, 2, 3], 3)), "0000  01 02 03");
    }

    #[test]
    fn test_length_16()
    {
        let data: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(format!("{}", Hex::new(&data, 16)), "0000  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10");
    }

    #[test]
    fn test_length_17()
    {
        let data: [u8; 17] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        assert_eq!(format!("{}", Hex::new(&data, 17)), "0000  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10\n0010  11");
    }

    #[test]
    fn test_length_cutoff()
    {
        let data: [u8; 17] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        assert_eq!(format!("{}", Hex::new(&data, 15)), "0000  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
    }
}
