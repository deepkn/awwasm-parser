use num_derive::FromPrimitive;
use nom_derive::*;
use nom_leb128::leb128_u32;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum SectionCode {
    Type = 0x01,
    Import = 0x02,
    Function = 0x03,
    Memory = 0x05,
    Export = 0x07,
    Code = 0x0a,
    Data = 0x0b,
}

#[derive(Debug, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmSectionHeader {
    pub section_type: SectionCode,
    #[nom(Parse="leb128_u32")]
    pub section_size: u32,
}

#[derive(Debug, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmSection<'a> {
    pub section_header: AwwasmSectionHeader,
    #[nom(Parse="leb128_u32")]
    pub entry_count: u32,
    #[nom(Take="section_header.section_size")]
    pub section_body: &'a [u8],
}



