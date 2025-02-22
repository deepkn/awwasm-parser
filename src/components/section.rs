use num_derive::FromPrimitive;
use nom_derive::*;
use nom_leb128::leb128_u32;
use crate::components::module::AwwasmModule;
use crate::components::types::*;
use nom::multi::{count, many1};
use nom::combinator::cond;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
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

pub enum SectionItem<'a> {
    TypeSectionItems(Option<Vec<AwwasmTypeSectionItem<'a>>>),
    FunctionSectionItems(Option<Vec<AwwasmFuncSectionItem>>),
    CodeSectionItems(Option<Vec<AwwasmCodeSectionItem<'a>>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmSectionHeader {
    pub section_type: SectionCode,
    #[nom(Parse="leb128_u32")]
    pub section_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian, Complete)]
pub struct AwwasmSection<'a> {
    pub section_header: AwwasmSectionHeader,
    #[nom(Parse="leb128_u32")]
    pub entry_count: u32,
    #[nom(Take="section_header.section_size.checked_sub(1).unwrap_or(0)")]
    pub section_body: &'a [u8],
}

impl<'a> AwwasmSection<'a> {
    pub fn resolve(&mut self) -> anyhow::Result<SectionItem<'a>> {
        match self.section_header.section_type {
            SectionCode::Type => {
                let mut types: Option<Vec<AwwasmTypeSectionItem<'a>>> = None;
                (self.section_body, types) = cond(!self.section_body.is_empty(), count(AwwasmTypeSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()))(self.section_body).map_err(|e| anyhow::anyhow!("Failed to parse WASM Type Section: {}", e))?;
                println!("Type Section: {:?}", types);
                Ok(SectionItem::TypeSectionItems(types))
            },
            SectionCode::Function => {
                let mut funcs: Option<Vec<AwwasmFuncSectionItem>> = None;
                (self.section_body, funcs) = cond(!self.section_body.is_empty(), count(AwwasmFuncSectionItem::parse, self.entry_count.try_into().unwrap()))(self.section_body).map_err(|e| anyhow::anyhow!("Failed to parse WASM Function Section: {}", e))?;
                println!("Fn Section: {:?}", funcs);
                Ok(SectionItem::FunctionSectionItems(funcs))
            },
            SectionCode::Code => {
                let mut code: Option<Vec<AwwasmCodeSectionItem<'a>>> = None;
                (self.section_body, code) = cond(!self.section_body.is_empty(), count(AwwasmCodeSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()))(self.section_body).map_err(|e| anyhow::anyhow!("Failed to parse WASM Code Section: {}", e))?;
                println!("Code Section: {:?}", code);
                Ok(SectionItem::CodeSectionItems(code))
            },
            _ => Err(anyhow::anyhow!("Unknown/Not Implemented WASM module section")),
        }
    }
}
