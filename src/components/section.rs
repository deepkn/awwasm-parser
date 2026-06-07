use num_derive::FromPrimitive;
use nom_derive::*;
use nom_leb128::leb128_u32;
use nom::bytes::complete::take;
use nom::multi::count;
use nom::combinator::cond;
use crate::components::types::*;

// Helper: number of bytes needed to encode a u32 in unsigned LEB128
#[inline]
fn leb128_len_u32(mut v: u32) -> u32 {
    let mut len: u32 = 1;
    while v >= 0x80 {
        v >>= 7;
        len += 1;
    }
    len
}

/// Section IDs as defined by the WebAssembly binary format specification.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum SectionCode {
    /// Custom section — arbitrary name + bytes; skipped during resolve.
    Custom = 0x00,
    /// Type section (function signatures).
    Type = 0x01,
    /// Import section.
    Import = 0x02,
    /// Function section (type indices).
    Function = 0x03,
    /// Table section.
    Table = 0x04,
    /// Memory section.
    Memory = 0x05,
    /// Global section.
    Global = 0x06,
    /// Export section.
    Export = 0x07,
    /// Start section (single funcidx).
    Start = 0x08,
    /// Element section (table initializers).
    Element = 0x09,
    /// Code section (function bodies).
    Code = 0x0a,
    /// Data section (memory initializers).
    Data = 0x0b,
}

/// Resolved section content after calling `AwwasmSection::resolve()`.
pub enum SectionItem<'a> {
    TypeSectionItems(Option<Vec<AwwasmTypeSectionItem<'a>>>),
    ImportSectionItems(Option<Vec<AwwasmImportSectionItem<'a>>>),
    FunctionSectionItems(Option<Vec<AwwasmFuncSectionItem>>),
    TableSectionItems(Option<Vec<AwwasmTableSectionItem>>),
    MemorySectionItems(Option<Vec<AwwasmMemorySectionItem>>),
    GlobalSectionItems(Option<Vec<AwwasmGlobalSectionItem<'a>>>),
    ExportSectionItems(Option<Vec<AwwasmExportSectionItem<'a>>>),
    ElementSectionItems(Option<Vec<AwwasmElementSectionItem<'a>>>),
    CodeSectionItems(Option<Vec<AwwasmCodeSectionItem<'a>>>),
    DataSectionItems(Option<Vec<AwwasmDataSectionItem<'a>>>),
    /// Start section: contains the start item (or None if section was empty).
    StartSection(Option<AwwasmStartSectionItem>),
    /// Custom section: body was skipped, nothing to resolve.
    CustomSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmSectionHeader {
    pub section_type: SectionCode,
    #[nom(Parse = "leb128_u32")]
    pub section_size: u32,
}

/// A raw parsed section containing a header and unresolved body bytes.
///
/// Parsing notes:
/// - **Custom** sections: body is skipped entirely (`entry_count = 0`, `section_body = &[]`).
/// - **Start** sections: body is just a single funcidx encoded as LEB128, stored in `entry_count`.
/// - All other sections follow the standard format: `[entry_count: leb128][body_bytes]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwwasmSection<'a> {
    pub section_header: AwwasmSectionHeader,
    /// For standard sections: number of entries.
    /// For Start sections: the funcidx.
    /// For Custom sections: always 0.
    pub entry_count: u32,
    /// Raw body bytes (empty for Custom and Start sections).
    pub section_body: &'a [u8],
}

impl<'a> nom_derive::Parse<&'a [u8]> for AwwasmSection<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, section_header) = AwwasmSectionHeader::parse(input)?;

        match section_header.section_type {
            SectionCode::Custom => {
                // Skip the entire custom section body — arbitrary content.
                let size = section_header.section_size as usize;
                let (input, _body) = take(size)(input)?;
                Ok((input, AwwasmSection {
                    section_header,
                    entry_count: 0,
                    section_body: &[],
                }))
            }
            SectionCode::Start => {
                // Start section body is exactly one funcidx encoded as LEB128.
                // Reuse entry_count to store the funcidx value.
                let size = section_header.section_size as usize;
                let (input, body) = take(size)(input)?;
                let (_, funcidx) = leb128_u32(body)?;
                Ok((input, AwwasmSection {
                    section_header,
                    entry_count: funcidx,
                    section_body: &[],
                }))
            }
            _ => {
                // Standard sections: [entry_count: leb128][body_bytes...]
                let (input, entry_count) = leb128_u32(input)?;
                let body_size = section_header.section_size
                    .checked_sub(leb128_len_u32(entry_count))
                    .unwrap_or(0) as usize;
                let (input, section_body) = take(body_size)(input)?;
                Ok((input, AwwasmSection {
                    section_header,
                    entry_count,
                    section_body,
                }))
            }
        }
    }
}

impl<'a> AwwasmSection<'a> {
    /// Resolve this section's raw body bytes into typed `SectionItem` contents.
    pub fn resolve(&mut self) -> anyhow::Result<SectionItem<'a>> {
        match self.section_header.section_type {
            SectionCode::Custom => Ok(SectionItem::CustomSection),
            SectionCode::Start => {
                // entry_count holds the funcidx (set during parsing)
                let item = if self.section_header.section_size > 0 {
                    Some(AwwasmStartSectionItem { func_idx: self.entry_count })
                } else {
                    None
                };
                Ok(SectionItem::StartSection(item))
            }
            SectionCode::Type => {
                let mut types: Option<Vec<AwwasmTypeSectionItem<'a>>> = None;
                (self.section_body, types) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmTypeSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Type Section: {}", e))?;
                Ok(SectionItem::TypeSectionItems(types))
            }
            SectionCode::Import => {
                let mut imports: Option<Vec<AwwasmImportSectionItem<'a>>> = None;
                (self.section_body, imports) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmImportSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Import Section: {}", e))?;
                Ok(SectionItem::ImportSectionItems(imports))
            }
            SectionCode::Function => {
                let mut funcs: Option<Vec<AwwasmFuncSectionItem>> = None;
                (self.section_body, funcs) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmFuncSectionItem::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Function Section: {}", e))?;
                Ok(SectionItem::FunctionSectionItems(funcs))
            }
            SectionCode::Table => {
                let mut tables: Option<Vec<AwwasmTableSectionItem>> = None;
                (self.section_body, tables) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmTableSectionItem::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Table Section: {}", e))?;
                Ok(SectionItem::TableSectionItems(tables))
            }
            SectionCode::Memory => {
                let mut memories: Option<Vec<AwwasmMemorySectionItem>> = None;
                (self.section_body, memories) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmMemorySectionItem::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Memory Section: {}", e))?;
                Ok(SectionItem::MemorySectionItems(memories))
            }
            SectionCode::Global => {
                let mut globals: Option<Vec<AwwasmGlobalSectionItem<'a>>> = None;
                (self.section_body, globals) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmGlobalSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Global Section: {}", e))?;
                Ok(SectionItem::GlobalSectionItems(globals))
            }
            SectionCode::Export => {
                let mut exports: Option<Vec<AwwasmExportSectionItem<'a>>> = None;
                (self.section_body, exports) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmExportSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Export Section: {}", e))?;
                Ok(SectionItem::ExportSectionItems(exports))
            }
            SectionCode::Element => {
                let mut elements: Option<Vec<AwwasmElementSectionItem<'a>>> = None;
                (self.section_body, elements) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmElementSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Element Section: {}", e))?;
                Ok(SectionItem::ElementSectionItems(elements))
            }
            SectionCode::Code => {
                let mut code: Option<Vec<AwwasmCodeSectionItem<'a>>> = None;
                (self.section_body, code) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmCodeSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Code Section: {}", e))?;
                Ok(SectionItem::CodeSectionItems(code))
            }
            SectionCode::Data => {
                let mut data: Option<Vec<AwwasmDataSectionItem<'a>>> = None;
                (self.section_body, data) = cond(
                    !self.section_body.is_empty(),
                    count(AwwasmDataSectionItem::<'_>::parse, self.entry_count.try_into().unwrap()),
                )(self.section_body)
                .map_err(|e| anyhow::anyhow!("Failed to parse WASM Data Section: {}", e))?;
                Ok(SectionItem::DataSectionItems(data))
            }
        }
    }
}
