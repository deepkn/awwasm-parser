use crate::{consts::*};
use crate::components::{instructions::*};
use num_derive::FromPrimitive;
use nom_derive::*;
use nom_leb128::leb128_u32;
use nom::bytes::complete::take_while;
use nom::combinator::cond;
use nom::number::complete::le_u8;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum ParamType {
    IUnknown = 0x00,
    F64 = 0x7C,
    F32 = 0x7D,
    I64 = 0x7E,
    I32 = 0x7F,
}

impl Default for ParamType {
    fn default() -> Self {
        ParamType::IUnknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmTypeSectionItem<'a> {
    #[nom(Tag(WASM_TYPE_SECTION_OPCODE_FUNC))]
    pub type_magic: &'a[u8],
    #[nom(LengthCount="leb128_u32")]
    pub fn_args: Vec<ParamType>,
    #[nom(LengthCount="leb128_u32")]
    pub fn_rets: Vec<ParamType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFuncSectionItem {
    #[nom(Parse="leb128_u32")]
    pub type_item_idx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmCodeSectionItem<'a> {
    #[nom(Parse="leb128_u32")]
    pub fn_body_size: u32,
    #[nom(Take="fn_body_size")]
    pub func_body: &'a[u8],
    #[nom(Ignore)]
    pub parsed_func: Option<AwwasmFunction<'a>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFunction<'a> {
    #[nom(LengthCount="leb128_u32")]
    pub fn_rets: Vec<AwwasmFunctionLocals>,
    #[nom(Parse = "take_while(|byte| byte != WASM_FUNC_SECTION_OPCODE_END)")]
    pub code: &'a[u8],
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFunctionLocals {
    #[nom(Parse="leb128_u32")]
    pub type_count: u32,
    pub param_type: ParamType,
}

impl<'a> AwwasmCodeSectionItem<'a> {
    pub fn resolve(&mut self) -> anyhow::Result<()> {
        (self.func_body, self.parsed_func) = cond(!self.func_body.is_empty(), AwwasmFunction::<'_>::parse)(self.func_body).map_err(|e| anyhow::anyhow!("Failed to parse WASM Function: {}", e))?;
        Ok(())
    }
}

// Memory section types
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmMemoryParams {
    #[nom(Parse = "leb128_u32")]
    pub flags: u32,
    #[nom(Parse = "leb128_u32")]
    pub min: u32,
    #[nom(Cond = "(flags & 0x1) != 0", Parse = "leb128_u32")]
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmMemorySectionItem {
    pub limits: AwwasmMemoryParams,
}

// Import section types
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmName<'a> {
    #[nom(Parse = "leb128_u32")]
    pub len: u32,
    #[nom(Take = "len")]
    pub bytes: &'a [u8],
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum AwwasmImportKind {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmImportSectionItem<'a> {
    pub module: AwwasmName<'a>,
    pub name: AwwasmName<'a>,
    pub kind: AwwasmImportKind,
    #[nom(Cond = "kind == AwwasmImportKind::Function", Parse = "leb128_u32")]
    pub func_type_idx: Option<u32>,
    #[nom(Cond = "kind == AwwasmImportKind::Memory")]
    pub mem: Option<AwwasmMemoryParams>,
}

// Export section types
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum AwwasmExportKind {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmExportSectionItem<'a> {
    pub name: AwwasmName<'a>,
    pub kind: AwwasmExportKind,
    #[nom(Parse = "leb128_u32")]
    pub index: u32,
}

// Start section types
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmStartSectionItem {
    #[nom(Parse = "leb128_u32")]
    pub func_idx: u32,
}

// Data section types
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmDataInitExpr<'a> {
    #[nom(Parse = "take_while(|byte| byte != WASM_FUNC_SECTION_OPCODE_END)")]
    pub code: &'a [u8],
    #[nom(Parse = "le_u8")]
    pub end: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmDataSegmentHeader<'a> {
    #[nom(Parse = "leb128_u32")]
    pub flags: u32,
    #[nom(Cond = "flags == 0x02", Parse = "leb128_u32")]
    pub memidx: Option<u32>,
    #[nom(Cond = "flags == 0x00 || flags == 0x02")]
    pub offset: Option<AwwasmDataInitExpr<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmDataSectionItem<'a> {
    pub header: AwwasmDataSegmentHeader<'a>,
    #[nom(Parse = "leb128_u32")]
    pub size: u32,
    #[nom(Take = "size")]
    pub data_bytes: &'a [u8],
}

// Global value mutability state
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum AwwasmGlobalMutability {
    Immutable = 0x00,
    Mutable   = 0x01,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmGlobalSectionItem<'a> {
    pub value_type: ParamType,
    pub mutability: AwwasmGlobalMutability,
    pub init_expr: AwwasmDataInitExpr<'a>,
}

// Table reference type
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum AwwasmTableReferenceType {
    Function = 0x70,
    Extern = 0x6F,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmTableSectionItem {
    pub elem_type: AwwasmTableReferenceType,
    pub limits: AwwasmMemoryParams,
}

// Element section variants

// Element kind byte
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum AwwasmElemKind {
    FuncRef = 0x00,
}
// Active element segment, implicit table
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmActiveImplicitElemSeg<'a> {
    pub offset: AwwasmDataInitExpr<'a>,
    #[nom(Parse = "leb128_u32")]
    pub func_count: u32,
    #[nom(Count = "func_count as usize", Parse = "leb128_u32")]
    pub func_indices: Vec<u32>,
}

// Passive element segment
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmPassiveElemSeg {
    pub elemkind: AwwasmElemKind,
    #[nom(Parse = "leb128_u32")]
    pub func_count: u32,
    #[nom(Count = "func_count as usize", Parse = "leb128_u32")]
    pub func_indices: Vec<u32>,
}

// Active element segment, explicit table
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmActiveExplicitElemSeg<'a> {
    #[nom(Parse = "leb128_u32")]
    pub tableidx: u32,
    pub offset: AwwasmDataInitExpr<'a>,
    pub elemkind: AwwasmElemKind,
    #[nom(Parse = "leb128_u32")]
    pub func_count: u32,
    #[nom(Count = "func_count as usize", Parse = "leb128_u32")]
    pub func_indices: Vec<u32>,
}

// Declarative element segment
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmDeclarativeElemSeg {
    pub elemkind: AwwasmElemKind,
    #[nom(Parse = "leb128_u32")]
    pub func_count: u32,
    #[nom(Count = "func_count as usize", Parse = "leb128_u32")]
    pub func_indices: Vec<u32>,
}

// Dispatcher enum — selects a payload subtype based on the flags value.
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian, Selector = "u32")]
pub enum AwwasmElemSegmentBody<'a> {
    // flags = 0x00: active, implicit table 0
    #[nom(Selector = "0_u32")]
    ActiveImplicit(AwwasmActiveImplicitElemSeg<'a>),
    // flags = 0x01: passive
    #[nom(Selector = "1_u32")]
    Passive(AwwasmPassiveElemSeg),
    // flags = 0x02: active, explicit tableidx
    #[nom(Selector = "2_u32")]
    ActiveExplicit(AwwasmActiveExplicitElemSeg<'a>),
    // flags = 0x03: declarative
    #[nom(Selector = "3_u32")]
    Declarative(AwwasmDeclarativeElemSeg),
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmElementSectionItem<'a> {
    #[nom(Parse = "leb128_u32")]
    pub flags: u32,
    #[nom(Selector = "flags", Parse = "{ |i| AwwasmElemSegmentBody::parse(i, flags) }")]
    pub body: AwwasmElemSegmentBody<'a>,
}
