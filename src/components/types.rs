use crate::{consts::*};
use crate::components::{instructions::*};
use num_derive::FromPrimitive;
use nom_derive::*;
use nom::number::complete::le_u8;
use nom_leb128::leb128_u32;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum ParamType {
    I32 = 0x7F,
    I64 = 0x7E,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmTypeSectionItem<'a> {
    #[nom(Tag(WASM_TYPE_SECTION_OPCODE_FUNC))]
    pub type_magic: &'a[u8],
    #[nom(LengthCount="le_u8")]
    pub fn_args: Vec<ParamType>,
    #[nom(LengthCount="le_u8")]
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
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct FuncLocalParams {
    #[nom(LengthCount="le_u8")]
    pub local_vars: Vec<ParamType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct FuncBody {
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFunction {
    pub locals: FuncLocalParams,
    pub body: FuncBody,
}