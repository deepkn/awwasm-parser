use crate::{consts::*};
use crate::components::{instructions::*};
use num_derive::FromPrimitive;
use nom_derive::*;
use nom::number::complete::le_u8;
use nom_leb128::leb128_u32;
use nom::bytes::complete::take_while;
use nom::combinator::cond;

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
    #[nom(Ignore)]
    pub parsed_func: Option<AwwasmFunction<'a>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFunction<'a> {
    #[nom(LengthCount="le_u8")]
    pub fn_rets: Vec<AwwasmFunctionLocals>,
    #[nom(Parse = "take_while(|byte| byte != WASM_FUNC_SECTION_OPCODE_END)")]
    pub code: &'a[u8],
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmFunctionLocals {
    #[nom(Parse="leb128_u32")]
    pub type_count: u32,
    #[nom(Count="1")]
    pub param_type: Vec<ParamType>,
}

impl<'a> AwwasmCodeSectionItem<'a> {
    pub fn resolve(&mut self) -> anyhow::Result<()> {
        (self.func_body, self.parsed_func) = cond(!self.func_body.is_empty(), AwwasmFunction::<'_>::parse)(self.func_body).map_err(|e| anyhow::anyhow!("Failed to parse WASM Function: {}", e))?;
        Ok(())
    }
}