use crate::{consts::*};
use nom_derive::*;
use nom_leb128::{leb128_u32, leb128_i32, leb128_i64};
use nom::{branch::alt, bytes::complete::tag, combinator::cond, multi::many_till};

// BlockType using nom_derive with custom parser for the 0x40 case
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub enum BlockValueType {
    VOID = 0x40,
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub enum WasmOpCode {
    // Control Flow
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0B,
    Br = 0x0C,
    BrIf = 0x0D,
    BrTable = 0x0E,
    Return = 0x0F,

    // Calls
    Call = 0x10,
    CallIndirect = 0x11,

    // Variable Access
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,

    // Memory Operations
    I32Load = 0x28,
    I64Load = 0x29,
    I32Store = 0x36,
    I64Store = 0x37,
    MemorySize = 0x3F,
    MemoryGrow = 0x40,

    // Constants
    I32Const = 0x41,
    I64Const = 0x42,
    F32Const = 0x43,
    F64Const = 0x44,

    // Numeric Operations
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32Add = 0x6A,
    I32Sub = 0x6B,
    I32Mul = 0x6C,
}

// Core instruction using nom_derive with Selector
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmInstruction<'a> {
    pub opcode: WasmOpCode,
    #[nom(Selector = "opcode", Parse = "{ |i| AwwasmOperands::parse(i, opcode) }")]
    pub operands: AwwasmOperands<'a>,
}

// Operands using nom_derive Selector properly
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian, Selector = "WasmOpCode")]
pub enum AwwasmOperands<'a> {
    // Control Flow (using custom parsers for nested structures)
    #[nom(Selector = "WasmOpCode::Block")]
    Block(BlockOperands<'a>),

    #[nom(Selector = "WasmOpCode::Loop")]
    Loop(LoopOperands<'a>),

    #[nom(Selector = "WasmOpCode::If")]
    If(IfOperands<'a>),
    
    // Branches - pure nom_derive
    #[nom(Selector = "WasmOpCode::Br")]
    Br(BrOperands),

    #[nom(Selector = "WasmOpCode::BrIf")]
    BrIf(BrOperands),

    #[nom(Selector = "WasmOpCode::BrTable")]
    BrTable(BrTableOperands),

    #[nom(Selector = "WasmOpCode::Return")]
    Return,

    // Calls - pure nom_derive
    #[nom(Selector = "WasmOpCode::Call")]
    Call(CallOperands),

    #[nom(Selector = "WasmOpCode::CallIndirect")]
    CallIndirect(CallIndirectOperands),

    // Variables - pure nom_derive
    #[nom(Selector = "WasmOpCode::LocalGet")]
    LocalGet(IndexOperands),

    #[nom(Selector = "WasmOpCode::LocalSet")]
    LocalSet(IndexOperands),

    #[nom(Selector = "WasmOpCode::LocalTee")]
    LocalTee(IndexOperands),

    #[nom(Selector = "WasmOpCode::GlobalGet")]
    GlobalGet(IndexOperands),

    #[nom(Selector = "WasmOpCode::GlobalSet")]
    GlobalSet(IndexOperands),

    // Memory - pure nom_derive
    #[nom(Selector = "WasmOpCode::I32Load")]
    I32Load(MemArg),

    #[nom(Selector = "WasmOpCode::I64Load")]
    I64Load(MemArg),

    #[nom(Selector = "WasmOpCode::I32Store")]
    I32Store(MemArg),

    #[nom(Selector = "WasmOpCode::I64Store")]
    I64Store(MemArg),

    #[nom(Selector = "WasmOpCode::MemorySize")]
    MemorySize(MemoryZeroOperands<'a>),

    #[nom(Selector = "WasmOpCode::MemoryGrow")]
    MemoryGrow(MemoryZeroOperands<'a>),

    // Constants - pure nom_derive
    #[nom(Selector = "WasmOpCode::I32Const")]
    I32Const(I32ConstOperands),

    #[nom(Selector = "WasmOpCode::I64Const")]
    I64Const(I64ConstOperands),

    #[nom(Selector = "WasmOpCode::F32Const")]
    F32Const(F32ConstOperands),

    #[nom(Selector = "WasmOpCode::F64Const")]
    F64Const(F64ConstOperands),

    // Numeric - no operands
    #[nom(Selector = "WasmOpCode::I32Eqz")]
    I32Eqz,

    #[nom(Selector = "WasmOpCode::I32Eq")]
    I32Eq,

    #[nom(Selector = "WasmOpCode::I32Ne")]
    I32Ne,

    #[nom(Selector = "WasmOpCode::I32Add")]
    I32Add,

    #[nom(Selector = "WasmOpCode::I32Sub")]
    I32Sub,

    #[nom(Selector = "WasmOpCode::I32Mul")]
    I32Mul,
}

// All operand structs using nom_derive
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct BrOperands {
    #[nom(Parse = "leb128_u32")]
    pub labelidx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct BrTableOperands {
    #[nom(Parse = "leb128_u32")]
    pub target_count: u32,
    #[nom(Count = "target_count")]
    pub targets: Vec<u32>,
    #[nom(Parse = "leb128_u32")]
    pub default: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct IndexOperands {
    #[nom(Parse = "leb128_u32")]
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct CallOperands {
    #[nom(Parse = "leb128_u32")]
    pub funcidx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct CallIndirectOperands {
    #[nom(Parse = "leb128_u32")]
    pub typeidx: u32,
    #[nom(Parse = "leb128_u32")]
    pub tableidx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct MemArg {
    #[nom(Parse = "leb128_u32")]
    pub align: u32,
    #[nom(Parse = "leb128_u32")]
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct MemoryZeroOperands<'a> {
    #[nom(Tag(WASM_INSTRUCTION_MEMORY_ZERO))]
    pub reserved: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct I32ConstOperands {
    #[nom(Parse = "leb128_i32")]
    pub value: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct I64ConstOperands {
    #[nom(Parse = "leb128_i64")]
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Nom)]
#[nom(LittleEndian)]
pub struct F32ConstOperands {
    pub value: f32,
}

impl Eq for F32ConstOperands {}

#[derive(Debug, Clone, PartialEq, Nom)]
#[nom(LittleEndian)]
pub struct F64ConstOperands {
    pub value: f64,
}

impl Eq for F64ConstOperands {}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
pub struct BlockOperands<'a> {
    pub block_type: BlockValueType,
    #[nom(Parse = "many_till(AwwasmInstruction::parse, tag([WASM_FUNC_SECTION_OPCODE_END]))")]
    pub body: (Vec<AwwasmInstruction<'a>>, &'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
pub struct LoopOperands<'a> {
    pub block_type: BlockValueType,
    #[nom(Parse = "many_till(AwwasmInstruction::parse, tag([WASM_FUNC_SECTION_OPCODE_END]))")]
    pub body: (Vec<AwwasmInstruction<'a>>, &'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
pub struct IfOperands<'a> {
    pub block_type: BlockValueType,
    #[nom(Parse = "many_till(AwwasmInstruction::parse, alt((tag([WASM_FUNC_SECTION_OPCODE_END]), tag([WASM_FUNC_SECTION_OPCODE_THEN]))))")]
    pub then_body: (Vec<AwwasmInstruction<'a>>, &'a [u8]),
    #[nom(Parse = "cond(then_body.1[0] == WASM_FUNC_SECTION_OPCODE_THEN, many_till(AwwasmInstruction::parse, tag([WASM_FUNC_SECTION_OPCODE_END])))")]
    pub else_body: Option<(Vec<AwwasmInstruction<'a>>, &'a [u8])>,
}

// Custom parsers only for recursive control structures
/* 
fn parse_instrs_until_end<'a>(i: &'a [u8]) -> IResult<&'a [u8], Vec<AwwasmInstruction<'a>>> {
    let (i, (instrs, _end)) = many_till(AwwasmInstruction::parse, tag([0x0B]))(i)?;
    Ok((i, instrs))
}

fn parse_block_operands<'a>(i: &'a [u8]) -> IResult<&'a [u8], BlockOperands<'a>> {
    let (i, block_type) = parse_block_type(i)?;
    let (i, body) = parse_instrs_until_end(i)?;
    Ok((i, BlockOperands { block_type, body }))
}

fn parse_loop_operands<'a>(i: &'a [u8]) -> IResult<&'a [u8], LoopOperands<'a>> {
    let (i, block_type) = parse_block_type(i)?;
    let (i, body) = parse_instrs_until_end(i)?;
    Ok((i, LoopOperands { block_type, body }))
}

fn parse_if_operands<'a>(i: &'a [u8]) -> IResult<&'a [u8], IfOperands<'a>> {
    let (i, block_type) = parse_block_type(i)?;
    let (i, (then_body, sep)) = many_till(AwwasmInstruction::parse, alt((tag([0x05]), tag([0x0B]))))(i)?;
    if sep[0] == 0x05 { // Else
        let (i, (else_body, _end)) = many_till(AwwasmInstruction::parse, tag([0x0B]))(i)?;
        Ok((i, IfOperands { block_type, then_body, else_body: Some(else_body) }))
    } else {
        Ok((i, IfOperands { block_type, then_body, else_body: None }))
    }
}
*/

// Lazy iterator for function bodies
pub struct InstructionIterator<'a> {
    remaining: &'a [u8],
}

impl<'a> InstructionIterator<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = Result<AwwasmInstruction<'a>, nom::Err<nom::error::Error<&'a [u8]>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        match AwwasmInstruction::parse(self.remaining) {
            Ok((rest, instr)) => {
                self.remaining = rest;
                Some(Ok(instr))
            },
            Err(e) => {
                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}