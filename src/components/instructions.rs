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
    Unreachable = 0x00,
    Nop = 0x01,
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

    // Parametric
    Drop = 0x1A,
    Select = 0x1B,

    // Variable Access
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,

    // Memory Operations
    I32Load = 0x28,
    I64Load = 0x29,
    F32Load = 0x2A,
    F64Load = 0x2B,
    I32Load8S = 0x2C,
    I32Load8U = 0x2D,
    I32Load16S = 0x2E,
    I32Load16U = 0x2F,
    I64Load8S = 0x30,
    I64Load8U = 0x31,
    I64Load16S = 0x32,
    I64Load16U = 0x33,
    I64Load32S = 0x34,
    I64Load32U = 0x35,
    I32Store = 0x36,
    I64Store = 0x37,
    F32Store = 0x38,
    F64Store = 0x39,
    I32Store8 = 0x3A,
    I32Store16 = 0x3B,
    I64Store8 = 0x3C,
    I64Store16 = 0x3D,
    I64Store32 = 0x3E,
    MemorySize = 0x3F,
    MemoryGrow = 0x40,

    // Constants
    I32Const = 0x41,
    I64Const = 0x42,
    F32Const = 0x43,
    F64Const = 0x44,

    // i32 numeric
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32LtU = 0x49,
    I32GtS = 0x4A,
    I32GtU = 0x4B,
    I32LeS = 0x4C,
    I32LeU = 0x4D,
    I32GeS = 0x4E,
    I32GeU = 0x4F,

    // i64 numeric
    I64Eqz = 0x50,
    I64Eq = 0x51,
    I64Ne = 0x52,
    I64LtS = 0x53,
    I64LtU = 0x54,
    I64GtS = 0x55,
    I64GtU = 0x56,
    I64LeS = 0x57,
    I64LeU = 0x58,
    I64GeS = 0x59,
    I64GeU = 0x5A,

    // f32 comparisons
    F32Eq = 0x5B,
    F32Ne = 0x5C,
    F32Lt = 0x5D,
    F32Gt = 0x5E,
    F32Le = 0x5F,
    F32Ge = 0x60,

    // f64 comparisons
    F64Eq = 0x61,
    F64Ne = 0x62,
    F64Lt = 0x63,
    F64Gt = 0x64,
    F64Le = 0x65,
    F64Ge = 0x66,

    // i32 unary + arithmetic
    I32Clz = 0x67,
    I32Ctz = 0x68,
    I32Popcnt = 0x69,
    I32Add = 0x6A,
    I32Sub = 0x6B,
    I32Mul = 0x6C,
    I32DivS = 0x6D,
    I32DivU = 0x6E,
    I32RemS = 0x6F,
    I32RemU = 0x70,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,
    I32ShrU = 0x76,
    I32Rotl = 0x77,
    I32Rotr = 0x78,

    // i64 unary + arithmetic
    I64Clz = 0x79,
    I64Ctz = 0x7A,
    I64Popcnt = 0x7B,
    I64Add = 0x7C,
    I64Sub = 0x7D,
    I64Mul = 0x7E,
    I64DivS = 0x7F,
    I64DivU = 0x80,
    I64RemS = 0x81,
    I64RemU = 0x82,
    I64And = 0x83,
    I64Or = 0x84,
    I64Xor = 0x85,
    I64Shl = 0x86,
    I64ShrS = 0x87,
    I64ShrU = 0x88,
    I64Rotl = 0x89,
    I64Rotr = 0x8A,

    // f32 arithmetic
    F32Abs = 0x8B,
    F32Neg = 0x8C,
    F32Ceil = 0x8D,
    F32Floor = 0x8E,
    F32Trunc = 0x8F,
    F32Nearest = 0x90,
    F32Sqrt = 0x91,
    F32Add = 0x92,
    F32Sub = 0x93,
    F32Mul = 0x94,
    F32Div = 0x95,
    F32Min = 0x96,
    F32Max = 0x97,
    F32Copysign = 0x98,

    // f64 arithmetic
    F64Abs = 0x99,
    F64Neg = 0x9A,
    F64Ceil = 0x9B,
    F64Floor = 0x9C,
    F64Trunc = 0x9D,
    F64Nearest = 0x9E,
    F64Sqrt = 0x9F,
    F64Add = 0xA0,
    F64Sub = 0xA1,
    F64Mul = 0xA2,
    F64Div = 0xA3,
    F64Min = 0xA4,
    F64Max = 0xA5,
    F64Copysign = 0xA6,

    // Type conversions
    I32WrapI64 = 0xA7,
    I32TruncF32S = 0xA8,
    I32TruncF32U = 0xA9,
    I32TruncF64S = 0xAA,
    I32TruncF64U = 0xAB,
    I64ExtendI32S = 0xAC,
    I64ExtendI32U = 0xAD,
    I64TruncF32S = 0xAE,
    I64TruncF32U = 0xAF,
    I64TruncF64S = 0xB0,
    I64TruncF64U = 0xB1,
    F32ConvertI32S = 0xB2,
    F32ConvertI32U = 0xB3,
    F32ConvertI64S = 0xB4,
    F32ConvertI64U = 0xB5,
    F32DemoteF64 = 0xB6,
    F64ConvertI32S = 0xB7,
    F64ConvertI32U = 0xB8,
    F64ConvertI64S = 0xB9,
    F64ConvertI64U = 0xBA,
    F64PromoteF32 = 0xBB,
    I32ReinterpretF32 = 0xBC,
    I64ReinterpretF64 = 0xBD,
    F32ReinterpretI32 = 0xBE,
    F64ReinterpretI64 = 0xBF,

    // Sign-extension operators
    I32Extend8S = 0xC0,
    I32Extend16S = 0xC1,
    I64Extend8S = 0xC2,
    I64Extend16S = 0xC3,
    I64Extend32S = 0xC4,

    // Miscellaneous (0xFC prefix): trunc_sat, memory.copy, etc.
    Misc = 0xFC,
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
    #[nom(Selector = "WasmOpCode::Unreachable")]
    Unreachable,

    #[nom(Selector = "WasmOpCode::Nop")]
    Nop,

    #[nom(Selector = "WasmOpCode::Block")]
    Block(BlockOperands<'a>),

    #[nom(Selector = "WasmOpCode::Loop")]
    Loop(LoopOperands<'a>),

    #[nom(Selector = "WasmOpCode::If")]
    If(IfOperands<'a>),

    #[nom(Selector = "WasmOpCode::Else")]
    Else,

    #[nom(Selector = "WasmOpCode::End")]
    End,
    
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
 
    // Parametric
    #[nom(Selector = "WasmOpCode::Drop")]
    Drop,

    #[nom(Selector = "WasmOpCode::Select")]
    Select,

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
    #[nom(Selector = "WasmOpCode::I32Load")]    I32Load(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load")]    I64Load(MemArg),
    #[nom(Selector = "WasmOpCode::F32Load")]    F32Load(MemArg),
    #[nom(Selector = "WasmOpCode::F64Load")]    F64Load(MemArg),
    #[nom(Selector = "WasmOpCode::I32Load8S")]  I32Load8S(MemArg),
    #[nom(Selector = "WasmOpCode::I32Load8U")]  I32Load8U(MemArg),
    #[nom(Selector = "WasmOpCode::I32Load16S")] I32Load16S(MemArg),
    #[nom(Selector = "WasmOpCode::I32Load16U")] I32Load16U(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load8S")]  I64Load8S(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load8U")]  I64Load8U(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load16S")] I64Load16S(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load16U")] I64Load16U(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load32S")] I64Load32S(MemArg),
    #[nom(Selector = "WasmOpCode::I64Load32U")] I64Load32U(MemArg),
    #[nom(Selector = "WasmOpCode::I32Store")]   I32Store(MemArg),
    #[nom(Selector = "WasmOpCode::I64Store")]   I64Store(MemArg),
    #[nom(Selector = "WasmOpCode::F32Store")]   F32Store(MemArg),
    #[nom(Selector = "WasmOpCode::F64Store")]   F64Store(MemArg),
    #[nom(Selector = "WasmOpCode::I32Store8")]  I32Store8(MemArg),
    #[nom(Selector = "WasmOpCode::I32Store16")] I32Store16(MemArg),
    #[nom(Selector = "WasmOpCode::I64Store8")]  I64Store8(MemArg),
    #[nom(Selector = "WasmOpCode::I64Store16")] I64Store16(MemArg),
    #[nom(Selector = "WasmOpCode::I64Store32")] I64Store32(MemArg),

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

    // i32 numeric - no operands
    #[nom(Selector = "WasmOpCode::I32Eqz")]   I32Eqz,
    #[nom(Selector = "WasmOpCode::I32Eq")]    I32Eq,
    #[nom(Selector = "WasmOpCode::I32Ne")]    I32Ne,
    #[nom(Selector = "WasmOpCode::I32LtS")]   I32LtS,
    #[nom(Selector = "WasmOpCode::I32LtU")]   I32LtU,
    #[nom(Selector = "WasmOpCode::I32GtS")]   I32GtS,
    #[nom(Selector = "WasmOpCode::I32GtU")]   I32GtU,
    #[nom(Selector = "WasmOpCode::I32LeS")]   I32LeS,
    #[nom(Selector = "WasmOpCode::I32LeU")]   I32LeU,
    #[nom(Selector = "WasmOpCode::I32GeS")]   I32GeS,
    #[nom(Selector = "WasmOpCode::I32GeU")]   I32GeU,
    #[nom(Selector = "WasmOpCode::I32Clz")]   I32Clz,
    #[nom(Selector = "WasmOpCode::I32Ctz")]   I32Ctz,
    #[nom(Selector = "WasmOpCode::I32Popcnt")] I32Popcnt,
    #[nom(Selector = "WasmOpCode::I32Add")]   I32Add,
    #[nom(Selector = "WasmOpCode::I32Sub")]   I32Sub,
    #[nom(Selector = "WasmOpCode::I32Mul")]   I32Mul,
    #[nom(Selector = "WasmOpCode::I32DivS")]  I32DivS,
    #[nom(Selector = "WasmOpCode::I32DivU")]  I32DivU,
    #[nom(Selector = "WasmOpCode::I32RemS")]  I32RemS,
    #[nom(Selector = "WasmOpCode::I32RemU")]  I32RemU,
    #[nom(Selector = "WasmOpCode::I32And")]   I32And,
    #[nom(Selector = "WasmOpCode::I32Or")]    I32Or,
    #[nom(Selector = "WasmOpCode::I32Xor")]   I32Xor,
    #[nom(Selector = "WasmOpCode::I32Shl")]   I32Shl,
    #[nom(Selector = "WasmOpCode::I32ShrS")]  I32ShrS,
    #[nom(Selector = "WasmOpCode::I32ShrU")]  I32ShrU,
    #[nom(Selector = "WasmOpCode::I32Rotl")]  I32Rotl,
    #[nom(Selector = "WasmOpCode::I32Rotr")]  I32Rotr,

    // i64 numeric - no operands
    #[nom(Selector = "WasmOpCode::I64Eqz")]   I64Eqz,
    #[nom(Selector = "WasmOpCode::I64Eq")]    I64Eq,
    #[nom(Selector = "WasmOpCode::I64Ne")]    I64Ne,
    #[nom(Selector = "WasmOpCode::I64LtS")]   I64LtS,
    #[nom(Selector = "WasmOpCode::I64LtU")]   I64LtU,
    #[nom(Selector = "WasmOpCode::I64GtS")]   I64GtS,
    #[nom(Selector = "WasmOpCode::I64GtU")]   I64GtU,
    #[nom(Selector = "WasmOpCode::I64LeS")]   I64LeS,
    #[nom(Selector = "WasmOpCode::I64LeU")]   I64LeU,
    #[nom(Selector = "WasmOpCode::I64GeS")]   I64GeS,
    #[nom(Selector = "WasmOpCode::I64GeU")]   I64GeU,
    #[nom(Selector = "WasmOpCode::I64Clz")]   I64Clz,
    #[nom(Selector = "WasmOpCode::I64Ctz")]   I64Ctz,
    #[nom(Selector = "WasmOpCode::I64Popcnt")] I64Popcnt,
    #[nom(Selector = "WasmOpCode::I64Add")]   I64Add,
    #[nom(Selector = "WasmOpCode::I64Sub")]   I64Sub,
    #[nom(Selector = "WasmOpCode::I64Mul")]   I64Mul,
    #[nom(Selector = "WasmOpCode::I64DivS")]  I64DivS,
    #[nom(Selector = "WasmOpCode::I64DivU")]  I64DivU,
    #[nom(Selector = "WasmOpCode::I64RemS")]  I64RemS,
    #[nom(Selector = "WasmOpCode::I64RemU")]  I64RemU,
    #[nom(Selector = "WasmOpCode::I64And")]   I64And,
    #[nom(Selector = "WasmOpCode::I64Or")]    I64Or,
    #[nom(Selector = "WasmOpCode::I64Xor")]   I64Xor,
    #[nom(Selector = "WasmOpCode::I64Shl")]   I64Shl,
    #[nom(Selector = "WasmOpCode::I64ShrS")]  I64ShrS,
    #[nom(Selector = "WasmOpCode::I64ShrU")]  I64ShrU,
    #[nom(Selector = "WasmOpCode::I64Rotl")]  I64Rotl,
    #[nom(Selector = "WasmOpCode::I64Rotr")]  I64Rotr,

    // f32 comparisons - no operands
    #[nom(Selector = "WasmOpCode::F32Eq")]    F32Eq,
    #[nom(Selector = "WasmOpCode::F32Ne")]    F32Ne,
    #[nom(Selector = "WasmOpCode::F32Lt")]    F32Lt,
    #[nom(Selector = "WasmOpCode::F32Gt")]    F32Gt,
    #[nom(Selector = "WasmOpCode::F32Le")]    F32Le,
    #[nom(Selector = "WasmOpCode::F32Ge")]    F32Ge,

    // f64 comparisons - no operands
    #[nom(Selector = "WasmOpCode::F64Eq")]    F64Eq,
    #[nom(Selector = "WasmOpCode::F64Ne")]    F64Ne,
    #[nom(Selector = "WasmOpCode::F64Lt")]    F64Lt,
    #[nom(Selector = "WasmOpCode::F64Gt")]    F64Gt,
    #[nom(Selector = "WasmOpCode::F64Le")]    F64Le,
    #[nom(Selector = "WasmOpCode::F64Ge")]    F64Ge,

    // f32 arithmetic - no operands
    #[nom(Selector = "WasmOpCode::F32Abs")]      F32Abs,
    #[nom(Selector = "WasmOpCode::F32Neg")]      F32Neg,
    #[nom(Selector = "WasmOpCode::F32Ceil")]     F32Ceil,
    #[nom(Selector = "WasmOpCode::F32Floor")]    F32Floor,
    #[nom(Selector = "WasmOpCode::F32Trunc")]    F32Trunc,
    #[nom(Selector = "WasmOpCode::F32Nearest")]  F32Nearest,
    #[nom(Selector = "WasmOpCode::F32Sqrt")]     F32Sqrt,
    #[nom(Selector = "WasmOpCode::F32Add")]      F32Add,
    #[nom(Selector = "WasmOpCode::F32Sub")]      F32Sub,
    #[nom(Selector = "WasmOpCode::F32Mul")]      F32Mul,
    #[nom(Selector = "WasmOpCode::F32Div")]      F32Div,
    #[nom(Selector = "WasmOpCode::F32Min")]      F32Min,
    #[nom(Selector = "WasmOpCode::F32Max")]      F32Max,
    #[nom(Selector = "WasmOpCode::F32Copysign")] F32Copysign,

    // f64 arithmetic - no operands
    #[nom(Selector = "WasmOpCode::F64Abs")]      F64Abs,
    #[nom(Selector = "WasmOpCode::F64Neg")]      F64Neg,
    #[nom(Selector = "WasmOpCode::F64Ceil")]     F64Ceil,
    #[nom(Selector = "WasmOpCode::F64Floor")]    F64Floor,
    #[nom(Selector = "WasmOpCode::F64Trunc")]    F64Trunc,
    #[nom(Selector = "WasmOpCode::F64Nearest")]  F64Nearest,
    #[nom(Selector = "WasmOpCode::F64Sqrt")]     F64Sqrt,
    #[nom(Selector = "WasmOpCode::F64Add")]      F64Add,
    #[nom(Selector = "WasmOpCode::F64Sub")]      F64Sub,
    #[nom(Selector = "WasmOpCode::F64Mul")]      F64Mul,
    #[nom(Selector = "WasmOpCode::F64Div")]      F64Div,
    #[nom(Selector = "WasmOpCode::F64Min")]      F64Min,
    #[nom(Selector = "WasmOpCode::F64Max")]      F64Max,
    #[nom(Selector = "WasmOpCode::F64Copysign")] F64Copysign,

    // Type conversions - no operands
    #[nom(Selector = "WasmOpCode::I32WrapI64")]      I32WrapI64,
    #[nom(Selector = "WasmOpCode::I32TruncF32S")]    I32TruncF32S,
    #[nom(Selector = "WasmOpCode::I32TruncF32U")]    I32TruncF32U,
    #[nom(Selector = "WasmOpCode::I32TruncF64S")]    I32TruncF64S,
    #[nom(Selector = "WasmOpCode::I32TruncF64U")]    I32TruncF64U,
    #[nom(Selector = "WasmOpCode::I64ExtendI32S")]   I64ExtendI32S,
    #[nom(Selector = "WasmOpCode::I64ExtendI32U")]   I64ExtendI32U,
    #[nom(Selector = "WasmOpCode::I64TruncF32S")]    I64TruncF32S,
    #[nom(Selector = "WasmOpCode::I64TruncF32U")]    I64TruncF32U,
    #[nom(Selector = "WasmOpCode::I64TruncF64S")]    I64TruncF64S,
    #[nom(Selector = "WasmOpCode::I64TruncF64U")]    I64TruncF64U,
    #[nom(Selector = "WasmOpCode::F32ConvertI32S")]  F32ConvertI32S,
    #[nom(Selector = "WasmOpCode::F32ConvertI32U")]  F32ConvertI32U,
    #[nom(Selector = "WasmOpCode::F32ConvertI64S")]  F32ConvertI64S,
    #[nom(Selector = "WasmOpCode::F32ConvertI64U")]  F32ConvertI64U,
    #[nom(Selector = "WasmOpCode::F32DemoteF64")]    F32DemoteF64,
    #[nom(Selector = "WasmOpCode::F64ConvertI32S")]  F64ConvertI32S,
    #[nom(Selector = "WasmOpCode::F64ConvertI32U")]  F64ConvertI32U,
    #[nom(Selector = "WasmOpCode::F64ConvertI64S")]  F64ConvertI64S,
    #[nom(Selector = "WasmOpCode::F64ConvertI64U")]  F64ConvertI64U,
    #[nom(Selector = "WasmOpCode::F64PromoteF32")]   F64PromoteF32,
    #[nom(Selector = "WasmOpCode::I32ReinterpretF32")] I32ReinterpretF32,
    #[nom(Selector = "WasmOpCode::I64ReinterpretF64")] I64ReinterpretF64,
    #[nom(Selector = "WasmOpCode::F32ReinterpretI32")] F32ReinterpretI32,
    #[nom(Selector = "WasmOpCode::F64ReinterpretI64")] F64ReinterpretI64,

    // Sign-extension operators
    #[nom(Selector = "WasmOpCode::I32Extend8S")]  I32Extend8S,
    #[nom(Selector = "WasmOpCode::I32Extend16S")] I32Extend16S,
    #[nom(Selector = "WasmOpCode::I64Extend8S")]  I64Extend8S,
    #[nom(Selector = "WasmOpCode::I64Extend16S")] I64Extend16S,
    #[nom(Selector = "WasmOpCode::I64Extend32S")] I64Extend32S,

    // 0xFC prefix: trunc_sat and bulk memory ops
    #[nom(Selector = "WasmOpCode::Misc")]
    Misc(MiscOperands),
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

/// 0xFC prefix operands: reads the sub-opcode as a LEB128 u32.
/// For trunc_sat (sub-ops 0-7) there are no additional bytes.
#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct MiscOperands {
    #[nom(Parse = "leb128_u32")]
    pub sub_op: u32,
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


/// Evaluate a constant initializer expression and return its i32 value.
///
/// Used for data segment offsets and global initializers.
/// The `code` bytes contain the raw instruction (e.g. `i32.const N`)
/// without the trailing `end` (0x0B) opcode.
pub fn eval_const_init_expr(code: &[u8]) -> anyhow::Result<i32> {
    if code.is_empty() {
        return Err(anyhow::anyhow!("empty constant expression"));
    }

    let (_rest, instr) = AwwasmInstruction::parse(code)
        .map_err(|e| anyhow::anyhow!("failed to parse init expr: {}", e))?;

    match instr.operands {
        AwwasmOperands::I32Const(op) => Ok(op.value),
        _ => Err(anyhow::anyhow!("unsupported init expr opcode: {:?}", instr.opcode)),
    }
}