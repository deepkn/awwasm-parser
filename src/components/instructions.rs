use num_derive::FromPrimitive;
use nom_derive::*;

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, Eq, FromPrimitive, Nom)]
#[nom(LittleEndian)]
pub enum Instruction {
    End,
}