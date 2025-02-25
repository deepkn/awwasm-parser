
pub(crate) const WASM_MAGIC_NUMBER: &[u8; 4] = b"\0asm";
pub(crate) const WASM_PREAMBLE_MAGIC_SIZE_BYTES: usize = 4;
pub(crate) const WASM_PREAMBLE_VERSION_SIZE_BYTES: usize = 4;

pub(crate) const WASM_TYPE_SECTION_OPCODE_FUNC: &[u8; 1] = b"\x60";
pub(crate) const WASM_FUNC_SECTION_OPCODE_END: u8 = 0x0b;
