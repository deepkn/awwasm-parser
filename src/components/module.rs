use crate::{limits::*};
use crate::{consts::*};
use crate::components::{section::*, types::*};
use nom_derive::*;
use nom::AsBytes;
use nom::IResult;

#[derive(Debug, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmModulePreamble<'a> {
    #[nom(Tag(WASM_MAGIC_NUMBER))]
    pub magic: &'a[u8],
    pub version: u32,
}

impl Default for AwwasmModulePreamble<'_> {
    fn default() -> Self {
        Self {
            magic: WASM_MAGIC_NUMBER.as_bytes().try_into().expect("Incorrect MAGIC NUMBER"),
            version: 1,
        }
    }
}

impl AwwasmModulePreamble<'_> {
    pub fn new(input: &[u8]) -> anyhow::Result<AwwasmModulePreamble> {
        let (_, preamble) = AwwasmModulePreamble::parse(input).map_err(|e| anyhow::anyhow!("Failed to parse WASM module preamble: {}", e))?;
        Ok(preamble)
    }
}


#[derive(Debug, PartialEq, Eq)]
pub struct AwwasmModule<'a> {
    pub preamble: AwwasmModulePreamble<'a>,
    pub sections: Option<Vec<AwwasmSection<'a>>>,
    pub types: Option<Vec<AwwasmTypeSectionItem<'a>>>,
    pub funcs: Option<Vec<AwwasmFuncSectionItem>>,
    pub code: Option<Vec<AwwasmCodeSectionItem<'a>>>,
}

impl Default for AwwasmModule<'_> {
    fn default() -> Self {
        Self {
            preamble: AwwasmModulePreamble::<'_>::default(),
            sections: vec![].into(),
            types: vec![].into(),
            funcs: vec![].into(),
            code: vec![].into(),
        }
    }
}

impl<'a> Parse<&'a[u8]> for AwwasmModule<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], AwwasmModule<'a>> {
        let (input, p) = AwwasmModulePreamble::<'_>::parse(input)?;
        Ok((input, Self {
            preamble: p,
            sections: vec![].into(),
            types: vec![].into(),
            funcs: vec![].into(),
            code: vec![].into(),
        }))
    }
}

impl AwwasmModule<'_> {
    pub fn new(input: &[u8]) -> anyhow::Result<AwwasmModule> {
        let (_, module) = AwwasmModule::parse(input).map_err(|e| anyhow::anyhow!("Failed to parse WASM module: {}", e))?;
        Ok(module)
    }
}


#[cfg(test)]
mod tests {
    use crate::components::module::{AwwasmModule, AwwasmModulePreamble};
    use anyhow::Result;

    #[test]
    fn decode_module_preamble_test() -> Result<()> {
        // Generate a wasm module with just preamble.
        let module = wat::parse_str("(module)")?;
        // Decode the preamble and validate.
        let preamble = AwwasmModulePreamble::new(&module)?;
        assert_eq!(preamble, AwwasmModulePreamble::default());
        Ok(())
    }

    #[test]
    fn decode_minimal_module_test() -> Result<()> {
        // Generate a wasm module with just preamble.
        let module = wat::parse_str("(module)")?;
        // Decode the module and validate.
        let module = AwwasmModule::new(&module)?;
        assert_eq!(module, AwwasmModule::default());
        Ok(())
    }
}

