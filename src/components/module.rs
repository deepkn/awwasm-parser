use crate::{limits::*};
use crate::{consts::*};
use crate::components::{section::*, types::*};
use anyhow::Error;
use nom_derive::*;
use nom::AsBytes;
use nom::IResult;
use nom::multi::{count, many1};
use nom::combinator::cond;

#[derive(Debug, Clone, PartialEq, Eq, Nom)]
#[nom(LittleEndian)]
pub struct AwwasmModulePreamble<'a> {
    #[nom(Tag(WASM_MAGIC_NUMBER))]
    pub magic: &'a[u8],
    pub version: u32,
}

impl Default for AwwasmModulePreamble<'_> {
    fn default() -> Self {
        Self {
            magic: WASM_MAGIC_NUMBER.as_bytes().try_into().expect("Incorrect WASM MAGIC NUMBER"),
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


#[derive(Debug, PartialEq, Eq, Clone)]
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
            sections: None,
            types: None,
            funcs: None,
            code: None,
        }
    }
}

impl<'a> Parse<&'a[u8]> for AwwasmModule<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], AwwasmModule<'a>> {
        let (input, p) = AwwasmModulePreamble::<'_>::parse(input)?;
        let (input, secs) = cond(!input.is_empty(), many1(AwwasmSection::<'_>::parse))(input)?;
        Ok((input, Self {
            preamble: p,
            sections: secs,
            types: None,
            funcs: None,
            code: None,
        }))
    }
}

impl AwwasmModule<'_> {
    pub fn new(input: &[u8]) -> anyhow::Result<AwwasmModule> {
        let (_, module) = AwwasmModule::parse(input).map_err(|e| anyhow::anyhow!("Failed to parse WASM module: {}", e))?;
        Ok(module)
    }
}

impl<'a> AwwasmModule<'a> {
    pub fn resolve_all_sections(&mut self) -> anyhow::Result<()> {
        self.sections.as_mut().unwrap().iter_mut().for_each(|sec| { 
            let items = sec.resolve().map_err(|e| anyhow::anyhow!("Failed to parse WASM module: {}", e));
            match items.unwrap() {
                SectionItem::TypeSectionItems(x) => { self.types = x; },
                SectionItem::FunctionSectionItems(x) => { self.funcs = x; },
                SectionItem::CodeSectionItems(x) => { self.code = x; },
            }
        });
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::components::module::{AwwasmModule, AwwasmModulePreamble};
    use crate::components::section::{AwwasmSection, AwwasmSectionHeader, SectionCode};
    use crate::components::types::{AwwasmCodeSectionItem, AwwasmFuncSectionItem, AwwasmTypeSectionItem, ParamType};
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
        let module_parsed = AwwasmModule::new(&module)?;
        assert_eq!(module_parsed, AwwasmModule::default());
        Ok(())
    }

    #[test]
    fn decode_minimal_module_with_minimal_fuction_test() -> Result<()> {
        // Generate a wasm module with just preamble and an empty function.
        let module = wat::parse_str("(module (func))")?;
        // Decode the module and validate.
        let module_parsed = AwwasmModule::new(&module)?;
        assert_eq!(module_parsed, AwwasmModule {
            preamble: AwwasmModulePreamble::<'_>::default(),
            sections: Some(vec![AwwasmSection { 
                section_header: AwwasmSectionHeader {
                    section_type: SectionCode::Type,
                    section_size: 4,
                },
                entry_count: 1,
                section_body: &[96, 0, 0],
            }, AwwasmSection {
                section_header: AwwasmSectionHeader {
                    section_type: SectionCode::Function,
                    section_size: 2,
                },
                entry_count: 1,
                section_body: &[0],
            }, AwwasmSection {
                section_header: AwwasmSectionHeader {
                    section_type: SectionCode::Code,
                    section_size: 4,
                },
                entry_count: 1,
                section_body: &[2, 0, 11], 
            }]),
            types: None,
            funcs: None,
            code: None,
        });
        Ok(())
    }

    #[test]
    fn decode_function_signature_test() -> Result<()> {
        // Generate a wasm module with a function that takes parameters.
        let module = wat::parse_str("(module (func (param i32 i64)))")?;
        // Top level decode the module
        let mut module_parsed = AwwasmModule::new(&module)?;
        // Resolve all sections
        module_parsed.resolve_all_sections()?;
        assert_eq!(module_parsed.types, Some(vec![AwwasmTypeSectionItem {
            type_magic: &[96],
            fn_args: vec![ParamType::I32, ParamType::I64],
            fn_rets: vec![],
        }]));
        assert_eq!(module_parsed.funcs, Some(vec![AwwasmFuncSectionItem {
            type_item_idx: 0,
        }]));
        assert_eq!(module_parsed.code, Some(vec![AwwasmCodeSectionItem {
            fn_body_size: 2,
            func_body: &[0, 11],
        }]));
        Ok(())
    }

    #[test]
    fn decode_function_local_params_test() -> Result<()> {
        // Generate a wasm module with a basic function with some local parameters.
        let module = wat::parse_str(
    "(module
            (func
                (local i32)
                (local i64 i64)
            )
        )")?;
        // Init and top level decode the module
        let mut module_parsed = AwwasmModule::new(&module)?;
        // Resolve all sections
        module_parsed.resolve_all_sections()?;
        println!("{:?}", module_parsed);
        assert_eq!(module_parsed.types, Some(vec![AwwasmTypeSectionItem {
            type_magic: &[96],
            fn_args: vec![],
            fn_rets: vec![],
        }]));
        assert_eq!(module_parsed.funcs, Some(vec![AwwasmFuncSectionItem {
            type_item_idx: 0,
        }]));
        assert_eq!(module_parsed.code, Some(vec![AwwasmCodeSectionItem {
            fn_body_size: 2,
            func_body: &[0, 11],
        }]));
        Ok(())
    }
}

