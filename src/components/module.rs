use crate::{limits::*};
use crate::{consts::*};
use crate::components::{section::*, types::*};
use nom_derive::*;
use nom::AsBytes;
use nom::IResult;
use nom::multi::many1;
use nom::combinator::{cond, complete};

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
    /// Raw parsed sections (before resolve).
    pub sections: Option<Vec<AwwasmSection<'a>>>,
    /// Resolved type section.
    pub types: Option<Vec<AwwasmTypeSectionItem<'a>>>,
    /// Resolved import section.
    pub imports: Option<Vec<AwwasmImportSectionItem<'a>>>,
    /// Resolved export section.
    pub exports: Option<Vec<AwwasmExportSectionItem<'a>>>,
    /// Resolved function section (type indices).
    pub funcs: Option<Vec<AwwasmFuncSectionItem>>,
    /// Resolved code section (function bodies).
    pub code: Option<Vec<AwwasmCodeSectionItem<'a>>>,
    /// Resolved memory section.
    pub memories: Option<Vec<AwwasmMemorySectionItem>>,
    /// Resolved data section.
    pub data: Option<Vec<AwwasmDataSectionItem<'a>>>,
    /// Resolved global section.
    pub globals: Option<Vec<AwwasmGlobalSectionItem<'a>>>,
    /// Resolved table section.
    pub tables: Option<Vec<AwwasmTableSectionItem>>,
    /// Resolved element section.
    pub elements: Option<Vec<AwwasmElementSectionItem<'a>>>,
    /// Start section item (from start section), if present.
    pub start: Option<AwwasmStartSectionItem>,
}

impl Default for AwwasmModule<'_> {
    fn default() -> Self {
        Self {
            preamble: AwwasmModulePreamble::<'_>::default(),
            sections: None,
            types: None,
            imports: None,
            exports: None,
            funcs: None,
            code: None,
            memories: None,
            data: None,
            globals: None,
            tables: None,
            elements: None,
            start: None,
        }
    }
}

impl<'a> Parse<&'a[u8]> for AwwasmModule<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], AwwasmModule<'a>> {
        let (input, p) = AwwasmModulePreamble::<'_>::parse(input)?;
        let (input, secs) = cond(!input.is_empty(), many1(complete(AwwasmSection::<'_>::parse)))(input)?;
        Ok((input, Self {
            preamble: p,
            sections: secs,
            types: None,
            imports: None,
            exports: None,
            funcs: None,
            code: None,
            memories: None,
            data: None,
            globals: None,
            tables: None,
            elements: None,
            start: None,
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
    /// Resolve all raw section bodies into typed data.
    ///
    /// After calling this, fields like `types`, `imports`, `funcs`, `code`,
    /// `memories`, `data`, `globals`, `tables`, `elements`, and `start` are
    /// populated from the parsed sections.
    pub fn resolve_all_sections(&mut self) -> anyhow::Result<()> {
        self.sections.as_mut().unwrap().iter_mut().for_each(|sec| { 
            let items = sec.resolve().map_err(|e| anyhow::anyhow!("Failed to parse WASM module: {}", e));
            match items.unwrap() {
                SectionItem::TypeSectionItems(x)     => { self.types    = x; }
                SectionItem::ImportSectionItems(x)   => { self.imports  = x; }
                SectionItem::FunctionSectionItems(x) => { self.funcs    = x; }
                SectionItem::TableSectionItems(x)    => { self.tables   = x; }
                SectionItem::MemorySectionItems(x)   => { self.memories = x; }
                SectionItem::GlobalSectionItems(x)   => { self.globals  = x; }
                SectionItem::ExportSectionItems(x)   => { self.exports  = x; }
                SectionItem::ElementSectionItems(x)  => { self.elements = x; }
                SectionItem::CodeSectionItems(x)     => { self.code     = x; }
                SectionItem::DataSectionItems(x)     => { self.data     = x; }
                SectionItem::StartSection(x)         => { self.start    = x; }
                SectionItem::CustomSection           => { /* skip */ }
            }
        });
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::components::module::{AwwasmModule, AwwasmModulePreamble};
    use crate::components::section::{AwwasmSection, AwwasmSectionHeader, SectionCode};
    use crate::components::types::{
        AwwasmCodeSectionItem, AwwasmFuncSectionItem, AwwasmFunction, 
        AwwasmFunctionLocals, AwwasmTypeSectionItem, ParamType, 
        AwwasmImportKind, AwwasmExportKind,
        AwwasmGlobalMutability, AwwasmTableReferenceType,
        AwwasmStartSectionItem,
    };
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
            // All resolved fields default to None before resolve_all_sections()
            ..AwwasmModule::default()
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
            parsed_func: None,
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
        assert_eq!(module_parsed.types, Some(vec![AwwasmTypeSectionItem {
            type_magic: &[96],
            fn_args: vec![],
            fn_rets: vec![],
        }]));
        assert_eq!(module_parsed.funcs, Some(vec![AwwasmFuncSectionItem {
            type_item_idx: 0,
        }]));
        assert_eq!(module_parsed.code, Some(vec![AwwasmCodeSectionItem {
            fn_body_size: 6,
            func_body: &[2, 1, 127, 2, 126, 11],
            parsed_func: None,
        }]));
        module_parsed.code.as_mut().unwrap().iter_mut().for_each(|x| {
            x.resolve().unwrap();
        });
        assert_eq!(module_parsed.code, Some(vec![AwwasmCodeSectionItem {
            fn_body_size: 6,
            func_body: &[11],
            parsed_func: Some(AwwasmFunction {
                fn_rets: vec![AwwasmFunctionLocals {
                    type_count: 1,
                    param_type: ParamType::I32,
                }, AwwasmFunctionLocals {
                    type_count: 2,
                    param_type: ParamType::I64,
                }],
                code: &[],
            }),
        }]));
        Ok(())
    }

    #[test]
    fn decode_memory_min_only_test() -> anyhow::Result<()> {
        // (memory 1) => flags = 0, min = 1, no max
        let module = wat::parse_str("(module (memory 1))")?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let memories = module_parsed.memories.as_ref().expect("memories should exist");
        assert_eq!(memories.len(), 1);
        let m = &memories[0];
        assert_eq!(m.limits.flags, 0);
        assert_eq!(m.limits.min, 1);
        assert!(m.limits.max.is_none());
        Ok(())
    }

    #[test]
    fn decode_memory_min_max_test() -> anyhow::Result<()> {
        // (memory 1 2) => flags = 1, min = 1, max = 2
        let module = wat::parse_str("(module (memory 1 2))")?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let memories = module_parsed.memories.as_ref().expect("memories should exist");
        assert_eq!(memories.len(), 1);
        let m = &memories[0];
        assert_eq!(m.limits.flags, 1);
        assert_eq!(m.limits.min, 1);
        assert_eq!(m.limits.max, Some(2));
        Ok(())
    }

    #[test]
    fn decode_import_memory_and_function_test() -> anyhow::Result<()> {
        // Import a memory and a function; ensure both decode correctly
        let module = wat::parse_str(r#"
            (module
            (import "env" "mem" (memory 1 2))
            (import "env" "add1" (func (param i32) (result i32)))
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        // Validate imports
        let imports = module_parsed.imports.as_ref().expect("imports should exist");
        assert_eq!(imports.len(), 2);

        // memory import
        let i0 = &imports[0];
        assert_eq!(i0.module.bytes, b"env");
        assert_eq!(i0.name.bytes, b"mem");
        assert_eq!(i0.kind, AwwasmImportKind::Memory);
        assert!(i0.func_type_idx.is_none());
        let mp = i0.mem.as_ref().expect("memory params");
        assert_eq!(mp.flags, 1);
        assert_eq!(mp.min, 1);
        assert_eq!(mp.max, Some(2));

        // function import
        let i1 = &imports[1];
        assert_eq!(i1.module.bytes, b"env");
        assert_eq!(i1.name.bytes, b"add1");
        assert_eq!(i1.kind, AwwasmImportKind::Function);
        assert!(i1.mem.is_none());
        // Function imports reference a type index; with this single func type it should be 0
        assert_eq!(i1.func_type_idx, Some(0));

        // validate the generated type section as well
        let types = module_parsed.types.as_ref().expect("types should exist");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].type_magic, &[0x60]);
        assert_eq!(types[0].fn_args, vec![ParamType::I32]);
        assert_eq!(types[0].fn_rets, vec![ParamType::I32]);

        Ok(())
    }

    #[test]
    fn decode_export_memory_and_function_test() -> anyhow::Result<()> {
        // Define a module with one function and one memory, and export both.
        let module = wat::parse_str(r#"
            (module
                (func (param i32) (result i32))
                (memory 1 2)
                (export "mem" (memory 0))
                (export "add1" (func 0))
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        // Validate exports
        let exports = module_parsed.exports.as_ref().expect("exports should exist");
        assert_eq!(exports.len(), 2);

        // First export: memory 0 as "mem"
        let e0 = &exports[0];
        assert_eq!(e0.name.bytes, b"mem");
        assert_eq!(e0.kind, AwwasmExportKind::Memory);
        assert_eq!(e0.index, 0);

        // Second export: func 0 as "add1"
        let e1 = &exports[1];
        assert_eq!(e1.name.bytes, b"add1");
        assert_eq!(e1.kind, AwwasmExportKind::Function);
        assert_eq!(e1.index, 0);

        // validate the type section produced for the function
        let types = module_parsed.types.as_ref().expect("types should exist");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].type_magic, &[0x60]);
        assert_eq!(types[0].fn_args, vec![ParamType::I32]);
        assert_eq!(types[0].fn_rets, vec![ParamType::I32]);

        Ok(())
    }

    #[test]
    fn decode_data_active_implicit_memidx_test() -> anyhow::Result<()> {
        // Active segment with implicit memidx 0 and offset i32.const 1, bytes "hi"
        let module = wat::parse_str(r#"
            (module
            (memory 1)
            (data (i32.const 1) "hi")
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let data = module_parsed.data.as_ref().expect("data should exist");
        assert_eq!(data.len(), 1);

        let seg = &data[0];
        assert_eq!(seg.header.flags, 0x00);                    // active, implicit memidx
        assert_eq!(seg.header.memidx, None);
        let offset = seg.header.offset.as_ref().expect("offset expr");
        assert_eq!(offset.end, 0x0b);                          // end opcode consumed
        assert!(!offset.code.is_empty() && offset.code[0] == 0x41); // i32.const
        assert_eq!(offset.code.last().copied(), Some(0x01));   // value 1 (LEB128)
        assert_eq!(seg.size, 2);
        assert_eq!(seg.data_bytes, b"hi");
        Ok(())
    }

    #[test]
    fn decode_data_active_explicit_memidx_test() -> anyhow::Result<()> {
        // Active segment with explicit memidx 1 and offset i32.const 2, bytes "x"
        let module = wat::parse_str(r#"
            (module
                (memory 1)
                (memory 1)
                (data 1 (i32.const 2) "x")
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let data = module_parsed.data.as_ref().expect("data should exist");
        assert_eq!(data.len(), 1);

        let seg = &data[0];
        assert_eq!(seg.header.flags, 0x02);                    // active with explicit memidx
        assert_eq!(seg.header.memidx, Some(1));
        let offset = seg.header.offset.as_ref().expect("offset expr");
        assert_eq!(offset.end, 0x0b);                          // end opcode consumed
        assert!(!offset.code.is_empty() && offset.code[0] == 0x41); // i32.const
        assert_eq!(offset.code.last().copied(), Some(0x02));   // value 2 (LEB128)
        assert_eq!(seg.size, 1);
        assert_eq!(seg.data_bytes, b"x");
        Ok(())
    }

    #[test]
    fn decode_global_section_test() -> anyhow::Result<()> {
        let module = wat::parse_str(r#"
            (module
                (global i32 (i32.const 42))
                (global (mut i64) (i64.const 100))
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let globals = module_parsed.globals.as_ref().expect("globals should exist");
        assert_eq!(globals.len(), 2);
        assert_eq!(globals[0].value_type, ParamType::I32);
        assert_eq!(globals[0].mutability, AwwasmGlobalMutability::Immutable);
        assert_eq!(globals[1].value_type, ParamType::I64);
        assert_eq!(globals[1].mutability, AwwasmGlobalMutability::Mutable);
        Ok(())
    }

    #[test]
    fn decode_table_section_test() -> anyhow::Result<()> {
        let module = wat::parse_str(r#"
            (module
                (table 10 funcref)
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        let tables = module_parsed.tables.as_ref().expect("tables should exist");
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].elem_type, AwwasmTableReferenceType::Function);
        assert_eq!(tables[0].limits.min, 10);
        assert!(tables[0].limits.max.is_none());
        Ok(())
    }

    #[test]
    fn decode_start_section_test() -> anyhow::Result<()> {
        let module = wat::parse_str(r#"
            (module
                (func)
                (start 0)
            )
        "#)?;
        let mut module_parsed = AwwasmModule::new(&module)?;
        module_parsed.resolve_all_sections()?;

        assert_eq!(module_parsed.start, Some(AwwasmStartSectionItem { func_idx: 0 }));
        Ok(())
    }
}
