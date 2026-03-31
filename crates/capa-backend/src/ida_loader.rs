//! IDA Pro binary loader — produces BinaryInfo from an IDB.
//!
//! This module uses idalib-rs to extract the same metadata
//! (imports, exports, sections, strings) that goblin+loader.rs provides,
//! but leverages IDA's analysis for richer results.

use idalib::idb::IDB;
use idalib::func::FunctionFlags;
use capa_core::rule::{ArchType, FormatType, OsType};

use crate::loader::{BinaryInfo, ExportInfo, ImportInfo, SectionInfo, StringInfo};

/// Load binary metadata from an IDA database.
pub(crate) fn load_from_idb(idb: &IDB) -> BinaryInfo {
    let meta = idb.meta();
    let processor = idb.processor();

    // Detect architecture from IDA's processor module
    let arch = detect_arch(&processor, &meta);
    let os = detect_os(&meta);
    let format = detect_format(&meta);

    // Extract imports from IDA's name list and function analysis
    let imports = extract_imports(idb);
    let exports = extract_exports(idb);
    let sections = extract_sections(idb);
    let strings = extract_strings(idb);

    // Detect .NET
    let is_dotnet = matches!(format, FormatType::DotNet)
        || processor.family().is_net();

    let entry_point = meta.start_address().unwrap_or(0);

    BinaryInfo {
        os,
        arch,
        format,
        imports,
        exports,
        sections,
        strings,
        is_dotnet,
        has_forwarded_exports: false, // IDA resolves forwarded exports transparently
        is_mixed_mode: false,
        entry_point,
    }
}

fn detect_arch(
    processor: &idalib::processor::Processor<'_>,
    meta: &idalib::meta::Metadata<'_>,
) -> ArchType {
    let family = processor.family();

    if family.is_386() {
        if meta.is_64bit() {
            ArchType::Amd64
        } else {
            ArchType::I386
        }
    } else if family.is_arm() {
        if meta.is_64bit() {
            ArchType::Arm64
        } else {
            ArchType::Arm
        }
    } else if family.is_mips() {
        ArchType::Mips
    } else if family.is_ppc() {
        if meta.is_64bit() {
            ArchType::Ppc64
        } else {
            ArchType::Ppc
        }
    } else if meta.is_64bit() {
        ArchType::Amd64
    } else {
        ArchType::I386
    }
}

fn detect_os(meta: &idalib::meta::Metadata<'_>) -> OsType {
    use idalib::meta::FileType;

    match meta.filetype() {
        FileType::PE | FileType::WIN | FileType::EXE | FileType::COM | FileType::DRV => {
            OsType::Windows
        }
        FileType::ELF | FileType::AOUT => OsType::Linux,
        FileType::MACHO => OsType::MacOS,
        _ => OsType::Windows, // default fallback
    }
}

fn detect_format(meta: &idalib::meta::Metadata<'_>) -> FormatType {
    use idalib::meta::FileType;

    match meta.filetype() {
        FileType::PE | FileType::WIN | FileType::EXE | FileType::COM | FileType::DRV => {
            FormatType::Pe
        }
        FileType::ELF | FileType::AOUT => FormatType::Elf,
        FileType::MACHO => FormatType::MachO,
        _ => FormatType::Pe, // default fallback
    }
}

/// Extract imports using IDA's native import enumeration API.
///
/// This uses `get_import_module_qty()` + `enum_import_names()` to get
/// proper module→function mappings (e.g., kernel32.dll → CreateFileA),
/// which is essential for matching capa rules that use `api: module.function`.
///
/// Falls back to name-list walking for any imports not covered by the
/// native API (e.g., ELF .plt thunks).
fn extract_imports(idb: &IDB) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Primary: use IDA's native import enumeration
    // This gives us proper module names (kernel32.dll, ntdll.dll, etc.)
    let ida_imports = idalib::imports::enum_all_imports();
    for entry in &ida_imports {
        let module = if entry.module.is_empty() {
            None
        } else {
            // Normalize module name: ensure it has .dll suffix
            let m = entry.module.to_lowercase();
            if m.ends_with(".dll") || m.ends_with(".drv") || m.ends_with(".sys")
                || m.ends_with(".ocx") || m.ends_with(".exe")
            {
                Some(m)
            } else {
                Some(format!("{}.dll", m))
            }
        };

        let key = format!("{}@{:#x}", entry.name, entry.address);
        if seen.insert(key) {
            imports.push(ImportInfo {
                name: entry.name.clone(),
                module,
                address: entry.address,
            });
        }
    }

    // Secondary: check for .plt thunk functions (ELF imports not in module table)
    for (_id, func) in idb.functions() {
        if func.flags().contains(FunctionFlags::THUNK) {
            if let Some(name) = func.name() {
                let normalized = name.trim_start_matches(['.', '_']).to_string();
                let key = format!("{}@{:#x}", normalized, func.start_address());
                if seen.insert(key) {
                    imports.push(ImportInfo {
                        name: normalized,
                        module: None,
                        address: func.start_address(),
                    });
                }
            }
        }
    }

    imports
}

/// Extract exports from functions that are publicly named.
fn extract_exports(idb: &IDB) -> Vec<ExportInfo> {
    let mut exports = Vec::new();
    let names = idb.names();

    for name in names.iter() {
        if name.is_public() {
            exports.push(ExportInfo {
                name: name.name().to_string(),
                address: name.address(),
                is_forwarded: false,
                forward_target: None,
            });
        }
    }

    exports
}

/// Extract sections from IDA's segment list.
fn extract_sections(idb: &IDB) -> Vec<SectionInfo> {
    let mut sections = Vec::new();

    for (_id, seg) in idb.segments() {
        let name = seg.name().unwrap_or_default();
        let perms = seg.permissions();

        sections.push(SectionInfo {
            name,
            address: seg.start_address(),
            size: seg.len() as u64,
            is_executable: perms.is_executable(),
        });
    }

    sections
}

/// Extract strings from IDA's string list.
fn extract_strings(idb: &IDB) -> Vec<StringInfo> {
    let mut strings = Vec::new();
    let strlist = idb.strings();
    strlist.rebuild();

    for (addr, value) in strlist.iter() {
        if value.len() >= 4 {
            strings.push(StringInfo { value, address: addr });
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_import_name_with_module() {
        let (module, name) = split_import_name("kernel32_CreateFileA");
        assert_eq!(module, Some("kernel32.dll".to_string()));
        assert_eq!(name, "CreateFileA");
    }

    #[test]
    fn test_split_import_name_without_module() {
        let (module, name) = split_import_name("CreateFileA");
        assert_eq!(module, None);
        assert_eq!(name, "CreateFileA");
    }

    #[test]
    fn test_split_import_name_unknown_module() {
        let (module, name) = split_import_name("unknown_SomeFunction");
        assert_eq!(module, None);
        assert_eq!(name, "unknown_SomeFunction");
    }

    #[test]
    fn test_split_import_name_case_insensitive() {
        let (module, name) = split_import_name("KERNEL32_CreateFileA");
        assert_eq!(module, Some("kernel32.dll".to_string()));
        assert_eq!(name, "CreateFileA");
    }
}
