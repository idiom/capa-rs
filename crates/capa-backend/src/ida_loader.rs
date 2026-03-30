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

/// Extract imports by finding functions with external xrefs or in import segments.
///
/// IDA identifies imports through:
/// 1. Functions in extern/import segments (XTRN/IMP)
/// 2. Named entries that are imported symbols
/// 3. .plt thunk functions in ELF (unwrapped to their target name)
fn extract_imports(idb: &IDB) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Walk the name list — IDA's name list includes imports
    let names = idb.names();
    for name in names.iter() {
        let addr = name.address();

        // Check if this name is in an import/extern segment
        if let Some(seg) = idb.segment_at(addr) {
            let seg_type = seg.r#type();
            if seg_type.is_xtrn() || seg_type.is_imp() {
                let func_name = name.name().to_string();
                if seen.insert(func_name.clone()) {
                    // Try to extract module name from IDA's naming convention
                    // e.g., "kernel32_CreateFileA" or just "CreateFileA"
                    let (module, clean_name) = split_import_name(&func_name);
                    imports.push(ImportInfo {
                        name: clean_name,
                        module,
                        address: addr,
                    });
                }
            }
        }
    }

    // Also check for .plt thunk functions (ELF imports)
    for (_id, func) in idb.functions() {
        if func.flags().contains(FunctionFlags::THUNK) {
            if let Some(name) = func.name() {
                let normalized = name.trim_start_matches(['.', '_']).to_string();
                if !seen.contains(&normalized) {
                    seen.insert(normalized.clone());
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

/// Split an import name like "kernel32_CreateFileA" into module + function.
/// Returns (module, function_name).
fn split_import_name(name: &str) -> (Option<String>, String) {
    // Common Windows DLL prefixes that IDA uses in naming
    let known_modules = [
        "kernel32", "ntdll", "user32", "advapi32", "ws2_32", "wsock32",
        "ole32", "oleaut32", "shell32", "gdi32", "msvcrt", "ucrtbase",
        "comctl32", "comdlg32", "shlwapi", "wininet", "winhttp",
        "crypt32", "bcrypt", "ncrypt", "secur32", "wtsapi32",
        "psapi", "iphlpapi", "dnsapi", "netapi32", "mpr",
    ];

    // Check if name matches "module_function" pattern
    if let Some(pos) = name.find('_') {
        let prefix = &name[..pos].to_lowercase();
        if known_modules.iter().any(|m| m == prefix) {
            return (
                Some(format!("{}.dll", prefix)),
                name[pos + 1..].to_string(),
            );
        }
    }

    (None, name.to_string())
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
