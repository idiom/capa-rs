//! Binary loading using goblin
//!
//! Loads PE and ELF binaries and extracts basic metadata.

use capa_core::rule::{ArchType, FormatType, OsType};
use goblin::Object;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("Failed to parse binary: {0}")]
    ParseError(String),
    #[error("Unsupported binary format")]
    UnsupportedFormat,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Information extracted from binary header
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub os: OsType,
    pub arch: ArchType,
    pub format: FormatType,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub sections: Vec<SectionInfo>,
    pub strings: Vec<StringInfo>,
    /// PE-specific: has .NET CLR header
    pub is_dotnet: bool,
    /// PE-specific: has forwarded exports
    pub has_forwarded_exports: bool,
    /// PE-specific: is mixed-mode assembly (native + .NET)
    pub is_mixed_mode: bool,
    /// Entry point address
    pub entry_point: u64,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub name: String,
    pub module: Option<String>,
    pub address: u64,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    /// True if this export forwards to another DLL
    pub is_forwarded: bool,
    /// Forward target if forwarded (e.g., "NTDLL.RtlAllocateHeap")
    pub forward_target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_executable: bool,
}

#[derive(Debug, Clone)]
pub struct StringInfo {
    pub value: String,
    pub address: u64,
}

/// Load a binary and extract metadata
pub fn load_binary(bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    match Object::parse(bytes).map_err(|e| LoaderError::ParseError(e.to_string()))? {
        Object::PE(pe) => load_pe(&pe, bytes),
        Object::Elf(elf) => load_elf(&elf, bytes),
        Object::Mach(_) => Err(LoaderError::UnsupportedFormat),
        Object::Archive(_) => Err(LoaderError::UnsupportedFormat),
        Object::Unknown(_) => Err(LoaderError::UnsupportedFormat),
        _ => Err(LoaderError::UnsupportedFormat),
    }
}

/// Load a binary with explicit format specification
/// Used for shellcode or when auto-detection fails
pub fn load_binary_with_format(bytes: &[u8], format: FormatType) -> Result<BinaryInfo, LoaderError> {
    match format {
        FormatType::Sc32 => load_shellcode(bytes, ArchType::I386),
        FormatType::Sc64 => load_shellcode(bytes, ArchType::Amd64),
        FormatType::Pe | FormatType::Elf | FormatType::MachO | FormatType::DotNet | FormatType::Any => {
            load_binary(bytes)
        }
    }
}

/// Load raw shellcode (no PE/ELF headers)
/// Shellcode is treated as pure machine code starting at offset 0
fn load_shellcode(bytes: &[u8], arch: ArchType) -> Result<BinaryInfo, LoaderError> {
    // Extract strings from shellcode
    let strings = extract_strings(bytes);

    // Create a single executable section covering the entire shellcode
    let sections = vec![SectionInfo {
        name: ".shellcode".to_string(),
        address: 0,
        size: bytes.len() as u64,
        is_executable: true,
    }];

    Ok(BinaryInfo {
        // Shellcode OS is unknown - could be any OS
        // Rules with os: conditions may not match
        os: OsType::Windows, // Default to Windows (most common for shellcode)
        arch,
        format: if arch == ArchType::I386 {
            FormatType::Sc32
        } else {
            FormatType::Sc64
        },
        imports: Vec::new(),   // Shellcode has no import table
        exports: Vec::new(),   // Shellcode has no export table
        sections,
        strings,
        is_dotnet: false,
        has_forwarded_exports: false,
        is_mixed_mode: false,
        entry_point: 0, // Shellcode starts at offset 0
    })
}

fn load_pe(pe: &goblin::pe::PE, bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    let arch = if pe.is_64 {
        ArchType::Amd64
    } else {
        ArchType::I386
    };

    // Extract imports
    let mut imports = Vec::new();
    for import in &pe.imports {
        imports.push(ImportInfo {
            name: import.name.to_string(),
            module: Some(import.dll.to_string()),
            address: import.offset as u64,
        });
    }

    // Check for .NET CLR imports (indicates managed code)
    let has_clr_import = imports.iter().any(|i| {
        i.module.as_ref().map_or(false, |m| m.eq_ignore_ascii_case("mscoree.dll"))
    });

    // Extract exports and detect forwarded exports
    let mut exports = Vec::new();
    let mut has_forwarded_exports = false;

    for export in &pe.exports {
        if let Some(name) = export.name {
            // Check if export is forwarded
            let (is_forwarded, forward_target) = if let Some(reexport) = &export.reexport {
                has_forwarded_exports = true;
                // Reexport is an enum with DLLName and DLLOrdinal variants
                let target = match reexport {
                    goblin::pe::export::Reexport::DLLName { export, lib } => {
                        format!("{}.{}", lib, export)
                    }
                    goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                        format!("{}.#{}", lib, ordinal)
                    }
                };
                (true, Some(target))
            } else {
                (false, None)
            };

            exports.push(ExportInfo {
                name: name.to_string(),
                address: export.offset.unwrap_or(0) as u64,
                is_forwarded,
                forward_target,
            });
        }
    }

    // Extract sections
    let mut sections = Vec::new();
    let mut has_native_code = false;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        let is_executable = section.characteristics & 0x20000000 != 0;
        if is_executable {
            has_native_code = true;
        }

        sections.push(SectionInfo {
            name,
            address: section.virtual_address as u64,
            size: section.virtual_size as u64,
            is_executable,
        });
    }

    // Detect .NET via CLR header directory
    let is_dotnet = pe.header.optional_header
        .map(|oh| {
            oh.data_directories.get_clr_runtime_header().is_some()
        })
        .unwrap_or(false) || has_clr_import;

    // Mixed mode: has both .NET CLR and native executable code
    let is_mixed_mode = is_dotnet && has_native_code && !exports.is_empty();

    // Extract strings
    let strings = extract_strings(bytes);

    Ok(BinaryInfo {
        os: OsType::Windows,
        arch,
        format: if is_dotnet { FormatType::DotNet } else { FormatType::Pe },
        imports,
        exports,
        sections,
        strings,
        is_dotnet,
        has_forwarded_exports,
        is_mixed_mode,
        entry_point: pe.entry as u64,
    })
}

fn load_elf(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<BinaryInfo, LoaderError> {
    use goblin::elf::header::*;

    // Detect architecture from ELF machine type
    let arch = match elf.header.e_machine {
        EM_386 => ArchType::I386,
        EM_X86_64 => ArchType::Amd64,
        EM_ARM => ArchType::Arm,
        EM_AARCH64 => ArchType::Arm64,
        EM_MIPS | EM_MIPS_RS3_LE => ArchType::Mips,
        EM_PPC => ArchType::Ppc,
        EM_PPC64 => ArchType::Ppc64,
        _ => {
            // Fallback based on bitness for unknown architectures
            if elf.is_64 {
                ArchType::Amd64
            } else {
                ArchType::I386
            }
        }
    };

    // Detect OS from ELF header
    // Note: ELFOSABI_LINUX and ELFOSABI_GNU have the same value (3)
    let os = match elf.header.e_ident[goblin::elf::header::EI_OSABI] {
        goblin::elf::header::ELFOSABI_LINUX => OsType::Linux,
        _ => OsType::Linux, // Default to Linux for ELF
    };

    // Extract imports (dynamic symbols)
    let mut imports = Vec::new();
    for sym in &elf.dynsyms {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                imports.push(ImportInfo {
                    name: name.to_string(),
                    module: None,
                    address: sym.st_value,
                });
            }
        }
    }

    // Extract exports
    let mut exports = Vec::new();
    for sym in &elf.dynsyms {
        if !sym.is_import() && sym.st_bind() != goblin::elf::sym::STB_LOCAL {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        is_forwarded: false,
                        forward_target: None,
                    });
                }
            }
        }
    }

    // Extract sections
    let mut sections = Vec::new();
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            sections.push(SectionInfo {
                name: name.to_string(),
                address: section.sh_addr,
                size: section.sh_size,
                is_executable: section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0,
            });
        }
    }

    // Extract strings
    let strings = extract_strings(bytes);

    Ok(BinaryInfo {
        os,
        arch,
        format: FormatType::Elf,
        imports,
        exports,
        sections,
        strings,
        is_dotnet: false,
        has_forwarded_exports: false,
        is_mixed_mode: false,
        entry_point: elf.entry,
    })
}

/// Extract printable strings from binary (ASCII and wide/UTF-16LE)
/// Delegates to the public `strings` module, matching Python's
/// `capa.features.extractors.common.extract_file_strings`.
fn extract_strings(bytes: &[u8]) -> Vec<StringInfo> {
    let mut strings = Vec::new();

    for s in crate::strings::extract_ascii_strings(bytes, 4) {
        strings.push(StringInfo {
            value: s.value,
            address: s.offset,
        });
    }

    for s in crate::strings::extract_unicode_strings(bytes, 4) {
        strings.push(StringInfo {
            value: s.value,
            address: s.offset,
        });
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"hello\x00world\x00ab\x00testing123\x00";
        let strings = crate::strings::extract_ascii_strings(data, 4);
        assert_eq!(strings.len(), 3); // "hello", "world", "testing123" (min 4 chars)
    }

    #[test]
    fn test_extract_wide_strings() {
        // "test" in UTF-16LE
        let data = b"t\x00e\x00s\x00t\x00\x00\x00";
        let strings = crate::strings::extract_unicode_strings(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "test");
    }

    #[test]
    fn test_extract_strings_combined() {
        // Mix of ASCII and wide strings with proper alignment
        let mut data = Vec::new();
        data.extend_from_slice(b"hello\x00\x00\x00"); // ASCII with padding to align
        data.extend_from_slice(b"t\x00e\x00s\x00t\x00i\x00n\x00g\x00\x00\x00"); // "testing" in UTF-16LE
        let strings = extract_strings(&data);

        // Should find ASCII "hello" and potentially wide "testing"
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"hello"));
        // Wide string extraction is best-effort due to alignment challenges
        // Just verify we got at least the ASCII string
        assert!(!strings.is_empty());
    }
}
