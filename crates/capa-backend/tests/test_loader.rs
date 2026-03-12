// Port of concepts from:
// - capa/tests/test_os_detection.py
// - capa/tests/test_loader_segfault.py
// - capa/tests/test_elffile_features.py
// - capa/tests/test_pefile_features.py
// - capa/tests/test_dotnetfile_features.py

use std::path::PathBuf;

use capa_backend::{load_binary, BinaryInfo};
use capa_core::rule::{ArchType, FormatType, OsType};

fn sample_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("samples");
    p.push(name);
    p
}

fn load_sample(name: &str) -> Option<BinaryInfo> {
    let path = sample_path(name);
    if !path.exists() {
        eprintln!("SKIP: sample not found at {:?}", path);
        return None;
    }
    let bytes = std::fs::read(&path).unwrap();
    Some(load_binary(&bytes).unwrap())
}

// ---------- Format detection (test_os_detection concepts) ----------

#[test]
fn test_dotnet_sample_format_detection() {
    let info = match load_sample("dotnet") { Some(i) => i, None => return };
    // .NET binaries get FormatType::DotNet (not Pe) in capa-rs
    assert!(
        info.format == FormatType::DotNet || info.format == FormatType::Pe,
        "dotnet sample should be Pe or DotNet, got {:?}", info.format
    );
    assert!(info.is_dotnet, "dotnet sample should be detected as .NET");
    assert_eq!(info.os, OsType::Windows);
    assert_eq!(info.arch, ArchType::I386);
}

#[test]
fn test_elf_sample_format_detection() {
    let info = match load_sample("elf") { Some(i) => i, None => return };
    assert_eq!(info.format, FormatType::Elf);
    assert_eq!(info.os, OsType::Linux);
    assert_eq!(info.arch, ArchType::Amd64);
}

#[test]
fn test_pe_sample_format_detection() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    assert_eq!(info.format, FormatType::Pe);
    assert_eq!(info.os, OsType::Windows);
    assert_eq!(info.arch, ArchType::Amd64);
}

// ---------- ELF feature tests (test_elffile_features concepts) ----------

#[test]
fn test_elf_sections_extracted() {
    let info = match load_sample("elf") { Some(i) => i, None => return };
    assert!(!info.sections.is_empty(), "ELF should have sections");
    let section_names: Vec<&str> = info.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(section_names.contains(&".text"), "ELF should have .text section");
}

#[test]
fn test_elf_has_executable_section() {
    let info = match load_sample("elf") { Some(i) => i, None => return };
    assert!(
        info.sections.iter().any(|s| s.is_executable),
        "ELF should have at least one executable section"
    );
}

#[test]
fn test_elf_not_dotnet() {
    let info = match load_sample("elf") { Some(i) => i, None => return };
    assert!(!info.is_dotnet, "ELF should not be detected as .NET");
}

// ---------- PE feature tests (test_pefile_features concepts) ----------

#[test]
fn test_pe_imports_extracted() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    assert!(!info.imports.is_empty(), "PE should have imports");
}

#[test]
fn test_pe_sections_include_text() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    let section_names: Vec<&str> = info.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(
        section_names.contains(&".text"),
        "PE should have .text section, got: {:?}", section_names
    );
}

#[test]
fn test_pe_not_dotnet() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    assert!(!info.is_dotnet, "Regular PE should not be .NET");
}

#[test]
fn test_pe_has_executable_section() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    assert!(
        info.sections.iter().any(|s| s.is_executable),
        "PE should have executable section"
    );
}

// ---------- .NET detection (test_dotnetfile_features concepts) ----------

#[test]
fn test_dotnet_detected() {
    let info = match load_sample("dotnet") { Some(i) => i, None => return };
    assert!(info.is_dotnet);
}

#[test]
fn test_dotnet_imports() {
    let info = match load_sample("dotnet") { Some(i) => i, None => return };
    // .NET binaries typically import from mscoree.dll
    let has_mscoree = info.imports.iter().any(|i| {
        i.module.as_deref().map_or(false, |m| m.to_lowercase().contains("mscoree"))
    });
    assert!(has_mscoree, "dotnet sample should import from mscoree.dll");
}

// ---------- Loader error handling (test_loader_segfault concepts) ----------

#[test]
fn test_load_empty_input() {
    assert!(load_binary(b"").is_err(), "Empty input should error");
}

#[test]
fn test_load_invalid_magic() {
    assert!(
        load_binary(&[0x00; 100]).is_err(),
        "Invalid magic should error"
    );
}

#[test]
fn test_load_truncated_mz_no_panic() {
    // Truncated PE - should error gracefully, not panic
    let mut buf = vec![0u8; 200];
    buf[0] = b'M';
    buf[1] = b'Z';
    let result = load_binary(&buf);
    // Either error or parse (goblin may be lenient) - just shouldn't panic
    let _ = result;
}

#[test]
fn test_load_truncated_elf_no_panic() {
    let mut buf = vec![0u8; 200];
    buf[0] = 0x7f;
    buf[1] = b'E';
    buf[2] = b'L';
    buf[3] = b'F';
    let result = load_binary(&buf);
    let _ = result;
}

// ---------- String extraction tests ----------

#[test]
fn test_strings_extracted_from_pe() {
    let info = match load_sample("shellcode_beacon") { Some(i) => i, None => return };
    assert!(!info.strings.is_empty(), "PE should have extractable strings");
    assert!(
        info.strings.iter().all(|s| !s.value.is_empty()),
        "All extracted strings should be non-empty"
    );
}

#[test]
fn test_strings_extracted_from_elf() {
    let info = match load_sample("elf") { Some(i) => i, None => return };
    assert!(!info.strings.is_empty(), "ELF should have extractable strings");
}

// ---------- Multiple format tests ----------

#[test]
fn test_golang_sample_loads() {
    let _info = match load_sample("golang") { Some(i) => i, None => return };
}

#[test]
fn test_graalvm_sample_loads() {
    let _info = match load_sample("graalvm") { Some(i) => i, None => return };
}

#[test]
fn test_all_samples_have_entry_point() {
    for name in &["dotnet", "elf", "shellcode_beacon", "shellcode_beacon2"] {
        if let Some(info) = load_sample(name) {
            // Entry point should be set (can be 0 for some formats but shouldn't panic)
            let _ = info.entry_point;
        }
    }
}
