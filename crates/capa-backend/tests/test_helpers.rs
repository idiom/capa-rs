// Port of capa/tests/test_helpers.py

use capa_backend::helpers::{all_zeros, generate_symbols};

// ---------- test_all_zeros ----------

#[test]
fn test_all_zeros_true() {
    assert!(all_zeros(&[0x00, 0x00, 0x00, 0x00]));
}

#[test]
fn test_all_zeros_from_hex() {
    assert!(all_zeros(&[0x00, 0x00, 0x00, 0x00]));
}

#[test]
fn test_not_all_zeros() {
    assert!(!all_zeros(&[0x01, 0x00, 0x00, 0x00]));
}

#[test]
fn test_not_all_zeros_from_hex() {
    assert!(!all_zeros(&[0x01, 0x00, 0x00, 0x00]));
}

// ---------- test_generate_symbols ----------

#[test]
fn test_generate_symbols_dll_extension_stripped() {
    let a = generate_symbols("name.dll", "api", true);
    let b = generate_symbols("name", "api", true);
    assert_eq!(a, b);

    let c = generate_symbols("name.dll", "api", false);
    let d = generate_symbols("name", "api", false);
    assert_eq!(c, d);
}

#[test]
fn test_generate_symbols_aw_import_with_dll() {
    let symbols = generate_symbols("kernel32", "CreateFileA", true);
    assert_eq!(symbols.len(), 4);
    assert!(symbols.contains(&"kernel32.CreateFileA".to_string()));
    assert!(symbols.contains(&"kernel32.CreateFile".to_string()));
    assert!(symbols.contains(&"CreateFileA".to_string()));
    assert!(symbols.contains(&"CreateFile".to_string()));
}

#[test]
fn test_generate_symbols_regular_import_with_dll() {
    let symbols = generate_symbols("kernel32", "WriteFile", true);
    assert_eq!(symbols.len(), 2);
    assert!(symbols.contains(&"kernel32.WriteFile".to_string()));
    assert!(symbols.contains(&"WriteFile".to_string()));
}

#[test]
fn test_generate_symbols_ordinal_import_with_dll() {
    let symbols = generate_symbols("ws2_32", "#1", true);
    assert_eq!(symbols.len(), 1);
    assert!(symbols.contains(&"ws2_32.#1".to_string()));
}

#[test]
fn test_generate_symbols_aw_api_without_dll() {
    let symbols = generate_symbols("kernel32", "CreateFileA", false);
    assert_eq!(symbols.len(), 2);
    assert!(symbols.contains(&"CreateFileA".to_string()));
    assert!(symbols.contains(&"CreateFile".to_string()));
}

#[test]
fn test_generate_symbols_regular_api_without_dll() {
    let symbols = generate_symbols("kernel32", "WriteFile", false);
    assert_eq!(symbols.len(), 1);
    assert!(symbols.contains(&"WriteFile".to_string()));
}

#[test]
fn test_generate_symbols_ordinal_api_without_dll() {
    let symbols = generate_symbols("ws2_32", "#1", false);
    assert_eq!(symbols.len(), 1);
    assert!(symbols.contains(&"ws2_32.#1".to_string()));
}
