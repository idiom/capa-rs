// Port of concepts from:
// - capa/tests/test_freeze_static.py (serialization round-trips)
// - capa/tests/test_freeze_dynamic.py (serialization round-trips)
// - capa/tests/test_result_document.py (output round-trip)

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::rule::{ArchType, CharacteristicType, FormatType, OsType, PropertyAccess};

// ---------- FeatureSet round-trip ----------

#[test]
fn test_feature_set_json_roundtrip() {
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    fs.apis.insert("WriteFile".to_string());
    fs.strings.insert("password".to_string());
    fs.numbers.insert(42);
    fs.numbers.insert(-1);
    fs.numbers.insert(0x80000000u32 as i64);
    fs.offsets.insert(0x100);
    fs.mnemonics.insert("push".to_string(), 5);
    fs.mnemonics.insert("mov".to_string(), 10);
    fs.imports.insert("kernel32.CreateFileA".to_string());
    fs.exports.insert("DllMain".to_string());
    fs.sections.insert(".text".to_string());
    fs.namespaces.insert("System.IO".to_string());
    fs.classes.insert("System.IO.File".to_string());
    fs.characteristics.insert(CharacteristicType::Nzxor);
    fs.characteristics.insert(CharacteristicType::Loop);
    fs.bytes_sequences.push(vec![0x4D, 0x5A, 0x90, 0x00]);
    fs.operands.push((0, Some(0x10), None));
    fs.operands.push((1, None, Some(0x20)));
    fs.properties.push(("Prop::Length".to_string(), PropertyAccess::Read));
    fs.basic_block_count = 7;

    let json = serde_json::to_string(&fs).unwrap();
    let restored: FeatureSet = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.apis, fs.apis);
    assert_eq!(restored.strings, fs.strings);
    assert_eq!(restored.numbers, fs.numbers);
    assert_eq!(restored.offsets, fs.offsets);
    assert_eq!(restored.mnemonics, fs.mnemonics);
    assert_eq!(restored.imports, fs.imports);
    assert_eq!(restored.exports, fs.exports);
    assert_eq!(restored.sections, fs.sections);
    assert_eq!(restored.namespaces, fs.namespaces);
    assert_eq!(restored.classes, fs.classes);
    assert_eq!(restored.characteristics, fs.characteristics);
    assert_eq!(restored.bytes_sequences, fs.bytes_sequences);
    assert_eq!(restored.operands, fs.operands);
    assert_eq!(restored.properties, fs.properties);
    assert_eq!(restored.basic_block_count, fs.basic_block_count);
}

// ---------- FunctionFeatures round-trip ----------

#[test]
fn test_function_features_json_roundtrip() {
    let mut func = FunctionFeatures::new(Address(0x401000));
    func.name = Some("test_func".to_string());
    func.features.apis.insert("CreateFile".to_string());
    func.features.mnemonics.insert("push".to_string(), 3);

    let mut bb = FeatureSet::new();
    bb.characteristics.insert(CharacteristicType::TightLoop);
    func.basic_blocks.insert(0, bb);

    let mut insn = FeatureSet::new();
    insn.mnemonics.insert("mov".to_string(), 1);
    insn.numbers.insert(5);
    func.instructions.insert(Address(0x401010), insn);

    let json = serde_json::to_string(&func).unwrap();
    let restored: FunctionFeatures = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.address, func.address);
    assert_eq!(restored.name, func.name);
    assert_eq!(restored.features.apis, func.features.apis);
    assert_eq!(restored.basic_blocks.len(), 1);
    assert_eq!(restored.instructions.len(), 1);
}

// ---------- ExtractedFeatures round-trip ----------

#[test]
fn test_extracted_features_json_roundtrip() {
    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.imports.insert("kernel32.WriteFile".to_string());
    features.file.sections.insert(".text".to_string());

    let mut func = FunctionFeatures::new(Address(0x401000));
    func.features.apis.insert("TestAPI".to_string());
    features.functions.insert(Address(0x401000), func);

    let json = serde_json::to_string(&features).unwrap();
    let restored: ExtractedFeatures = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.os, features.os);
    assert_eq!(restored.arch, features.arch);
    assert_eq!(restored.format, features.format);
    assert_eq!(restored.file.imports, features.file.imports);
    assert_eq!(restored.functions.len(), features.functions.len());
}

#[test]
fn test_extracted_features_multiple_functions_roundtrip() {
    let mut features = ExtractedFeatures::new(OsType::Linux, ArchType::Amd64, FormatType::Elf);

    for addr in [0x401000u64, 0x402000, 0x403000] {
        let mut func = FunctionFeatures::new(Address(addr));
        func.features.apis.insert(format!("api_{:x}", addr));
        features.functions.insert(Address(addr), func);
    }

    let json = serde_json::to_string(&features).unwrap();
    let restored: ExtractedFeatures = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.functions.len(), 3);
}

// ---------- Address round-trip ----------

#[test]
fn test_address_json_roundtrip() {
    for addr in [0u64, 1, 0x401000, 0xFFFFFFFF, u64::MAX] {
        let a = Address(addr);
        let json = serde_json::to_string(&a).unwrap();
        let restored: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }
}

// ---------- Empty features round-trip ----------

#[test]
fn test_empty_features_roundtrip() {
    let features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let json = serde_json::to_string(&features).unwrap();
    let restored: ExtractedFeatures = serde_json::from_str(&json).unwrap();
    assert!(restored.functions.is_empty());
    assert!(restored.file.apis.is_empty());
}

// ---------- Individual feature type round-trips ----------

#[test]
fn test_serialize_api_feature() {
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert!(r.apis.contains("CreateFileA"));
}

#[test]
fn test_serialize_string_feature() {
    let mut fs = FeatureSet::new();
    fs.strings.insert("hello world".to_string());
    fs.strings.insert("special chars: \t\n".to_string());
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.strings.len(), 2);
}

#[test]
fn test_serialize_number_feature() {
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(-1);
    fs.numbers.insert(0xFF);
    fs.numbers.insert(0x7FFFFFFFFFFFFFFF);
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.numbers.len(), 4);
}

#[test]
fn test_serialize_mnemonic_feature() {
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("push".to_string(), 42);
    fs.mnemonics.insert("mov".to_string(), 100);
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(*r.mnemonics.get("push").unwrap(), 42);
}

#[test]
fn test_serialize_offset_feature() {
    let mut fs = FeatureSet::new();
    fs.offsets.insert(0x100);
    fs.offsets.insert(-0x10);
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.offsets.len(), 2);
}

#[test]
fn test_serialize_bytes_feature() {
    let mut fs = FeatureSet::new();
    fs.bytes_sequences.push(vec![0x4D, 0x5A]);
    fs.bytes_sequences.push(vec![0x00, 0xFF, 0xAB]);
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.bytes_sequences.len(), 2);
}

#[test]
fn test_serialize_characteristic_feature() {
    let mut fs = FeatureSet::new();
    fs.characteristics.insert(CharacteristicType::Nzxor);
    fs.characteristics.insert(CharacteristicType::Loop);
    fs.characteristics.insert(CharacteristicType::TightLoop);
    fs.characteristics.insert(CharacteristicType::EmbeddedPe);
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.characteristics.len(), 4);
}

#[test]
fn test_serialize_section_feature() {
    let mut fs = FeatureSet::new();
    fs.sections.insert(".text".to_string());
    fs.sections.insert(".data".to_string());
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert!(r.sections.contains(".text"));
}

#[test]
fn test_serialize_import_export_feature() {
    let mut fs = FeatureSet::new();
    fs.imports.insert("kernel32.WriteFile".to_string());
    fs.exports.insert("DllMain".to_string());
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert!(r.imports.contains("kernel32.WriteFile"));
    assert!(r.exports.contains("DllMain"));
}

#[test]
fn test_serialize_operand_feature() {
    let mut fs = FeatureSet::new();
    fs.operands.push((0, Some(0x10), None));
    fs.operands.push((1, None, Some(0x20)));
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.operands.len(), 2);
    assert_eq!(r.operands[0], (0, Some(0x10), None));
}

#[test]
fn test_serialize_property_feature() {
    let mut fs = FeatureSet::new();
    fs.properties.push(("Length".to_string(), PropertyAccess::Read));
    fs.properties.push(("Count".to_string(), PropertyAccess::Write));
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert_eq!(r.properties.len(), 2);
}

#[test]
fn test_serialize_namespace_class_feature() {
    let mut fs = FeatureSet::new();
    fs.namespaces.insert("System.IO".to_string());
    fs.classes.insert("System.IO.File".to_string());
    let json = serde_json::to_string(&fs).unwrap();
    let r: FeatureSet = serde_json::from_str(&json).unwrap();
    assert!(r.namespaces.contains("System.IO"));
    assert!(r.classes.contains("System.IO.File"));
}

// ---------- all_features merge ----------

#[test]
fn test_all_features_merges_scopes() {
    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.imports.insert("file_import".to_string());

    let mut func = FunctionFeatures::new(Address(0x401000));
    func.features.apis.insert("func_api".to_string());

    let mut insn = FeatureSet::new();
    insn.mnemonics.insert("insn_mnem".to_string(), 1);
    func.instructions.insert(Address(0x401010), insn);
    features.functions.insert(Address(0x401000), func);

    let merged = features.all_features();
    assert!(merged.imports.contains("file_import"));
    assert!(merged.apis.contains("func_api"));
    assert!(merged.mnemonics.contains_key("insn_mnem"));
}
