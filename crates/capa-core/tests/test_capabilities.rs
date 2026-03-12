// Port of capa/tests/test_capabilities.py and test_main.py concepts
//
// Tests cross-scope matching, subscope matching, byte matching,
// instruction scope, multiple scopes, namespace matching,
// ATT&CK metadata, lib rules, and match result fields.

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::matcher::MatchEngine;
use capa_core::output::CapaOutput;
use capa_core::rule::parse_rule;
use capa_core::rule::{ArchType, CharacteristicType, FormatType, OsType};

const ADDR1: Address = Address(0x401000);
const ADDR2: Address = Address(0x402000);
const ADDR3: Address = Address(0x403000);

// ---------- test_match_across_scopes_file_and_function ----------

#[test]
fn test_match_across_scopes_file_and_function() {
    let yaml = r#"
rule:
    meta:
        name: cross-scope rule
        scopes:
            static: file
    features:
        - and:
            - import: kernel32.CreateFileA
            - function:
                - api: WriteFile
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.imports.insert("kernel32.CreateFileA".to_string());
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("WriteFile".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert!(!matches.is_empty(), "Should match across file and function scopes");
    assert_eq!(matches[0].name, "cross-scope rule");
}

// ---------- test_byte_matching ----------

#[test]
fn test_byte_matching() {
    let yaml = r#"
rule:
    meta:
        name: byte match rule
        scopes:
            static: function
    features:
        - bytes: 4D 5A 90 00
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.bytes_sequences.push(vec![0x4D, 0x5A, 0x90, 0x00]);
    features.functions.insert(ADDR1, func);

    assert!(!engine.match_all_sequential(&features).is_empty());
}

#[test]
fn test_byte_no_match() {
    let yaml = r#"
rule:
    meta:
        name: byte match rule
        scopes:
            static: function
    features:
        - bytes: 4D 5A 90 00
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.bytes_sequences.push(vec![0x00, 0x00, 0x00, 0x00]);
    features.functions.insert(ADDR1, func);

    assert!(engine.match_all_sequential(&features).is_empty());
}

// ---------- test_count_basic_blocks ----------

#[test]
fn test_count_basic_blocks_match() {
    let yaml = r#"
rule:
    meta:
        name: bb count rule
        scopes:
            static: function
    features:
        - count(basic block): 3 or more
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.basic_block_count = 5;
    features.functions.insert(ADDR1, func);

    assert!(!engine.match_all_sequential(&features).is_empty());
}

#[test]
fn test_count_basic_blocks_no_match() {
    let yaml = r#"
rule:
    meta:
        name: bb count rule
        scopes:
            static: function
    features:
        - count(basic block): 3 or more
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.basic_block_count = 2;
    features.functions.insert(ADDR1, func);

    assert!(engine.match_all_sequential(&features).is_empty());
}

// ---------- test_instruction_scope_features ----------

#[test]
fn test_instruction_scope_features() {
    let yaml = r#"
rule:
    meta:
        name: insn scope rule
        scopes:
            static: instruction
    features:
        - and:
            - mnemonic: push
            - number: 0x80000000
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    let mut insn = FeatureSet::new();
    insn.mnemonics.insert("push".to_string(), 1);
    insn.numbers.insert(0x80000000u32 as i64);
    func.instructions.insert(Address(0x401010), insn);
    features.functions.insert(ADDR1, func);

    assert!(!engine.match_all_sequential(&features).is_empty());
}

// ---------- test_instruction_subscope ----------

#[test]
fn test_instruction_subscope() {
    let yaml = r#"
rule:
    meta:
        name: func with insn subscope
        scopes:
            static: function
    features:
        - and:
            - api: CreateFileA
            - instruction:
                - and:
                    - mnemonic: push
                    - number: 5
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("CreateFileA".to_string());
    let mut insn = FeatureSet::new();
    insn.mnemonics.insert("push".to_string(), 1);
    insn.numbers.insert(5);
    func.instructions.insert(Address(0x401010), insn);
    features.functions.insert(ADDR1, func);

    assert!(!engine.match_all_sequential(&features).is_empty());
}

// ---------- test_multiple_scope_rules ----------

#[test]
fn test_multiple_scope_rules() {
    let yaml_file = r#"
rule:
    meta:
        name: file scope rule
        scopes:
            static: file
    features:
        - import: kernel32.WriteFile
"#;
    let yaml_func = r#"
rule:
    meta:
        name: func scope rule
        scopes:
            static: function
    features:
        - api: CreateFileA
"#;
    let r1 = parse_rule(yaml_file).unwrap();
    let r2 = parse_rule(yaml_func).unwrap();
    let engine = MatchEngine::new(vec![r1, r2]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.imports.insert("kernel32.WriteFile".to_string());
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("CreateFileA".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 2);
    let names: Vec<&str> = matches.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"file scope rule"));
    assert!(names.contains(&"func scope rule"));
}

// ---------- test_match_with_namespace ----------

#[test]
fn test_match_with_namespace() {
    let yaml = r#"
rule:
    meta:
        name: namespace rule
        namespace: anti-analysis/anti-debugging
        scopes:
            static: function
    features:
        - api: IsDebuggerPresent
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("IsDebuggerPresent".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].namespace, Some("anti-analysis/anti-debugging".to_string()));
}

// ---------- test_match_with_attack_metadata ----------

#[test]
fn test_match_with_attack_metadata() {
    let yaml = r#"
rule:
    meta:
        name: attack rule
        scopes:
            static: function
        att&ck:
            - "Defense Evasion::Obfuscated Files or Information [T1027]"
    features:
        - api: VirtualAlloc
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("VirtualAlloc".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 1);
    assert!(!matches[0].attack.is_empty());
}

// ---------- test_match_lib_rule ----------

#[test]
fn test_lib_rule_filtered_from_output() {
    let yaml = r#"
rule:
    meta:
        name: lib helper
        scopes:
            static: function
        lib: true
    features:
        - api: VirtualAlloc
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("VirtualAlloc".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert!(!matches.is_empty(), "lib rule should still match");
    assert!(matches[0].is_lib);

    let output = CapaOutput::from_matches(matches, 1);
    assert_eq!(output.matched_rules, 0, "lib rules filtered from output");
    assert!(output.capabilities.is_empty());
}

// ---------- test_no_match ----------

#[test]
fn test_no_match_returns_empty() {
    let yaml = r#"
rule:
    meta:
        name: no match
        scopes:
            static: function
    features:
        - api: NonExistentAPI
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    assert!(engine.match_all_sequential(&features).is_empty());
}

// ---------- test_multiple_functions_matching ----------

#[test]
fn test_multiple_functions_matching() {
    let yaml = r#"
rule:
    meta:
        name: api rule
        scopes:
            static: function
    features:
        - api: CreateFile
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);

    // Function 1: has CreateFile
    let mut func1 = FunctionFeatures::new(ADDR1);
    func1.features.apis.insert("CreateFile".to_string());
    features.functions.insert(ADDR1, func1);

    // Function 2: does NOT have CreateFile
    let mut func2 = FunctionFeatures::new(ADDR2);
    func2.features.apis.insert("WriteFile".to_string());
    features.functions.insert(ADDR2, func2);

    // Function 3: has CreateFile
    let mut func3 = FunctionFeatures::new(ADDR3);
    func3.features.apis.insert("CreateFile".to_string());
    features.functions.insert(ADDR3, func3);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 1, "Rule should match once (deduplicated)");
}

// ---------- test_file_scope_imports_exports ----------

#[test]
fn test_file_scope_imports() {
    let yaml = r#"
rule:
    meta:
        name: import rule
        scopes:
            static: file
    features:
        - and:
            - import: kernel32.CreateFileA
            - import: kernel32.WriteFile
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.imports.insert("kernel32.CreateFileA".to_string());
    features.file.imports.insert("kernel32.WriteFile".to_string());

    assert!(!engine.match_all_sequential(&features).is_empty());
}

#[test]
fn test_file_scope_exports() {
    let yaml = r#"
rule:
    meta:
        name: export rule
        scopes:
            static: file
    features:
        - export: DllRegisterServer
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.exports.insert("DllRegisterServer".to_string());

    assert!(!engine.match_all_sequential(&features).is_empty());
}

// ---------- test_match_result_fields ----------

#[test]
fn test_match_result_fields() {
    let yaml = r#"
rule:
    meta:
        name: full result rule
        namespace: test/full
        scopes:
            static: function
        att&ck:
            - "Execution::Command [T1059]"
        mbc:
            - "Anti-Behavioral Analysis::Debugger Detection [B0001]"
    features:
        - api: TestAPI
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("TestAPI".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.name, "full result rule");
    assert_eq!(m.namespace, Some("test/full".to_string()));
    assert!(!m.attack.is_empty());
    assert!(!m.mbc.is_empty());
    assert!(!m.is_lib);
}

// ---------- test_characteristic_matching ----------

#[test]
fn test_characteristic_nzxor_in_function() {
    let yaml = r#"
rule:
    meta:
        name: nzxor rule
        scopes:
            static: function
    features:
        - characteristic: nzxor
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.characteristics.insert(CharacteristicType::Nzxor);
    features.functions.insert(ADDR1, func);

    assert!(!engine.match_all_sequential(&features).is_empty());
}

#[test]
fn test_characteristic_embedded_pe_file_scope() {
    let yaml = r#"
rule:
    meta:
        name: embedded pe rule
        scopes:
            static: file
    features:
        - characteristic: embedded pe
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features.file.characteristics.insert(CharacteristicType::EmbeddedPe);

    assert!(!engine.match_all_sequential(&features).is_empty());
}
