// Port of capa/tests/test_rules.py
//
// Tests rule YAML parsing, validation, feature types, scopes,
// count operators, number/offset symbols, and error handling.

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::matcher::MatchEngine;
use capa_core::rule::parse_rule;
use capa_core::rule::{ArchType, FormatType, OsType};

const ADDR1: Address = Address(0x401001);

/// Helper: create ExtractedFeatures with a single function at ADDR1
fn make_features(func_features: FeatureSet) -> ExtractedFeatures {
    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features = func_features;
    features.functions.insert(ADDR1, func);
    features
}

/// Helper: check if a rule matches
fn matches_rule(yaml: &str, func_features: FeatureSet) -> bool {
    let rule = parse_rule(yaml).expect("failed to parse rule");
    let engine = MatchEngine::new(vec![rule]);
    let features = make_features(func_features);
    !engine.match_all_sequential(&features).is_empty()
}

// ---------- test_rule_yaml (port of test_rules.py::test_rule_yaml) ----------

#[test]
fn test_rule_yaml_basic_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        authors:
            - user@domain.com
        scopes:
            static: function
            dynamic: process
        examples:
            - foo1234
            - bar5678
    features:
        - and:
            - number: 1
            - number: 2
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
    assert_eq!(rule.meta.authors, vec!["user@domain.com".to_string()]);
}

#[test]
fn test_rule_yaml_and_evaluation() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - number: 1
            - number: 2
"#;
    // neither present
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));

    // only one present
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(1);
    assert!(!matches_rule(yaml, fs));

    // both present
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));

    // both present plus extras
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    fs.numbers.insert(3);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_rule_yaml_complex ----------

#[test]
fn test_rule_yaml_complex() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - or:
            - and:
                - number: 1
                - number: 2
            - or:
                - number: 3
                - 2 or more:
                    - number: 4
                    - number: 5
                    - number: 6
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(5);
    fs.numbers.insert(6);
    fs.numbers.insert(7);
    fs.numbers.insert(8);
    assert!(matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(6);
    fs2.numbers.insert(7);
    fs2.numbers.insert(8);
    assert!(!matches_rule(yaml, fs2));
}

// ---------- test_rule_yaml_not ----------

#[test]
fn test_rule_yaml_not() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - number: 1
            - not:
                - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(1);
    fs2.numbers.insert(2);
    assert!(!matches_rule(yaml, fs2));
}

// ---------- test_rule_yaml_count ----------

#[test]
fn test_rule_yaml_count() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(number(100)): 1
"#;
    let fs = FeatureSet::new();
    assert!(!matches_rule(yaml, fs));

    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_rule_yaml_count_range ----------

#[test]
fn test_rule_yaml_count_range() {
    // count(number(100)): (1, 2)
    // In the Rust engine, count(number(X)) returns 0 or 1 since numbers is a HashSet
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(number(100)): (0, 1)
"#;
    // not present → count 0 → in range (0,1)
    let fs = FeatureSet::new();
    assert!(matches_rule(yaml, fs));

    // present → count 1 → in range (0,1)
    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(100);
    assert!(matches_rule(yaml, fs2));
}

// ---------- test_rule_yaml_count_string ----------

#[test]
fn test_rule_yaml_count_string() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(string(foo)): 1
"#;
    let fs = FeatureSet::new();
    assert!(!matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.strings.insert("foo".to_string());
    assert!(matches_rule(yaml, fs2));
}

// ---------- test_invalid_rule_feature ----------

#[test]
fn test_invalid_rule_feature_unknown() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - foo: true
"#;
    assert!(parse_rule(yaml).is_err());
}

// ---------- test_rule_yaml_api ----------

#[test]
fn test_rule_yaml_api() {
    let yaml = r#"
rule:
    meta:
        name: test api
        scopes:
            static: function
    features:
        - api: CreateFileA
"#;
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    assert!(matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.apis.insert("WriteFile".to_string());
    assert!(!matches_rule(yaml, fs2));
}

// ---------- test_number_symbol (port of test_rules.py::test_number_symbol) ----------

#[test]
fn test_number_plain() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - number: 1
            - number: 0xFFFFFFFF
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

#[test]
fn test_number_with_description() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - number: 2 = symbol name
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");

    // Should match when number 2 is present
    let mut fs = FeatureSet::new();
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_number_hex_with_description() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - number: 0x100 = symbol name
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0x100);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_number_hex_flags() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - number: 0x11 = (FLAG_A | FLAG_B)
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0x11);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_count_number_symbol ----------

#[test]
fn test_count_number_symbol() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(number(2 = symbol name)): 1
"#;
    let fs = FeatureSet::new();
    assert!(!matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(2);
    assert!(matches_rule(yaml, fs2));
}

// ---------- test_count_api ----------

#[test]
fn test_count_api() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - or:
            - count(api(CreateFileA)): 1
"#;
    let fs = FeatureSet::new();
    assert!(!matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.apis.insert("CreateFileA".to_string());
    assert!(matches_rule(yaml, fs2));
}

// ---------- test_offset_symbol ----------

#[test]
fn test_offset_plain() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - offset: 1
"#;
    let mut fs = FeatureSet::new();
    fs.offsets.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_offset_with_description() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - offset: 0x100 = symbol name
"#;
    let mut fs = FeatureSet::new();
    fs.offsets.insert(0x100);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_invalid_number ----------

#[test]
fn test_invalid_number_string_value() {
    // "this is a string" is not a valid number
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - number: "this is a string"
"#;
    assert!(parse_rule(yaml).is_err());
}

// ---------- test_empty_yaml_raises ----------

#[test]
fn test_empty_yaml() {
    assert!(parse_rule("").is_err());
    assert!(parse_rule("   \n  \n").is_err());
}

// ---------- Scope and format tests ----------

#[test]
fn test_rule_file_scope() {
    let yaml = r#"
rule:
    meta:
        name: test file scope
        scopes:
            static: file
    features:
        - import: kernel32.CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test file scope");
}

#[test]
fn test_rule_instruction_scope() {
    let yaml = r#"
rule:
    meta:
        name: test insn scope
        scopes:
            static: instruction
    features:
        - mnemonic: mov
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test insn scope");
}

#[test]
fn test_rule_basic_block_scope() {
    let yaml = r#"
rule:
    meta:
        name: test bb scope
        scopes:
            static: basic block
    features:
        - characteristic: tight loop
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test bb scope");
}

// ---------- Feature type parsing tests ----------

#[test]
fn test_parse_string_feature() {
    let yaml = r#"
rule:
    meta:
        name: test string
        scopes:
            static: function
    features:
        - string: Hello World
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("Hello World".to_string());
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_parse_substring_feature() {
    let yaml = r#"
rule:
    meta:
        name: test substring
        scopes:
            static: function
    features:
        - substring: abc
"#;
    // exact match
    let mut fs = FeatureSet::new();
    fs.strings.insert("abc".to_string());
    assert!(matches_rule(yaml, fs));

    // substring in middle
    let mut fs2 = FeatureSet::new();
    fs2.strings.insert("111abc222".to_string());
    assert!(matches_rule(yaml, fs2));

    // not present
    let mut fs3 = FeatureSet::new();
    fs3.strings.insert("aaaa".to_string());
    assert!(!matches_rule(yaml, fs3));
}

#[test]
fn test_parse_regex_feature() {
    let yaml = r#"
rule:
    meta:
        name: test regex
        scopes:
            static: function
    features:
        - string: /password/i
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test regex");
}

#[test]
fn test_parse_bytes_feature() {
    let yaml = r#"
rule:
    meta:
        name: test bytes
        scopes:
            static: function
    features:
        - bytes: 4D 5A 90 00
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test bytes");
}

#[test]
fn test_parse_mnemonic_feature() {
    let yaml = r#"
rule:
    meta:
        name: test mnemonic
        scopes:
            static: function
    features:
        - mnemonic: mov
"#;
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("mov".to_string(), 1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_parse_characteristic_feature() {
    let yaml = r#"
rule:
    meta:
        name: test characteristic
        scopes:
            static: function
    features:
        - characteristic: nzxor
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test characteristic");
}

#[test]
fn test_parse_section_feature() {
    let yaml = r#"
rule:
    meta:
        name: test section
        scopes:
            static: file
    features:
        - section: .text
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test section");
}

#[test]
fn test_parse_import_feature() {
    let yaml = r#"
rule:
    meta:
        name: test import
        scopes:
            static: file
    features:
        - import: kernel32.CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test import");
}

#[test]
fn test_parse_export_feature() {
    let yaml = r#"
rule:
    meta:
        name: test export
        scopes:
            static: file
    features:
        - export: DllRegisterServer
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test export");
}

// ---------- OS / Arch / Format features ----------

#[test]
fn test_parse_os_feature() {
    let yaml = r#"
rule:
    meta:
        name: test os
        scopes:
            static: file
    features:
        - os: windows
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test os");
}

#[test]
fn test_parse_arch_feature() {
    let yaml = r#"
rule:
    meta:
        name: test arch
        scopes:
            static: file
    features:
        - arch: amd64
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test arch");
}

#[test]
fn test_parse_format_feature() {
    let yaml = r#"
rule:
    meta:
        name: test format
        scopes:
            static: file
    features:
        - format: pe
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test format");
}

// ---------- Operand features ----------

#[test]
fn test_parse_operand_number() {
    let yaml = r#"
rule:
    meta:
        name: test operand
        scopes:
            static: function
    features:
        - operand[0].number: 0x10
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test operand");
}

#[test]
fn test_parse_operand_offset() {
    let yaml = r#"
rule:
    meta:
        name: test operand offset
        scopes:
            static: function
    features:
        - operand[1].offset: 0x20
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test operand offset");
}

// ---------- Property features ----------

#[test]
fn test_parse_property_read() {
    let yaml = r#"
rule:
    meta:
        name: test property
        scopes:
            static: function
    features:
        - property/read: System.IO.FileInfo::Length
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test property");
}

#[test]
fn test_parse_property_write() {
    let yaml = r#"
rule:
    meta:
        name: test property write
        scopes:
            static: function
    features:
        - property/write: System.IO.FileInfo::Length
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test property write");
}

// ---------- Subscope tests ----------

#[test]
fn test_parse_function_subscope() {
    let yaml = r#"
rule:
    meta:
        name: test function subscope
        scopes:
            static: file
    features:
        - and:
            - characteristic: embedded pe
            - function:
                - and:
                    - characteristic: nzxor
                    - characteristic: loop
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test function subscope");
}

#[test]
fn test_parse_instruction_subscope() {
    let yaml = r#"
rule:
    meta:
        name: test instruction subscope
        scopes:
            static: function
    features:
        - and:
            - api: CreateFileA
            - instruction:
                - and:
                    - mnemonic: push
                    - number: 0x80000000
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test instruction subscope");
}

#[test]
fn test_parse_basic_block_subscope() {
    let yaml = r#"
rule:
    meta:
        name: test basic block subscope
        scopes:
            static: function
    features:
        - and:
            - api: CreateFileA
            - basic block:
                - and:
                    - mnemonic: push
                    - number: 5
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test basic block subscope");
}

// ---------- Match operator ----------

#[test]
fn test_parse_match_rule() {
    let yaml = r#"
rule:
    meta:
        name: test match
        scopes:
            static: function
    features:
        - match: some other rule
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test match");
}

// ---------- Meta fields ----------

#[test]
fn test_rule_meta_attack() {
    let yaml = r#"
rule:
    meta:
        name: test attack
        scopes:
            static: function
        att&ck:
            - "Defense Evasion::Obfuscated Files or Information [T1027]"
    features:
        - api: CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.attack.len(), 1);
}

#[test]
fn test_rule_meta_mbc() {
    let yaml = r#"
rule:
    meta:
        name: test mbc
        scopes:
            static: function
        mbc:
            - "Anti-Behavioral Analysis::Debugger Detection [B0001]"
    features:
        - api: IsDebuggerPresent
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.mbc.len(), 1);
}

#[test]
fn test_rule_meta_namespace() {
    let yaml = r#"
rule:
    meta:
        name: test namespace
        namespace: anti-analysis/anti-debugging
        scopes:
            static: function
    features:
        - api: IsDebuggerPresent
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(
        rule.meta.namespace,
        Some("anti-analysis/anti-debugging".to_string())
    );
}

#[test]
fn test_rule_meta_lib() {
    let yaml = r#"
rule:
    meta:
        name: test lib
        scopes:
            static: function
        lib: true
    features:
        - api: CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    assert!(rule.meta.is_lib);
}

// ---------- COM features ----------

#[test]
fn test_parse_com_interface() {
    let yaml = r#"
rule:
    meta:
        name: test com
        scopes:
            static: function
    features:
        - com/interface: IUnknown
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test com");
}

// ---------- .NET features ----------

#[test]
fn test_parse_namespace_feature() {
    let yaml = r#"
rule:
    meta:
        name: test namespace feature
        scopes:
            static: function
    features:
        - namespace: System.IO
"#;
    let mut fs = FeatureSet::new();
    fs.namespaces.insert("System.IO".to_string());
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_parse_class_feature() {
    let yaml = r#"
rule:
    meta:
        name: test class
        scopes:
            static: function
    features:
        - class: System.IO.File
"#;
    let mut fs = FeatureSet::new();
    fs.classes.insert("System.IO.File".to_string());
    assert!(matches_rule(yaml, fs));
}

// ---------- Description in features ----------

#[test]
fn test_feature_with_description() {
    let yaml = r#"
rule:
    meta:
        name: test description
        scopes:
            static: function
    features:
        - and:
            - number: 0x40 = PAGE_EXECUTE_READWRITE
              description: memory protection constant
            - api: VirtualAlloc
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0x40);
    fs.apis.insert("VirtualAlloc".to_string());
    assert!(matches_rule(yaml, fs));
}

// ---------- Bytes with description ----------

#[test]
fn test_bytes_with_description() {
    let yaml = r#"
rule:
    meta:
        name: test bytes desc
        scopes:
            static: function
    features:
        - bytes: 00 00 00 00 96 30 07 77 = crc32_tab
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test bytes desc");
}

// ---------- Multiple rules ----------

#[test]
fn test_multiple_rules_matching() {
    let yaml1 = r#"
rule:
    meta:
        name: rule one
        scopes:
            static: function
    features:
        - api: CreateFileA
"#;
    let yaml2 = r#"
rule:
    meta:
        name: rule two
        scopes:
            static: function
    features:
        - api: WriteFile
"#;
    let rule1 = parse_rule(yaml1).unwrap();
    let rule2 = parse_rule(yaml2).unwrap();
    let engine = MatchEngine::new(vec![rule1, rule2]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("CreateFileA".to_string());
    func.features.apis.insert("WriteFile".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 2);

    let names: Vec<&str> = matches.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"rule one"));
    assert!(names.contains(&"rule two"));
}

#[test]
fn test_rule_count() {
    let yaml1 = r#"
rule:
    meta:
        name: rule one
        scopes:
            static: function
    features:
        - api: CreateFileA
"#;
    let yaml2 = r#"
rule:
    meta:
        name: rule two
        scopes:
            static: function
    features:
        - api: WriteFile
"#;
    let rule1 = parse_rule(yaml1).unwrap();
    let rule2 = parse_rule(yaml2).unwrap();
    let engine = MatchEngine::new(vec![rule1, rule2]);
    assert_eq!(engine.rule_count(), 2);
}

// ---------- Multi-scope rule tests ----------

#[test]
fn test_multi_scope_rule_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - or:
            - api: write
            - and:
                - os: linux
                - mnemonic: syscall
                - number: 1 = write
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

// ---------- Optional features ----------

#[test]
fn test_optional_always_matches() {
    let yaml = r#"
rule:
    meta:
        name: test optional
        scopes:
            static: function
    features:
        - and:
            - api: CreateFileA
            - optional:
                - api: CloseHandle
"#;
    // Should match even without CloseHandle because optional always succeeds
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    assert!(matches_rule(yaml, fs));
}

// ---------- Characteristic matching ----------

#[test]
fn test_characteristic_nzxor() {
    let yaml = r#"
rule:
    meta:
        name: test nzxor
        scopes:
            static: function
    features:
        - characteristic: nzxor
"#;
    let mut fs = FeatureSet::new();
    fs.characteristics
        .insert(capa_core::rule::CharacteristicType::Nzxor);
    assert!(matches_rule(yaml, fs));

    let fs2 = FeatureSet::new();
    assert!(!matches_rule(yaml, fs2));
}

#[test]
fn test_characteristic_loop() {
    let yaml = r#"
rule:
    meta:
        name: test loop
        scopes:
            static: function
    features:
        - characteristic: loop
"#;
    let mut fs = FeatureSet::new();
    fs.characteristics
        .insert(capa_core::rule::CharacteristicType::Loop);
    assert!(matches_rule(yaml, fs));
}

// ---------- Count basic block ----------

#[test]
fn test_count_basic_block() {
    let yaml = r#"
rule:
    meta:
        name: test bb count
        scopes:
            static: function
    features:
        - count(basic block): 3 or more
"#;
    let mut fs = FeatureSet::new();
    fs.basic_block_count = 5;
    assert!(matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.basic_block_count = 2;
    assert!(!matches_rule(yaml, fs2));
}
