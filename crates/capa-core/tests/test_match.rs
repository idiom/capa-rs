// Port of capa/tests/test_match.py
//
// Tests rule matching engine behavior: simple matches, range/count matching,
// namespace matching, string/regex matching, operand matching, property access,
// OS/arch/format features, and NOT operator semantics.

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::matcher::MatchEngine;
use capa_core::rule::parse_rule;
use capa_core::rule::{ArchType, CharacteristicType, FormatType, OsType, PropertyAccess};

const ADDR1: Address = Address(0x401001);

/// Helper: create ExtractedFeatures with a function at ADDR1
fn make_features(func_features: FeatureSet) -> ExtractedFeatures {
    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features = func_features;
    features.functions.insert(ADDR1, func);
    features
}

/// Helper: create ExtractedFeatures with custom OS/arch/format + function features
fn make_features_with(
    os: OsType,
    arch: ArchType,
    format: FormatType,
    func_features: FeatureSet,
) -> ExtractedFeatures {
    let mut features = ExtractedFeatures::new(os, arch, format);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features = func_features;
    features.functions.insert(ADDR1, func);
    features
}

/// Helper: match a single rule and return whether it matched + the match name
fn match_single(yaml: &str, func_features: FeatureSet) -> bool {
    let rule = parse_rule(yaml).expect("failed to parse rule");
    let engine = MatchEngine::new(vec![rule]);
    let features = make_features(func_features);
    !engine.match_all_sequential(&features).is_empty()
}

/// Helper: match with custom OS/arch/format
fn match_with_env(
    yaml: &str,
    os: OsType,
    arch: ArchType,
    format: FormatType,
    func_features: FeatureSet,
) -> bool {
    let rule = parse_rule(yaml).expect("failed to parse rule");
    let engine = MatchEngine::new(vec![rule]);
    let features = make_features_with(os, arch, format, func_features);
    !engine.match_all_sequential(&features).is_empty()
}

// ---------- test_match_simple (port of test_match.py::test_match_simple) ----------

#[test]
fn test_match_simple_number() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
        namespace: testns1/testns2
    features:
        - number: 100
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_simple_number_no_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - number: 100
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(99);
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_range_exact ----------

#[test]
fn test_match_count_number_exact_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(number(100)): 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_count_number_exact_no_match() {
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
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_range_range ----------

#[test]
fn test_match_count_range() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - count(mnemonic(push)): (2, 5)
"#;
    // in range
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("push".to_string(), 3);
    assert!(match_single(yaml, fs));

    // below range
    let mut fs2 = FeatureSet::new();
    fs2.mnemonics.insert("push".to_string(), 1);
    assert!(!match_single(yaml, fs2));

    // above range
    let mut fs3 = FeatureSet::new();
    fs3.mnemonics.insert("push".to_string(), 6);
    assert!(!match_single(yaml, fs3));
}

// ---------- test_match_range_exact_zero ----------

#[test]
fn test_match_count_exact_zero() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - count(number(100)): 0
            - mnemonic: mov
"#;
    // feature not indexed → count is 0 → matches
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("mov".to_string(), 1);
    assert!(match_single(yaml, fs));

    // feature present → count is 1 → doesn't match 0
    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(100);
    fs2.mnemonics.insert("mov".to_string(), 1);
    assert!(!match_single(yaml, fs2));
}

// ---------- test_match_range_with_zero ----------

#[test]
fn test_match_count_range_with_zero() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - count(number(100)): (0, 1)
            - mnemonic: mov
"#;
    // not present → count 0 → in (0,1)
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("mov".to_string(), 1);
    assert!(match_single(yaml, fs));

    // present → count 1 → in (0,1)
    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(100);
    fs2.mnemonics.insert("mov".to_string(), 1);
    assert!(match_single(yaml, fs2));
}

// ---------- test_match_matched_rules ----------

#[test]
fn test_match_rule_reference() {
    let yaml1 = r#"
rule:
    meta:
        name: test rule1
        scopes:
            static: function
    features:
        - number: 100
"#;
    let yaml2 = r#"
rule:
    meta:
        name: test rule2
        scopes:
            static: function
    features:
        - match: test rule1
"#;
    let rule1 = parse_rule(yaml1).unwrap();
    let rule2 = parse_rule(yaml2).unwrap();
    let engine = MatchEngine::new(vec![rule1, rule2]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.numbers.insert(100);
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    let names: Vec<&str> = matches.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"test rule1"));
    assert!(names.contains(&"test rule2"));
}

// ---------- test_match_substring ----------

#[test]
fn test_match_substring_no_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - substring: abc
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("aaaa".to_string());
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_substring_exact() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - substring: abc
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("abc".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_substring_in_middle() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - substring: abc
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("111abc222".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_substring_at_start() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - substring: abc
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("abc222".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_substring_at_end() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - substring: abc
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("111abc".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- test_match_regex ----------

#[test]
fn test_match_regex_no_match_wrong_feature() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - string: /.*bbbb.*/
"#;
    // no strings at all, just numbers
    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_regex_no_match_wrong_string() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - string: /.*bbbb.*/
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("aaaa".to_string());
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_regex_case_sensitive_no_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - string: /.*bbbb.*/
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("aBBBBa".to_string());
    // case-sensitive regex → BBBB doesn't match bbbb
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_regex_case_sensitive_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - string: /.*bbbb.*/
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("abbbba".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_regex_with_anchor() {
    let yaml = r#"
rule:
    meta:
        name: rule with anchor
        scopes:
            static: function
    features:
        - string: /^bbbb/
"#;
    // "abbbba" starts with 'a', not 'bbbb'
    let mut fs = FeatureSet::new();
    fs.strings.insert("abbbba".to_string());
    assert!(!match_single(yaml, fs));

    // "bbbba" starts with 'bbbb'
    let mut fs2 = FeatureSet::new();
    fs2.strings.insert("bbbba".to_string());
    assert!(match_single(yaml, fs2));
}

// ---------- test_match_regex_ignorecase ----------

#[test]
fn test_match_regex_ignorecase() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - string: /.*bbbb.*/i
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("aBBBBa".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- test_match_regex_complex ----------

#[test]
fn test_match_regex_complex_backslashes() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - or:
            - string: /.*HARDWARE\\Key\\key with spaces\\.*/i
"#;
    let mut fs = FeatureSet::new();
    fs.strings
        .insert(r"Hardware\Key\key with spaces\some value".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- test_match_regex_values_always_string ----------

#[test]
fn test_match_regex_numeric_string() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - or:
            - string: /123/
            - string: /0x123/
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("123".to_string());
    assert!(match_single(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.strings.insert("0x123".to_string());
    assert!(match_single(yaml, fs2));
}

// ---------- test_match_not ----------

#[test]
fn test_match_not() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - mnemonic: mov
            - not:
                - number: 99
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    fs.mnemonics.insert("mov".to_string(), 1);
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_not_with_feature_present() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - mnemonic: mov
            - not:
                - number: 99
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(99);
    fs.mnemonics.insert("mov".to_string(), 1);
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_operand_number ----------

#[test]
fn test_match_operand_number() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].number: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((0, Some(0x10), None));
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_operand_number_wrong_index() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].number: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((1, Some(0x10), None));
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_operand_number_wrong_value() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].number: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((0, Some(0x11), None));
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_operand_offset ----------

#[test]
fn test_match_operand_offset() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].offset: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((0, None, Some(0x10)));
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_operand_offset_wrong_index() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].offset: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((1, None, Some(0x10)));
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_operand_offset_wrong_value() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - operand[0].offset: 0x10
"#;
    let mut fs = FeatureSet::new();
    fs.operands.push((0, None, Some(0x11)));
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_property_access ----------

#[test]
fn test_match_property_read() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - property/read: System.IO.FileInfo::Length
"#;
    let mut fs = FeatureSet::new();
    fs.properties.push((
        "System.IO.FileInfo::Length".to_string(),
        PropertyAccess::Read,
    ));
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_property_wrong_access() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - property/read: System.IO.FileInfo::Length
"#;
    let mut fs = FeatureSet::new();
    fs.properties.push((
        "System.IO.FileInfo::Length".to_string(),
        PropertyAccess::Write,
    ));
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_match_property_wrong_name() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - property/read: System.IO.FileInfo::Length
"#;
    let mut fs = FeatureSet::new();
    fs.properties.push((
        "System.IO.FileInfo::Size".to_string(),
        PropertyAccess::Read,
    ));
    assert!(!match_single(yaml, fs));
}

// ---------- test_match_os ----------

#[test]
fn test_match_os_windows() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - os: windows
            - string: "Hello world"
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("Hello world".to_string());
    assert!(match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

#[test]
fn test_match_os_any() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - os: any
            - string: "Goodbye world"
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("Goodbye world".to_string());
    // os: any matches any OS
    assert!(match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

#[test]
fn test_match_os_linux_on_windows() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - os: linux
            - string: "Hello world"
"#;
    let mut fs = FeatureSet::new();
    fs.strings.insert("Hello world".to_string());
    // linux rule on Windows binary → no match
    assert!(!match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

// ---------- test_match_arch ----------

#[test]
fn test_match_arch_i386() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - arch: i386
"#;
    let fs = FeatureSet::new();
    assert!(match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

#[test]
fn test_match_arch_amd64_on_i386() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - arch: amd64
"#;
    let fs = FeatureSet::new();
    assert!(!match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

// ---------- test_match_format ----------

#[test]
fn test_match_format_pe() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - format: pe
"#;
    let fs = FeatureSet::new();
    assert!(match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

#[test]
fn test_match_format_elf_on_pe() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - format: elf
"#;
    let fs = FeatureSet::new();
    assert!(!match_with_env(
        yaml,
        OsType::Windows,
        ArchType::I386,
        FormatType::Pe,
        fs
    ));
}

// ---------- API matching ----------

#[test]
fn test_match_api_case_insensitive() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - api: createfilea
"#;
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_api_or() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - or:
            - api: CreateFileA
            - api: CreateFileW
"#;
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileW".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- Import / Export matching ----------

#[test]
fn test_match_import() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - import: kernel32.CreateFileA
"#;
    let mut fs = FeatureSet::new();
    fs.imports.insert("kernel32.CreateFileA".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_export() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - export: DllRegisterServer
"#;
    let mut fs = FeatureSet::new();
    fs.exports.insert("DllRegisterServer".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- Section matching ----------

#[test]
fn test_match_section() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - section: .text
"#;
    let mut fs = FeatureSet::new();
    fs.sections.insert(".text".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- Characteristic matching ----------

#[test]
fn test_match_characteristic_embedded_pe() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: file
    features:
        - characteristic: embedded pe
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features
        .file
        .characteristics
        .insert(CharacteristicType::EmbeddedPe);

    let matches = engine.match_all_sequential(&features);
    assert!(!matches.is_empty());
}

// ---------- Bytes matching ----------

#[test]
fn test_match_bytes() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - bytes: 4D 5A 90 00
"#;
    let mut fs = FeatureSet::new();
    fs.bytes_sequences.push(vec![0x4D, 0x5A, 0x90, 0x00]);
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_bytes_no_match() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - bytes: 4D 5A 90 00
"#;
    let mut fs = FeatureSet::new();
    fs.bytes_sequences.push(vec![0x4D, 0x5A, 0x00, 0x00]);
    assert!(!match_single(yaml, fs));
}

// ---------- .NET features ----------

#[test]
fn test_match_namespace() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - namespace: System.IO
"#;
    let mut fs = FeatureSet::new();
    fs.namespaces.insert("System.IO".to_string());
    assert!(match_single(yaml, fs));
}

#[test]
fn test_match_class() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - class: System.IO.File
"#;
    let mut fs = FeatureSet::new();
    fs.classes.insert("System.IO.File".to_string());
    assert!(match_single(yaml, fs));
}

// ---------- Complex multi-rule scenarios ----------

#[test]
fn test_match_and_or_combined() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - and:
            - api: CreateFileA
            - or:
                - api: WriteFile
                - api: WriteFileEx
"#;
    // both CreateFileA and WriteFile
    let mut fs = FeatureSet::new();
    fs.apis.insert("CreateFileA".to_string());
    fs.apis.insert("WriteFile".to_string());
    assert!(match_single(yaml, fs));

    // both CreateFileA and WriteFileEx
    let mut fs2 = FeatureSet::new();
    fs2.apis.insert("CreateFileA".to_string());
    fs2.apis.insert("WriteFileEx".to_string());
    assert!(match_single(yaml, fs2));

    // only CreateFileA (missing or branch)
    let mut fs3 = FeatureSet::new();
    fs3.apis.insert("CreateFileA".to_string());
    assert!(!match_single(yaml, fs3));
}

#[test]
fn test_match_result_fields() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        namespace: test/ns
        scopes:
            static: function
        att&ck:
            - "Execution::Shared Modules [T1129]"
        lib: true
    features:
        - api: LoadLibraryA
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("LoadLibraryA".to_string());
    features.functions.insert(ADDR1, func);

    let matches = engine.match_all_sequential(&features);
    assert_eq!(matches.len(), 1);

    let m = &matches[0];
    assert_eq!(m.name, "test rule");
    assert_eq!(m.namespace, Some("test/ns".to_string()));
    assert!(m.is_lib);
    assert_eq!(m.attack.len(), 1);
    assert!(m.match_count > 0);
    assert!(!m.locations.is_empty());
}

// ---------- File scope matching ----------

#[test]
fn test_match_file_scope_import() {
    let yaml = r#"
rule:
    meta:
        name: test file import
        scopes:
            static: file
    features:
        - import: kernel32.CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    features
        .file
        .imports
        .insert("kernel32.CreateFileA".to_string());

    let matches = engine.match_all_sequential(&features);
    assert!(!matches.is_empty());
}

// ---------- Instruction scope matching ----------

#[test]
fn test_match_instruction_scope() {
    let yaml = r#"
rule:
    meta:
        name: test insn scope
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
    let addr = Address(0x1000);
    let mut func = FunctionFeatures::new(addr);
    let mut insn_features = FeatureSet::new();
    insn_features.mnemonics.insert("push".to_string(), 1);
    insn_features.numbers.insert(0x80000000u32 as i64);
    func.instructions.insert(Address(0x1000), insn_features);
    features.functions.insert(addr, func);

    let matches = engine.match_all_sequential(&features);
    assert!(!matches.is_empty());
    assert_eq!(matches[0].name, "test insn scope");
}

// ---------- No match scenarios ----------

#[test]
fn test_no_match_empty_features() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - api: NonexistentAPI
"#;
    let fs = FeatureSet::new();
    assert!(!match_single(yaml, fs));
}

#[test]
fn test_no_match_empty_functions() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
    features:
        - api: CreateFileA
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);
    let features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let matches = engine.match_all_sequential(&features);
    assert!(matches.is_empty());
}
