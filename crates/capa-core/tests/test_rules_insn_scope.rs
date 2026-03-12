// Port of capa/tests/test_rules_insn_scope.py
//
// Tests instruction scope parsing, subscope instruction blocks,
// implied AND in instruction subscopes, and descriptions within instruction subscopes.

use capa_core::rule::parse_rule;

// ---------- test_rule_scope_instruction ----------

#[test]
fn test_rule_scope_instruction_valid() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: instruction
            dynamic: unsupported
    features:
        - and:
            - mnemonic: mov
            - arch: i386
            - os: windows
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

// ---------- test_rule_subscope_instruction ----------

#[test]
fn test_rule_subscope_instruction() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - instruction:
                - and:
                    - mnemonic: mov
                    - arch: i386
                    - os: windows
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

// ---------- test_scope_instruction_implied_and ----------

#[test]
fn test_scope_instruction_implied_and() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - instruction:
                - mnemonic: mov
                - arch: i386
                - os: windows
"#;
    // Multiple features within an instruction subscope form an implied AND
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

// ---------- test_scope_instruction_description ----------

#[test]
fn test_scope_instruction_description() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - instruction:
                - description: foo
                - mnemonic: mov
                - arch: i386
                - os: windows
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

#[test]
fn test_scope_instruction_description_variant() {
    // Same structure, just verify it parses consistently
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - instruction:
                - description: foo
                - mnemonic: mov
                - arch: i386
                - os: windows
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

// ---------- Additional instruction scope tests ----------

#[test]
fn test_basic_block_subscope_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - basic block:
                - and:
                    - mnemonic: push
                    - number: 5
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

#[test]
fn test_function_subscope_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: file
            dynamic: process
    features:
        - and:
            - function:
                - and:
                    - api: CreateFile
                    - api: WriteFile
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}

#[test]
fn test_nested_subscopes() {
    let yaml = r#"
rule:
    meta:
        name: test rule
        scopes:
            static: file
    features:
        - and:
            - function:
                - and:
                    - api: CreateFile
                    - instruction:
                        - and:
                            - mnemonic: push
                            - number: 0x80000000
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "test rule");
}
