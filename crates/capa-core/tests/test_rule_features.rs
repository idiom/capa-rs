// Port of concepts from:
// - capa/tests/test_render.py (feature type coverage)
// - capa/tests/test_fmt.py (meta fields preservation)
// - capa/tests/test_optimizer.py (AST structure)
// - capa/tests/test_proto.py (scope parsing)
// - capa/tests/test_result_document.py (node type verification)
// - capa/tests/test_rule_cache.py (parse consistency)

use capa_core::rule::parse_rule;
use capa_core::rule::FeatureNode;

// ---------- Feature type parsing (from test_render.py) ----------

#[test]
fn test_number_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - number: 0x1000
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_offset_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - offset: 0x100
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_property_read_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - property/read: System.IO.FileInfo::Length
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_property_write_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - property/write: MyProp
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_api_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - api: CreateFile
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_string_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - string: "test string"
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_bytes_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - bytes: 4D 5A 90 00
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_mnemonic_feature_parsing() {
    let yaml = r#"
rule:
    meta:
        name: test
        scopes: { static: function }
    features:
        - mnemonic: mov
"#;
    assert!(parse_rule(yaml).is_ok());
}

#[test]
fn test_characteristic_nzxor_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: nzxor
"#).is_ok());
}

#[test]
fn test_characteristic_loop_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: loop
"#).is_ok());
}

#[test]
fn test_characteristic_tight_loop_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: tight loop
"#).is_ok());
}

#[test]
fn test_characteristic_embedded_pe_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - characteristic: embedded pe
"#).is_ok());
}

#[test]
fn test_characteristic_switch_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: switch
"#).is_ok());
}

#[test]
fn test_characteristic_recursive_call_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: recursive call
"#).is_ok());
}

#[test]
fn test_characteristic_stack_string_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - characteristic: stack string
"#).is_ok());
}

#[test]
fn test_characteristic_packer_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - characteristic: packer
"#).is_ok());
}

#[test]
fn test_section_feature_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - section: .text
"#).is_ok());
}

#[test]
fn test_import_feature_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - import: kernel32.CreateFileA
"#).is_ok());
}

#[test]
fn test_export_feature_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - export: DllRegisterServer
"#).is_ok());
}

#[test]
fn test_namespace_feature_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - namespace: System.IO
"#).is_ok());
}

#[test]
fn test_class_feature_parsing() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - class: System.IO.File
"#).is_ok());
}

// ---------- Meta fields preservation (from test_fmt.py) ----------

#[test]
fn test_rule_meta_fields_preserved() {
    let yaml = r#"
rule:
    meta:
        name: full meta rule
        namespace: test/meta
        authors:
            - author1
            - author2
        description: A test rule with all meta fields
        scopes:
            static: function
            dynamic: process
        att&ck:
            - "Execution::Command [T1059]"
        mbc:
            - "Anti-Behavioral Analysis::Debugger Detection [B0001]"
        references:
            - https://example.com
        examples:
            - abc123
        lib: true
    features:
        - api: TestAPI
"#;
    let rule = parse_rule(yaml).unwrap();
    assert_eq!(rule.meta.name, "full meta rule");
    assert_eq!(rule.meta.namespace, Some("test/meta".to_string()));
    assert_eq!(rule.meta.authors.len(), 2);
    assert_eq!(rule.meta.description, Some("A test rule with all meta fields".to_string()));
    assert!(!rule.meta.attack.is_empty());
    assert!(!rule.meta.mbc.is_empty());
    assert!(!rule.meta.references.is_empty());
    assert!(!rule.meta.examples.is_empty());
    assert!(rule.meta.is_lib);
}

// ---------- Scope parsing (from test_proto.py) ----------

#[test]
fn test_static_scope_file() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features: [import: kernel32.WriteFile]
"#).is_ok());
}

#[test]
fn test_static_scope_function() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features: [api: Test]
"#).is_ok());
}

#[test]
fn test_static_scope_basic_block() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: basic block } }
    features: [mnemonic: nop]
"#).is_ok());
}

#[test]
fn test_static_scope_instruction() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: instruction } }
    features: [mnemonic: mov]
"#).is_ok());
}

#[test]
fn test_dynamic_scope_process() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function, dynamic: process } }
    features: [api: Test]
"#).is_ok());
}

#[test]
fn test_dynamic_scope_thread() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function, dynamic: thread } }
    features: [api: Test]
"#).is_ok());
}

#[test]
fn test_dynamic_scope_call() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function, dynamic: call } }
    features: [api: Test]
"#).is_ok());
}

#[test]
fn test_dynamic_scope_unsupported() {
    assert!(parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: instruction, dynamic: unsupported } }
    features: [mnemonic: mov]
"#).is_ok());
}

// ---------- AST node types (from test_result_document.py + test_optimizer.py) ----------
//
// NOTE: The parser wraps the top-level features list in an implicit And node.
// So `features: [- and: [...]]` becomes `And([And([...])])`.
// We use a helper to unwrap the implicit outer And when testing inner structure.

fn unwrap_implicit_and(node: &FeatureNode) -> &[FeatureNode] {
    match node {
        FeatureNode::And(children) => children,
        _ => panic!("expected implicit And wrapper at root"),
    }
}

#[test]
fn test_feature_node_and() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - and:
            - number: 1
            - number: 2
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    assert_eq!(children.len(), 1);
    match &children[0] {
        FeatureNode::And(inner) => assert_eq!(inner.len(), 2),
        _ => panic!("expected And node"),
    }
}

#[test]
fn test_feature_node_or() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - or:
            - number: 1
            - number: 2
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    assert_eq!(children.len(), 1);
    match &children[0] {
        FeatureNode::Or(inner) => assert_eq!(inner.len(), 2),
        _ => panic!("expected Or node"),
    }
}

#[test]
fn test_feature_node_not() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - and:
            - number: 99
            - not:
                - number: 1
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::And(inner) => {
            assert_eq!(inner.len(), 2);
            assert!(matches!(&inner[1], FeatureNode::Not(_)));
        }
        _ => panic!("expected And node"),
    }
}

#[test]
fn test_feature_node_optional() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - and:
            - api: Test
            - optional:
                - api: Optional
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::And(inner) => {
            assert!(inner.iter().any(|c| matches!(c, FeatureNode::Optional(_))));
        }
        _ => panic!("expected And node"),
    }
}

#[test]
fn test_feature_node_n_or_more() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - 2 or more:
            - number: 1
            - number: 2
            - number: 3
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::NOrMore(n, inner) => {
            assert_eq!(*n, 2);
            assert_eq!(inner.len(), 3);
        }
        _ => panic!("expected NOrMore node"),
    }
}

#[test]
fn test_feature_node_count() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - count(number(100)): 1
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    assert!(matches!(&children[0], FeatureNode::Count(_, _)));
}

#[test]
fn test_feature_node_match() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - match: other rule
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::Match(name) => assert_eq!(name, "other rule"),
        _ => panic!("expected Match node"),
    }
}

#[test]
fn test_feature_node_instruction_subscope() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - and:
            - instruction:
                - mnemonic: mov
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::And(inner) => {
            assert!(inner.iter().any(|c| matches!(c, FeatureNode::Instruction(_))));
        }
        _ => panic!("expected And node"),
    }
}

#[test]
fn test_feature_node_basic_block_subscope() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: function } }
    features:
        - and:
            - basic block:
                - mnemonic: nop
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::And(inner) => {
            assert!(inner.iter().any(|c| matches!(c, FeatureNode::BasicBlock(_))));
        }
        _ => panic!("expected And node"),
    }
}

#[test]
fn test_feature_node_function_subscope() {
    let rule = parse_rule(r#"
rule:
    meta: { name: test, scopes: { static: file } }
    features:
        - and:
            - function:
                - api: Test
"#).unwrap();
    let children = unwrap_implicit_and(&rule.features);
    match &children[0] {
        FeatureNode::And(inner) => {
            assert!(inner.iter().any(|c| matches!(c, FeatureNode::Function(_))));
        }
        _ => panic!("expected And node"),
    }
}

// ---------- Parse consistency (from test_rule_cache.py) ----------

#[test]
fn test_parse_same_rule_twice() {
    let yaml = r#"
rule:
    meta:
        name: consistent rule
        scopes: { static: function }
    features:
        - api: TestAPI
"#;
    let r1 = parse_rule(yaml).unwrap();
    let r2 = parse_rule(yaml).unwrap();
    assert_eq!(r1.meta.name, r2.meta.name);
    assert_eq!(r1.meta.namespace, r2.meta.namespace);
    assert_eq!(r1.meta.is_lib, r2.meta.is_lib);
}

#[test]
fn test_parse_different_rules_differ() {
    let yaml1 = r#"
rule:
    meta: { name: rule A, scopes: { static: function } }
    features: [api: TestA]
"#;
    let yaml2 = r#"
rule:
    meta: { name: rule B, scopes: { static: function } }
    features: [api: TestB]
"#;
    let r1 = parse_rule(yaml1).unwrap();
    let r2 = parse_rule(yaml2).unwrap();
    assert_ne!(r1.meta.name, r2.meta.name);
}

// ---------- Complex nested AST (from test_optimizer.py) ----------

#[test]
fn test_complex_ast_structure() {
    let yaml = r#"
rule:
    meta:
        name: complex ast
        scopes:
            static: function
            dynamic: process
    features:
        - and:
            - substring: "foo"
            - arch: amd64
            - mnemonic: cmp
            - and:
                - number: 3
                - offset: 2
            - or:
                - number: 1
                - offset: 4
"#;
    let rule = parse_rule(yaml).unwrap();
    // Unwrap implicit outer And
    let outer = unwrap_implicit_and(&rule.features);
    assert_eq!(outer.len(), 1);
    match &outer[0] {
        FeatureNode::And(children) => {
            assert_eq!(children.len(), 5);
            // Verify child types exist
            assert!(children.iter().any(|c| matches!(c, FeatureNode::And(_))));
            assert!(children.iter().any(|c| matches!(c, FeatureNode::Or(_))));
        }
        _ => panic!("expected And node"),
    }
}
