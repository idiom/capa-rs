// Port of capa/tests/test_engine.py
//
// Tests core matching engine logic: boolean operators, count/range constraints,
// and evaluation semantics.

use capa_core::feature::{Address, ExtractedFeatures, FeatureSet, FunctionFeatures};
use capa_core::matcher::MatchEngine;
use capa_core::rule::parse_rule;
use capa_core::rule::{ArchType, FormatType, OsType};

const ADDR1: Address = Address(0x401001);

/// Helper: create ExtractedFeatures with a single function containing the given FeatureSet
fn make_features(func_features: FeatureSet) -> ExtractedFeatures {
    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features = func_features;
    features.functions.insert(ADDR1, func);
    features
}

/// Helper: check if a rule (given as YAML) matches against the given FeatureSet
fn matches_rule(yaml: &str, func_features: FeatureSet) -> bool {
    let rule = parse_rule(yaml).expect("failed to parse rule");
    let engine = MatchEngine::new(vec![rule]);
    let features = make_features(func_features);
    !engine.match_all_sequential(&features).is_empty()
}

// ---------- test_number (port of test_engine.py::test_number) ----------

#[test]
fn test_number_no_match() {
    let yaml = r#"
rule:
  meta:
    name: test number
    scopes:
      static: function
  features:
    - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_number_match() {
    let yaml = r#"
rule:
  meta:
    name: test number
    scopes:
      static: function
  features:
    - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_number_wrong_value() {
    let yaml = r#"
rule:
  meta:
    name: test number
    scopes:
      static: function
  features:
    - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(2);
    assert!(!matches_rule(yaml, fs));
}

// ---------- test_and (port of test_engine.py::test_and) ----------

#[test]
fn test_and_single_child_no_match() {
    let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_and_single_child_match() {
    let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_and_two_children_none_match() {
    let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_and_two_children_one_match() {
    let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(!matches_rule(yaml, fs.clone()));

    let mut fs2 = FeatureSet::new();
    fs2.numbers.insert(2);
    assert!(!matches_rule(yaml, fs2));
}

#[test]
fn test_and_two_children_both_match() {
    let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_or (port of test_engine.py::test_or) ----------

#[test]
fn test_or_single_child_no_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_or_single_child_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_or_two_children_none_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_or_two_children_first_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_or_two_children_second_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_or_two_children_both_match() {
    let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - number: 1
      - number: 2
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_not (port of test_engine.py::test_not) ----------

#[test]
fn test_not_no_feature() {
    let yaml = r#"
rule:
  meta:
    name: test not
    scopes:
      static: function
  features:
    - and:
      - number: 99
      - not:
        - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(99);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_not_with_feature() {
    let yaml = r#"
rule:
  meta:
    name: test not
    scopes:
      static: function
  features:
    - and:
      - number: 99
      - not:
        - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    fs.numbers.insert(99);
    assert!(!matches_rule(yaml, fs));
}

// ---------- test_some / NOrMore (port of test_engine.py::test_some) ----------

#[test]
fn test_n_or_more_zero_threshold_no_match() {
    // Some(0, [Number(1)]) should match even when Number(1) is not present
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 0 or more:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_n_or_more_one_threshold_no_match() {
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 1 or more:
      - number: 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_n_or_more_two_of_three_not_enough() {
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 2 or more:
      - number: 1
      - number: 2
      - number: 3
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_n_or_more_two_of_three_one_match() {
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 2 or more:
      - number: 1
      - number: 2
      - number: 3
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(1);
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_n_or_more_two_of_three_two_match() {
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 2 or more:
      - number: 1
      - number: 2
      - number: 3
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(0);
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_n_or_more_two_of_three_all_match() {
    let yaml = r#"
rule:
  meta:
    name: test some
    scopes:
      static: function
  features:
    - 2 or more:
      - number: 1
      - number: 2
      - number: 3
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    fs.numbers.insert(2);
    fs.numbers.insert(3);
    assert!(matches_rule(yaml, fs));
}

// ---------- test_complex (port of test_engine.py::test_complex) ----------

#[test]
fn test_complex_nested_match() {
    // Or([And([1, 2]), Or([3, Some(2, [4, 5, 6])])])
    // with {5, 6, 7, 8} → true (5 and 6 satisfy "2 or more" of [4, 5, 6])
    let yaml = r#"
rule:
  meta:
    name: test complex
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
}

#[test]
fn test_complex_nested_no_match() {
    // Or([And([1, 2]), Or([3, Some(2, [4, 5])])])
    // with {5, 6, 7, 8} → false (only 5 matches out of [4, 5], need 2)
    let yaml = r#"
rule:
  meta:
    name: test complex
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
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(5);
    fs.numbers.insert(6);
    fs.numbers.insert(7);
    fs.numbers.insert(8);
    assert!(!matches_rule(yaml, fs));
}

// ---------- test_count / range (port of test_engine.py::test_range) ----------
// Note: Python's Range counts the number of *addresses* where a feature appears.
// In Rust, count(number(X)) counts whether the number exists (0 or 1) in the FeatureSet,
// since FeatureSet.numbers is a HashSet. The semantics differ slightly.
// We test what the Rust engine actually supports.

#[test]
fn test_count_exact_match() {
    let yaml = r#"
rule:
  meta:
    name: test count
    scopes:
      static: function
  features:
    - count(number(1)): 1
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(1);
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_count_exact_no_feature() {
    let yaml = r#"
rule:
  meta:
    name: test count
    scopes:
      static: function
  features:
    - count(number(1)): 1
"#;
    let fs = FeatureSet::new();
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_count_exact_zero() {
    let yaml = r#"
rule:
  meta:
    name: test count zero
    scopes:
      static: function
  features:
    - and:
      - count(number(100)): 0
      - mnemonic: mov
"#;
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("mov".to_string(), 1);
    // number 100 is not present → count is 0 → matches
    assert!(matches_rule(yaml, fs));
}

#[test]
fn test_count_exact_zero_with_feature_present() {
    let yaml = r#"
rule:
  meta:
    name: test count zero
    scopes:
      static: function
  features:
    - and:
      - count(number(100)): 0
      - mnemonic: mov
"#;
    let mut fs = FeatureSet::new();
    fs.numbers.insert(100);
    fs.mnemonics.insert("mov".to_string(), 1);
    // number 100 IS present → count is 1 → doesn't match count=0
    assert!(!matches_rule(yaml, fs));
}

#[test]
fn test_count_or_more() {
    let yaml = r#"
rule:
  meta:
    name: test count or more
    scopes:
      static: function
  features:
    - count(mnemonic(push)): 3 or more
"#;
    // 5 push instructions → matches (>= 3)
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("push".to_string(), 5);
    assert!(matches_rule(yaml, fs));

    // 2 push instructions → doesn't match (< 3)
    let mut fs2 = FeatureSet::new();
    fs2.mnemonics.insert("push".to_string(), 2);
    assert!(!matches_rule(yaml, fs2));
}

#[test]
fn test_count_range() {
    let yaml = r#"
rule:
  meta:
    name: test count range
    scopes:
      static: function
  features:
    - count(mnemonic(push)): (3, 10)
"#;
    // 5 push instructions → matches (3..=10)
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("push".to_string(), 5);
    assert!(matches_rule(yaml, fs));

    // 2 push instructions → doesn't match (< 3)
    let mut fs2 = FeatureSet::new();
    fs2.mnemonics.insert("push".to_string(), 2);
    assert!(!matches_rule(yaml, fs2));

    // 11 push instructions → doesn't match (> 10)
    let mut fs3 = FeatureSet::new();
    fs3.mnemonics.insert("push".to_string(), 11);
    assert!(!matches_rule(yaml, fs3));
}

#[test]
fn test_count_or_fewer() {
    let yaml = r#"
rule:
  meta:
    name: test count or fewer
    scopes:
      static: function
  features:
    - count(mnemonic(push)): 2 or fewer
"#;
    let mut fs = FeatureSet::new();
    fs.mnemonics.insert("push".to_string(), 1);
    assert!(matches_rule(yaml, fs));

    let mut fs2 = FeatureSet::new();
    fs2.mnemonics.insert("push".to_string(), 3);
    assert!(!matches_rule(yaml, fs2));
}

// ---------- test parallel vs sequential ----------

#[test]
fn test_parallel_vs_sequential() {
    let yaml = r#"
rule:
  meta:
    name: test parallel
    scopes:
      static: function
  features:
    - api: TestAPI
"#;
    let rule = parse_rule(yaml).unwrap();
    let engine = MatchEngine::new(vec![rule]);

    let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
    let mut func = FunctionFeatures::new(ADDR1);
    func.features.apis.insert("TestAPI".to_string());
    features.functions.insert(ADDR1, func);

    let parallel = engine.match_all(&features);
    let sequential = engine.match_all_sequential(&features);
    assert_eq!(parallel.len(), sequential.len());
}
