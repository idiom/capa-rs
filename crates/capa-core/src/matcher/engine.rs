//! Core matching engine
//!
//! Evaluates rules against extracted features with parallel processing
//! and optimized string matching.

use aho_corasick::AhoCorasick;
use dashmap::DashMap;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::feature::{Address, ExtractedFeatures, FeatureSet};
use crate::rule::{
    ArchType, CountConstraint, Feature, FeatureNode, FormatType, OsType,
    Rule, StaticScope, StringMatcher,
};

/// Match result for a single rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule name
    pub name: String,
    /// Rule namespace
    pub namespace: Option<String>,
    /// Number of locations where rule matched
    pub match_count: usize,
    /// Locations where rule matched (addresses)
    pub locations: Vec<Address>,
    /// Function names where rule matched (for .NET and other symbolic binaries)
    pub function_names: Vec<String>,
    /// ATT&CK technique IDs
    pub attack: Vec<String>,
    /// MBC IDs
    pub mbc: Vec<String>,
    /// Is this a library rule?
    pub is_lib: bool,
}

/// Pre-compiled string patterns for fast matching
/// Currently built but reserved for future batch-matching optimization
#[derive(Debug)]
#[allow(dead_code)]
pub struct StringIndex {
    /// Exact string patterns mapped to pattern IDs
    exact_patterns: Vec<String>,
    /// Aho-Corasick automaton for exact matching
    exact_automaton: Option<AhoCorasick>,
    /// Map from pattern to indices in the automaton
    pattern_to_rules: HashMap<String, Vec<usize>>,
}

#[allow(dead_code)]
impl StringIndex {
    /// Build a string index from rules
    pub fn from_rules(rules: &[Rule]) -> Self {
        let mut patterns = Vec::new();
        let mut pattern_to_rules: HashMap<String, Vec<usize>> = HashMap::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            Self::collect_patterns(&rule.features, rule_idx, &mut patterns, &mut pattern_to_rules);
        }

        // Deduplicate patterns
        let unique_patterns: Vec<String> = patterns.into_iter().collect::<HashSet<_>>().into_iter().collect();

        let automaton = if !unique_patterns.is_empty() {
            AhoCorasick::new(&unique_patterns).ok()
        } else {
            None
        };

        Self {
            exact_patterns: unique_patterns,
            exact_automaton: automaton,
            pattern_to_rules,
        }
    }

    fn collect_patterns(
        node: &FeatureNode,
        rule_idx: usize,
        patterns: &mut Vec<String>,
        pattern_to_rules: &mut HashMap<String, Vec<usize>>,
    ) {
        match node {
            FeatureNode::And(children) | FeatureNode::Or(children) | FeatureNode::NOrMore(_, children) | FeatureNode::Optional(children) | FeatureNode::Instruction(children) | FeatureNode::BasicBlock(children) | FeatureNode::Function(children) => {
                for child in children {
                    Self::collect_patterns(child, rule_idx, patterns, pattern_to_rules);
                }
            }
            FeatureNode::Not(child) | FeatureNode::Count(child, _) | FeatureNode::Description(_, child) => {
                Self::collect_patterns(child, rule_idx, patterns, pattern_to_rules);
            }
            FeatureNode::Feature(feature) => {
                if let Some(pattern) = Self::extract_exact_pattern(feature) {
                    patterns.push(pattern.clone());
                    pattern_to_rules.entry(pattern).or_default().push(rule_idx);
                }
            }
            FeatureNode::Match(_) => {}
        }
    }

    fn extract_exact_pattern(feature: &Feature) -> Option<String> {
        match feature {
            Feature::Api(StringMatcher::Exact(s))
            | Feature::Import(StringMatcher::Exact(s))
            | Feature::Export(StringMatcher::Exact(s))
            | Feature::String(StringMatcher::Exact(s))
            | Feature::FunctionName(StringMatcher::Exact(s))
            | Feature::Section(StringMatcher::Exact(s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Check if any pattern matches in the given strings
    pub fn find_matches(&self, strings: &HashSet<String>) -> HashSet<String> {
        let mut found = HashSet::new();

        if let Some(ref automaton) = self.exact_automaton {
            for s in strings {
                for mat in automaton.find_iter(s) {
                    if let Some(pattern) = self.exact_patterns.get(mat.pattern().as_usize()) {
                        // Only count exact matches
                        if s == pattern {
                            found.insert(pattern.clone());
                        }
                    }
                }
            }
        }

        found
    }
}

/// Rule matching engine with parallel processing
pub struct MatchEngine {
    rules: Vec<Rule>,
    rule_index: HashMap<String, usize>,
    /// Pre-built string index for future batch optimization
    #[allow(dead_code)]
    string_index: StringIndex,
}

impl MatchEngine {
    /// Create a new match engine with the given rules
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut rule_index = HashMap::new();
        for (i, rule) in rules.iter().enumerate() {
            rule_index.insert(rule.meta.name.clone(), i);
        }

        let string_index = StringIndex::from_rules(&rules);

        Self {
            rules,
            rule_index,
            string_index,
        }
    }

    /// Get total number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Match all rules against extracted features (parallel)
    pub fn match_all(&self, features: &ExtractedFeatures) -> Vec<RuleMatch> {
        let cache: Arc<DashMap<String, bool>> = Arc::new(DashMap::new());

        // Process rules in parallel
        self.rules
            .par_iter()
            .filter_map(|rule| {
                self.match_rule(rule, features, &cache)
            })
            .collect()
    }

    /// Match all rules sequentially (for debugging/testing)
    pub fn match_all_sequential(&self, features: &ExtractedFeatures) -> Vec<RuleMatch> {
        let cache: Arc<DashMap<String, bool>> = Arc::new(DashMap::new());

        self.rules
            .iter()
            .filter_map(|rule| {
                self.match_rule(rule, features, &cache)
            })
            .collect()
    }

    /// Match a single rule by name
    pub fn match_rule_by_name(
        &self,
        name: &str,
        features: &ExtractedFeatures,
    ) -> Option<RuleMatch> {
        let cache = Arc::new(DashMap::new());
        let idx = self.rule_index.get(name)?;
        let rule = &self.rules[*idx];
        self.match_rule(rule, features, &cache)
    }

    fn match_rule(
        &self,
        rule: &Rule,
        features: &ExtractedFeatures,
        cache: &Arc<DashMap<String, bool>>,
    ) -> Option<RuleMatch> {
        // Check cache first
        if let Some(cached) = cache.get(&rule.meta.name) {
            if !*cached {
                return None;
            }
        }

        let scope = rule.meta.scopes.static_scope;
        let mut locations = Vec::new();
        let mut function_names = Vec::new();

        let matched = match scope {
            StaticScope::File => {
                let file_features = features.all_features();
                if self.evaluate_node(&rule.features, &file_features, features, cache) {
                    // File-scope matched - now find which functions contributed
                    // by checking which functions have features that match the rule
                    for (addr, func) in &features.functions {
                        let func_features = func.all_features();
                        // Check if this function has any features relevant to the rule
                        if self.evaluate_node(&rule.features, &func_features, features, cache) {
                            locations.push(*addr);
                            // Collect function names if available
                            for name in &func_features.function_names {
                                if !function_names.contains(name) {
                                    function_names.push(name.clone());
                                }
                            }
                        }
                    }
                    // If no individual functions matched, the features may be file-level only
                    // (like format: dotnet or characteristic: embedded pe)
                    if locations.is_empty() {
                        locations.push(Address(0));
                    }
                    true
                } else {
                    false
                }
            }
            StaticScope::Function => {
                // Check each function and collect matching locations
                for (addr, func) in &features.functions {
                    let func_features = func.all_features();
                    if self.evaluate_node(&rule.features, &func_features, features, cache) {
                        locations.push(*addr);
                        // Collect function names if available
                        for name in &func_features.function_names {
                            if !function_names.contains(name) {
                                function_names.push(name.clone());
                            }
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::BasicBlock => {
                // Check each basic block
                for (func_addr, func) in &features.functions {
                    for (bb_idx, bb) in &func.basic_blocks {
                        if self.evaluate_node(&rule.features, bb, features, cache) {
                            locations.push(Address(func_addr.0 + *bb_idx as u64));
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::Instruction => {
                // Check each instruction
                for func in features.functions.values() {
                    for (addr, inst) in &func.instructions {
                        if self.evaluate_node(&rule.features, inst, features, cache) {
                            locations.push(*addr);
                        }
                    }
                }
                !locations.is_empty()
            }
            StaticScope::Unsupported => false,
        };

        // Cache result
        cache.insert(rule.meta.name.clone(), matched);

        if matched {
            Some(RuleMatch {
                name: rule.meta.name.clone(),
                namespace: rule.meta.namespace.clone(),
                match_count: locations.len(),
                locations,
                function_names,
                attack: rule.meta.attack.clone(),
                mbc: rule.meta.mbc.clone(),
                is_lib: rule.meta.is_lib,
            })
        } else {
            None
        }
    }

    fn evaluate_node(
        &self,
        node: &FeatureNode,
        scope_features: &FeatureSet,
        all_features: &ExtractedFeatures,
        cache: &Arc<DashMap<String, bool>>,
    ) -> bool {
        match node {
            FeatureNode::And(children) => {
                children.iter().all(|c| self.evaluate_node(c, scope_features, all_features, cache))
            }

            FeatureNode::Or(children) => children
                .iter()
                .any(|c| self.evaluate_node(c, scope_features, all_features, cache)),

            FeatureNode::Not(child) => {
                !self.evaluate_node(child, scope_features, all_features, cache)
            }

            FeatureNode::NOrMore(n, children) => {
                let count = children
                    .iter()
                    .filter(|c| self.evaluate_node(c, scope_features, all_features, cache))
                    .count();
                count >= *n
            }

            FeatureNode::Optional(_) => true,

            FeatureNode::Count(child, constraint) => {
                let count = self.count_feature(child, scope_features);
                match constraint {
                    CountConstraint::Exact(n) => count == *n,
                    CountConstraint::OrMore(n) => count >= *n,
                    CountConstraint::OrFewer(n) => count <= *n,
                    CountConstraint::Range(min, max) => count >= *min && count <= *max,
                }
            }

            FeatureNode::Feature(feature) => self.match_feature(feature, scope_features, all_features),

            FeatureNode::Description(_, child) => {
                self.evaluate_node(child, scope_features, all_features, cache)
            }

            FeatureNode::Match(rule_name) => {
                // Check if referenced rule matches
                if let Some(cached) = cache.get(rule_name) {
                    return *cached;
                }
                if let Some(idx) = self.rule_index.get(rule_name) {
                    let rule = &self.rules[*idx];
                    self.match_rule(rule, all_features, cache).is_some()
                } else {
                    false
                }
            }

            FeatureNode::Instruction(children) => {
                // All children must match the same instruction
                // This is evaluated at instruction scope, so scope_features
                // already represents a single instruction's features
                children
                    .iter()
                    .all(|c| self.evaluate_node(c, scope_features, all_features, cache))
            }

            FeatureNode::BasicBlock(children) => {
                // All children must match within a basic block
                // Similar semantics to Instruction but at basic block scope
                children
                    .iter()
                    .all(|c| self.evaluate_node(c, scope_features, all_features, cache))
            }

            FeatureNode::Function(children) => {
                // All children must match within a function
                // Similar semantics to Instruction but at function scope
                children
                    .iter()
                    .all(|c| self.evaluate_node(c, scope_features, all_features, cache))
            }
        }
    }

    fn count_feature(&self, node: &FeatureNode, scope_features: &FeatureSet) -> usize {
        match node {
            FeatureNode::Feature(Feature::Api(matcher)) => {
                count_string_matches(matcher, &scope_features.apis)
            }
            FeatureNode::Feature(Feature::String(matcher)) => {
                count_string_matches(matcher, &scope_features.strings)
            }
            FeatureNode::Feature(Feature::Import(matcher)) => {
                count_string_matches(matcher, &scope_features.imports)
            }
            FeatureNode::Feature(Feature::Mnemonic(mnem)) => {
                *scope_features.mnemonics.get(mnem).unwrap_or(&0)
            }
            FeatureNode::Feature(Feature::Number(num)) => {
                if scope_features.numbers.contains(&num.value) { 1 } else { 0 }
            }
            FeatureNode::Feature(Feature::Characteristic(char_type)) => {
                if scope_features.characteristics.contains(char_type) {
                    1
                } else {
                    0
                }
            }
            FeatureNode::Feature(Feature::Offset(offset_matcher)) => {
                if scope_features.offsets.contains(&offset_matcher.value) { 1 } else { 0 }
            }
            FeatureNode::Feature(Feature::Export(matcher)) => {
                count_string_matches(matcher, &scope_features.exports)
            }
            FeatureNode::Feature(Feature::Section(matcher)) => {
                count_string_matches(matcher, &scope_features.sections)
            }
            FeatureNode::Feature(Feature::Substring(matcher)) => {
                // Count substring matches across all strings
                match matcher {
                    StringMatcher::Exact(pattern) => {
                        let p = pattern.to_lowercase();
                        scope_features.strings.iter().filter(|s| s.to_lowercase().contains(&p)).count()
                    }
                    StringMatcher::Regex(compiled) => {
                        scope_features.strings.iter().filter(|s| compiled.is_match(s)).count()
                    }
                }
            }
            FeatureNode::Feature(Feature::BasicBlockFeature) => {
                scope_features.basic_block_count
            }
            _ => 0,
        }
    }

    fn match_feature(
        &self,
        feature: &Feature,
        scope_features: &FeatureSet,
        all_features: &ExtractedFeatures,
    ) -> bool {
        match feature {
            Feature::Api(matcher) => match_string(matcher, &scope_features.apis),
            Feature::Import(matcher) => match_string(matcher, &scope_features.imports),
            Feature::Export(matcher) => match_string(matcher, &scope_features.exports),
            Feature::FunctionName(matcher) => match_string(matcher, &scope_features.function_names),
            Feature::String(matcher) => match_string(matcher, &scope_features.strings),
            Feature::Substring(matcher) => match_substring(matcher, &scope_features.strings),
            Feature::Section(matcher) => match_string(matcher, &scope_features.sections),
            Feature::Namespace(matcher) => match_string(matcher, &scope_features.namespaces),
            Feature::Class(matcher) => match_string(matcher, &scope_features.classes),

            Feature::Number(num_matcher) => scope_features.numbers.contains(&num_matcher.value),

            Feature::Offset(offset_matcher) => scope_features.offsets.contains(&offset_matcher.value),

            Feature::Bytes(pattern) => {
                scope_features.bytes_sequences.iter().any(|seq| seq == pattern)
            }

            Feature::Mnemonic(mnem) => scope_features.mnemonics.contains_key(mnem),

            Feature::Operand(op_matcher) => {
                scope_features.operands.iter().any(|(idx, num, offset)| {
                    if *idx != op_matcher.index {
                        return false;
                    }
                    match &op_matcher.value {
                        crate::rule::OperandValue::Number(n) => {
                            num.map(|v| v == n.value).unwrap_or(false)
                        }
                        crate::rule::OperandValue::Offset(o) => {
                            offset.map(|v| v == o.value).unwrap_or(false)
                        }
                    }
                })
            }

            Feature::Characteristic(char_type) => {
                scope_features.characteristics.contains(char_type)
            }

            Feature::Property(prop) => {
                scope_features.properties.iter().any(|(name, access)| {
                    name == &prop.name && (prop.access == crate::rule::PropertyAccess::Any || *access == prop.access)
                })
            }

            Feature::ComClass(name) => {
                // Match COM class GUID against extracted classes
                scope_features.classes.iter().any(|c| c.eq_ignore_ascii_case(name))
            }
            Feature::ComInterface(name) => {
                // Match COM interface GUID against extracted classes
                scope_features.classes.iter().any(|c| c.eq_ignore_ascii_case(name))
            }

            Feature::Os(os) => *os == OsType::Any || *os == all_features.os,
            Feature::Arch(arch) => *arch == ArchType::Any || *arch == all_features.arch,
            Feature::Format(fmt) => *fmt == FormatType::Any || *fmt == all_features.format,

            Feature::BasicBlockFeature => {
                // BasicBlockFeature matches if there's at least one basic block
                scope_features.basic_block_count > 0
            }
        }
    }
}

fn match_string(matcher: &StringMatcher, strings: &HashSet<String>) -> bool {
    match matcher {
        StringMatcher::Exact(pattern) => {
            // Case-insensitive comparison for API names
            strings.iter().any(|s| s.eq_ignore_ascii_case(pattern))
        }
        StringMatcher::Regex(compiled) => strings.iter().any(|s| compiled.is_match(s)),
    }
}

fn match_substring(matcher: &StringMatcher, strings: &HashSet<String>) -> bool {
    match matcher {
        StringMatcher::Exact(pattern) => {
            let pattern_lower = pattern.to_lowercase();
            strings.iter().any(|s| s.to_lowercase().contains(&pattern_lower))
        }
        StringMatcher::Regex(compiled) => strings.iter().any(|s| compiled.is_match(s)),
    }
}

fn count_string_matches(
    matcher: &StringMatcher,
    strings: &HashSet<String>,
) -> usize {
    match matcher {
        StringMatcher::Exact(pattern) => {
            strings.iter().filter(|s| s.eq_ignore_ascii_case(pattern)).count()
        }
        StringMatcher::Regex(compiled) => strings.iter().filter(|s| compiled.is_match(s)).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::parse_rule;

    #[test]
    fn test_simple_api_match() {
        let yaml = r#"
rule:
  meta:
    name: test api
    scopes:
      static: function
  features:
    - api: CreateFileA
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "test api");
        assert_eq!(matches[0].match_count, 1);
        assert_eq!(matches[0].locations.len(), 1);
    }

    #[test]
    fn test_case_insensitive_api_match() {
        let yaml = r#"
rule:
  meta:
    name: test api case
    scopes:
      static: function
  features:
    - api: createfilea
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_and_operator() {
        let yaml = r#"
rule:
  meta:
    name: test and
    scopes:
      static: function
  features:
    - and:
      - api: CreateFileA
      - api: WriteFile
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with both APIs present
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileA".to_string());
        func.features.apis.insert("WriteFile".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);

        // Test with only one API present
        let mut features2 = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func2 = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func2.features.apis.insert("CreateFileA".to_string());
        features2.functions.insert(crate::feature::Address(0x1000), func2);

        let matches2 = engine.match_all(&features2);
        assert_eq!(matches2.len(), 0);
    }

    #[test]
    fn test_or_operator() {
        let yaml = r#"
rule:
  meta:
    name: test or
    scopes:
      static: function
  features:
    - or:
      - api: CreateFileA
      - api: CreateFileW
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with one API present
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("CreateFileW".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_count_constraint() {
        let yaml = r#"
rule:
  meta:
    name: test count
    scopes:
      static: function
  features:
    - count(mnemonic(push)): (3, 10)
"#;
        let rule = parse_rule(yaml).unwrap();
        let engine = MatchEngine::new(vec![rule]);

        // Test with 5 push instructions
        let mut features = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.mnemonics.insert("push".to_string(), 5);
        features.functions.insert(crate::feature::Address(0x1000), func);

        let matches = engine.match_all(&features);
        assert_eq!(matches.len(), 1);

        // Test with 2 push instructions (below range)
        let mut features2 = ExtractedFeatures::new(OsType::Windows, ArchType::I386, FormatType::Pe);
        let mut func2 = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func2.features.mnemonics.insert("push".to_string(), 2);
        features2.functions.insert(crate::feature::Address(0x1000), func2);

        let matches2 = engine.match_all(&features2);
        assert_eq!(matches2.len(), 0);
    }

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
        let mut func = crate::feature::FunctionFeatures::new(crate::feature::Address(0x1000));
        func.features.apis.insert("TestAPI".to_string());
        features.functions.insert(crate::feature::Address(0x1000), func);

        let parallel_matches = engine.match_all(&features);
        let sequential_matches = engine.match_all_sequential(&features);

        assert_eq!(parallel_matches.len(), sequential_matches.len());
    }
}
