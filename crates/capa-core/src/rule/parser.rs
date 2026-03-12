//! CAPA rule YAML parser
//!
//! Parses YAML rule files into the Rule AST.

use crate::error::{CapaError, Result};
use crate::rule::types::*;
use serde_yaml::Value;
use std::fs;
use std::path::Path;

/// Parse a single rule from YAML string
pub fn parse_rule(yaml: &str) -> Result<Rule> {
    let doc: Value = serde_yaml::from_str(yaml)?;
    parse_rule_value(&doc, None)
}

/// Parse a rule from a YAML file
pub fn parse_rule_file(path: &Path) -> Result<Rule> {
    let content = fs::read_to_string(path)?;
    let doc: Value = serde_yaml::from_str(&content)?;
    parse_rule_value(&doc, Some(path.to_string_lossy().to_string()))
}

/// Parse all rules from a directory recursively
pub fn parse_rules_directory(path: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    parse_rules_recursive(path, &mut rules)?;
    Ok(rules)
}

fn parse_rules_recursive(path: &Path, rules: &mut Vec<Rule>) -> Result<()> {
    if path.is_file() {
        if let Some(ext) = path.extension() {
            if ext == "yml" || ext == "yaml" {
                match parse_rule_file(path) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => {
                        log::warn!("Failed to parse rule {}: {}", path.display(), e);
                        eprintln!("[PARSER] Failed to parse {}: {}", path.display(), e);
                    }
                }
            }
        }
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            parse_rules_recursive(&entry.path(), rules)?;
        }
    }
    Ok(())
}

fn parse_rule_value(doc: &Value, source_path: Option<String>) -> Result<Rule> {
    let rule_obj = doc
        .get("rule")
        .ok_or_else(|| CapaError::ParseError("Missing 'rule' key".to_string()))?;

    // Parse meta block
    let meta_value = rule_obj
        .get("meta")
        .ok_or_else(|| CapaError::ParseError("Missing 'meta' block".to_string()))?;
    let meta: RuleMeta = serde_yaml::from_value(meta_value.clone())?;

    // Parse features block
    let features_value = rule_obj
        .get("features")
        .ok_or_else(|| CapaError::ParseError("Missing 'features' block".to_string()))?;
    let features = parse_features(features_value)?;

    Ok(Rule {
        meta,
        features,
        source_path,
    })
}

fn parse_features(value: &Value) -> Result<FeatureNode> {
    match value {
        Value::Sequence(seq) => {
            // Implicit AND of all items
            let children: Result<Vec<_>> = seq.iter().map(parse_feature_node).collect();
            Ok(FeatureNode::And(children?))
        }
        Value::Mapping(_) => parse_feature_node(value),
        _ => Err(CapaError::SyntaxError(format!(
            "Expected sequence or mapping for features, got {:?}",
            value
        ))),
    }
}

/// Parse the child of a `not` node
/// Handles both single child and sequence with description + child
fn parse_not_child(value: &Value) -> Result<FeatureNode> {
    match value {
        // Single child (mapping or string)
        Value::Mapping(_) | Value::String(_) => parse_feature_node(value),
        // Sequence: may contain description + actual child
        Value::Sequence(seq) => {
            // Filter out description nodes, find the actual logic node
            let logic_nodes: Vec<&Value> = seq
                .iter()
                .filter(|v| {
                    // Keep nodes that are NOT just descriptions
                    if let Value::Mapping(map) = v {
                        !map.contains_key("description")
                            || map.len() > 1
                    } else {
                        true
                    }
                })
                .collect();

            if logic_nodes.len() == 1 {
                parse_feature_node(logic_nodes[0])
            } else if logic_nodes.is_empty() {
                Err(CapaError::SyntaxError(
                    "not: clause has no logic nodes (only descriptions)".to_string(),
                ))
            } else {
                // Multiple logic nodes - wrap in implicit And
                let children: Result<Vec<FeatureNode>> =
                    logic_nodes.iter().map(|v| parse_feature_node(v)).collect();
                Ok(FeatureNode::And(children?))
            }
        }
        _ => Err(CapaError::SyntaxError(format!(
            "Unexpected not child type: {:?}",
            value
        ))),
    }
}

fn parse_feature_node(value: &Value) -> Result<FeatureNode> {
    match value {
        Value::Mapping(map) => {
            // Handle mappings with 2 keys: feature + description
            // e.g., { string: /foo/i, description: "bar" }
            if map.len() == 2 && map.contains_key("description") {
                // Find the non-description key
                for (key, val) in map.iter() {
                    let key_str = key.as_str().ok_or_else(|| {
                        CapaError::SyntaxError("Feature key must be string".to_string())
                    })?;
                    if key_str != "description" {
                        // Parse the feature, ignore the description (it's metadata only)
                        return parse_feature_by_key(key_str, val);
                    }
                }
            }

            if map.len() != 1 {
                return Err(CapaError::SyntaxError(format!(
                    "Feature node must have exactly one key, got {}",
                    map.len()
                )));
            }

            let (key, val) = map.iter().next().unwrap();
            let key_str = key
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("Feature key must be string".to_string()))?;

            parse_feature_by_key(key_str, val)
        }
        Value::String(s) => {
            // Simple feature like "- api: CreateFile"
            parse_simple_feature(s)
        }
        _ => Err(CapaError::SyntaxError(format!(
            "Unexpected feature node type: {:?}",
            value
        ))),
    }
}

fn parse_feature_by_key(key: &str, value: &Value) -> Result<FeatureNode> {
    match key {
        // Boolean operators
        "and" => parse_boolean_children(value).map(FeatureNode::And),
        "or" => parse_boolean_children(value).map(FeatureNode::Or),
        "not" => {
            // not can have a single child or a sequence with description + child
            // e.g., "not: - description: x - or: ..."
            parse_not_child(value).map(|n| FeatureNode::Not(Box::new(n)))
        }
        "optional" => parse_boolean_children(value).map(FeatureNode::Optional),

        // N or more/fewer
        k if k.ends_with(" or more") => {
            let n = k
                .trim_end_matches(" or more")
                .parse::<usize>()
                .map_err(|_| CapaError::SyntaxError(format!("Invalid count: {}", k)))?;
            parse_boolean_children(value).map(|children| FeatureNode::NOrMore(n, children))
        }

        // Count operator
        k if k.starts_with("count(") && k.ends_with(")") => {
            let inner = &k[6..k.len() - 1];
            let feature_node = parse_feature_from_count_spec(inner)?;
            let constraint = parse_count_constraint(value)?;
            Ok(FeatureNode::Count(Box::new(feature_node), constraint))
        }

        // Match operator
        "match" => {
            let rule_name = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("match value must be string".to_string()))?;
            Ok(FeatureNode::Match(rule_name.to_string()))
        }

        // Description
        "description" => {
            let desc = value
                .as_str()
                .ok_or_else(|| {
                    CapaError::SyntaxError("description value must be string".to_string())
                })?
                .to_string();
            // Description wraps the next sibling - handled at parent level
            Ok(FeatureNode::Description(desc, Box::new(FeatureNode::And(vec![]))))
        }

        // Leaf features
        "api" => parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Api(m))),
        "import" => parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Import(m))),
        "export" => parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Export(m))),
        "function-name" => {
            parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::FunctionName(m)))
        }
        "string" => parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::String(m))),
        "substring" => {
            parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Substring(m)))
        }
        "section" => {
            parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Section(m)))
        }
        "namespace" => {
            parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Namespace(m)))
        }
        "class" => parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Class(m))),

        "number" => parse_number_feature(value).map(|m| FeatureNode::Feature(Feature::Number(m))),
        "offset" => parse_offset_feature(value).map(|m| FeatureNode::Feature(Feature::Offset(m))),

        "bytes" => parse_bytes_feature(value).map(|b| FeatureNode::Feature(Feature::Bytes(b))),

        "mnemonic" => {
            let mnem = value
                .as_str()
                .ok_or_else(|| {
                    CapaError::SyntaxError("mnemonic value must be string".to_string())
                })?
                .to_string();
            Ok(FeatureNode::Feature(Feature::Mnemonic(mnem)))
        }

        // Operand with index: operand[i].number or operand[i].offset
        k if k.starts_with("operand[") && k.ends_with("].number") => {
            let idx_str = &k[8..k.len() - 8]; // "operand[" = 8 chars, "].number" = 8 chars
            let index = idx_str
                .parse::<usize>()
                .map_err(|_| CapaError::SyntaxError(format!("Invalid operand index: {}", k)))?;
            let operand = parse_operand_number_feature(index, value)?;
            Ok(FeatureNode::Feature(Feature::Operand(operand)))
        }
        k if k.starts_with("operand[") && k.ends_with("].offset") => {
            let idx_str = &k[8..k.len() - 8]; // "operand[" = 8 chars, "].offset" = 8 chars
            let index = idx_str
                .parse::<usize>()
                .map_err(|_| CapaError::SyntaxError(format!("Invalid operand index: {}", k)))?;
            let operand = parse_operand_offset_feature(index, value)?;
            Ok(FeatureNode::Feature(Feature::Operand(operand)))
        }

        "characteristic" => {
            let char_str = value.as_str().ok_or_else(|| {
                CapaError::SyntaxError("characteristic value must be string".to_string())
            })?;
            // Strip description suffix "= comment" if present
            // e.g., "indirect call = call entry point"
            let char_name = if let Some(eq_idx) = char_str.find(" = ") {
                &char_str[..eq_idx]
            } else {
                char_str
            };
            let char_type = CharacteristicType::from_str(char_name).ok_or_else(|| {
                CapaError::SyntaxError(format!("Unknown characteristic: {}", char_name))
            })?;
            Ok(FeatureNode::Feature(Feature::Characteristic(char_type)))
        }

        "property" => {
            let name = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("property value must be string".to_string()))?
                .to_string();
            Ok(FeatureNode::Feature(Feature::Property(PropertyMatcher {
                name,
                access: PropertyAccess::Any,
            })))
        }
        "property/read" => {
            let name = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("property value must be string".to_string()))?
                .to_string();
            Ok(FeatureNode::Feature(Feature::Property(PropertyMatcher {
                name,
                access: PropertyAccess::Read,
            })))
        }
        "property/write" => {
            let name = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("property value must be string".to_string()))?
                .to_string();
            Ok(FeatureNode::Feature(Feature::Property(PropertyMatcher {
                name,
                access: PropertyAccess::Write,
            })))
        }

        "os" => {
            let os_str = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("os value must be string".to_string()))?;
            let os = OsType::from_str(os_str)
                .ok_or_else(|| CapaError::SyntaxError(format!("Unknown OS: {}", os_str)))?;
            Ok(FeatureNode::Feature(Feature::Os(os)))
        }

        "arch" => {
            let arch_str = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("arch value must be string".to_string()))?;
            let arch = ArchType::from_str(arch_str)
                .ok_or_else(|| CapaError::SyntaxError(format!("Unknown arch: {}", arch_str)))?;
            Ok(FeatureNode::Feature(Feature::Arch(arch)))
        }

        "format" => {
            let fmt_str = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("format value must be string".to_string()))?;
            let fmt = FormatType::from_str(fmt_str)
                .ok_or_else(|| CapaError::SyntaxError(format!("Unknown format: {}", fmt_str)))?;
            Ok(FeatureNode::Feature(Feature::Format(fmt)))
        }

        // Subscopes: instruction, basic block, function, call (dynamic)
        "instruction" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::Instruction(children))
        }
        "basic block" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::BasicBlock(children))
        }
        "function" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::Function(children))
        }
        // Dynamic analysis scope - treat like basic block for static analysis
        "call" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::BasicBlock(children))
        }
        // Thread scope - treat like function for static analysis
        "thread" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::Function(children))
        }
        // Process scope - treat like file for static analysis
        "process" => {
            let children = parse_boolean_children(value)?;
            Ok(FeatureNode::And(children))
        }

        // COM class GUID feature
        "com/class" => {
            parse_string_feature(value).map(|m| FeatureNode::Feature(Feature::Class(m)))
        }
        // COM interface GUID feature
        "com/interface" => {
            let guid = value
                .as_str()
                .ok_or_else(|| CapaError::SyntaxError("com/interface value must be string".to_string()))?
                .to_string();
            Ok(FeatureNode::Feature(Feature::ComInterface(guid)))
        }

        _ => Err(CapaError::SyntaxError(format!("Unknown feature key: {}", key))),
    }
}

fn parse_boolean_children(value: &Value) -> Result<Vec<FeatureNode>> {
    match value {
        Value::Sequence(seq) => {
            // Parse all children, filtering out standalone descriptions
            // (descriptions that only contain metadata, not logic)
            seq.iter()
                .filter(|v| {
                    // Filter out mappings that are ONLY { description: "..." }
                    if let Value::Mapping(map) = v {
                        if map.len() == 1 && map.contains_key("description") {
                            return false; // Skip standalone description
                        }
                    }
                    true
                })
                .map(parse_feature_node)
                .collect()
        }
        _ => Err(CapaError::SyntaxError(
            "Boolean operator requires sequence".to_string(),
        )),
    }
}

fn parse_string_feature(value: &Value) -> Result<StringMatcher> {
    let s = value
        .as_str()
        .ok_or_else(|| CapaError::SyntaxError("String feature value must be string".to_string()))?;

    // Check for regex pattern /pattern/flags
    if s.starts_with('/') {
        // Find closing slash (handle escaped slashes)
        let mut end_idx = None;
        let chars: Vec<char> = s.chars().collect();
        for i in 1..chars.len() {
            if chars[i] == '/' && (i == 0 || chars[i - 1] != '\\') {
                end_idx = Some(i);
            }
        }

        if let Some(end) = end_idx {
            let pattern = &s[1..end];
            let flags = &s[end + 1..];
            let case_insensitive = flags.contains('i');

            let compiled = CompiledRegex::new(pattern, case_insensitive).map_err(|e| {
                CapaError::RegexError {
                    pattern: pattern.to_string(),
                    source: e,
                }
            })?;
            return Ok(StringMatcher::Regex(compiled));
        }
    }

    Ok(StringMatcher::Exact(s.to_string()))
}

fn parse_number_feature(value: &Value) -> Result<NumberMatcher> {
    match value {
        Value::Number(n) => {
            // Try i64 first, then u64 (cast to i64 for large values)
            let val = n
                .as_i64()
                .or_else(|| n.as_u64().map(|u| u as i64))
                .ok_or_else(|| CapaError::SyntaxError("Invalid number".to_string()))?;
            Ok(NumberMatcher {
                value: val,
                description: None,
            })
        }
        Value::String(s) => {
            // Parse "0x40 = PAGE_EXECUTE_READWRITE" format
            let parts: Vec<&str> = s.splitn(2, '=').collect();
            let num_str = parts[0].trim();
            let description = parts.get(1).map(|d| d.trim().to_string());

            let value = parse_number_string(num_str)?;
            Ok(NumberMatcher { value, description })
        }
        _ => Err(CapaError::SyntaxError(
            "Number feature must be number or string".to_string(),
        )),
    }
}

fn parse_number_string(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        // Parse as u64 first to handle large values like 0xFFFFFFFFFFFFFFFF
        // Then reinterpret as i64 (two's complement)
        u64::from_str_radix(&s[2..], 16)
            .map(|v| v as i64)
            .map_err(|_| CapaError::SyntaxError(format!("Invalid hex number: {}", s)))
    } else if s.starts_with("0o") || s.starts_with("0O") {
        i64::from_str_radix(&s[2..], 8)
            .map_err(|_| CapaError::SyntaxError(format!("Invalid octal number: {}", s)))
    } else if s.starts_with('-') {
        s.parse::<i64>()
            .map_err(|_| CapaError::SyntaxError(format!("Invalid number: {}", s)))
    } else {
        // Try i64 first, then u64 for large positive values
        s.parse::<i64>()
            .or_else(|_| s.parse::<u64>().map(|v| v as i64))
            .map_err(|_| CapaError::SyntaxError(format!("Invalid number: {}", s)))
    }
}

fn parse_offset_feature(value: &Value) -> Result<OffsetMatcher> {
    match value {
        Value::Number(n) => {
            let val = n
                .as_i64()
                .ok_or_else(|| CapaError::SyntaxError("Invalid offset".to_string()))?;
            Ok(OffsetMatcher {
                value: val,
                arch: None,
                description: None,
            })
        }
        Value::String(s) => {
            let parts: Vec<&str> = s.splitn(2, '=').collect();
            let num_str = parts[0].trim();
            let description = parts.get(1).map(|d| d.trim().to_string());
            let value = parse_number_string(num_str)?;
            Ok(OffsetMatcher {
                value,
                arch: None,
                description,
            })
        }
        _ => Err(CapaError::SyntaxError(
            "Offset feature must be number or string".to_string(),
        )),
    }
}

fn parse_bytes_feature(value: &Value) -> Result<Vec<u8>> {
    let s = value
        .as_str()
        .ok_or_else(|| CapaError::SyntaxError("Bytes feature must be string".to_string()))?;

    // Strip description suffix "= comment" if present
    // e.g., "00 00 00 00 96 30 07 77 = crc32_tab"
    let hex_part = if let Some(eq_idx) = s.find(" = ") {
        &s[..eq_idx]
    } else {
        s
    };

    // Parse hex string like "4D 5A" or "4D5A"
    // Also support wildcards like "??" which we'll skip during matching
    let hex_str: String = hex_part.chars().filter(|c| !c.is_whitespace()).collect();
    if hex_str.len() % 2 != 0 {
        return Err(CapaError::SyntaxError(
            "Bytes hex string must have even length".to_string(),
        ));
    }

    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i + 2];
        // Handle wildcard bytes (e.g., "??")
        if byte_str == "??" {
            bytes.push(0x00); // Placeholder for wildcard - TODO: proper wildcard support
        } else {
            let byte = u8::from_str_radix(byte_str, 16)
                .map_err(|_| CapaError::SyntaxError(format!("Invalid hex byte: {}", byte_str)))?;
            bytes.push(byte);
        }
    }

    if bytes.len() > 0x100 {
        return Err(CapaError::SyntaxError(
            "Bytes pattern exceeds maximum length (0x100)".to_string(),
        ));
    }

    Ok(bytes)
}

fn parse_operand_number_feature(index: usize, value: &Value) -> Result<OperandMatcher> {
    match value {
        Value::Number(n) => {
            let val = n
                .as_i64()
                .ok_or_else(|| CapaError::SyntaxError("Invalid operand value".to_string()))?;
            Ok(OperandMatcher {
                index,
                value: OperandValue::Number(NumberMatcher {
                    value: val,
                    description: None,
                }),
            })
        }
        Value::String(s) => {
            // Could be number with description
            let value = parse_number_string(s.split('=').next().unwrap_or(s).trim())?;
            let description = s.split('=').nth(1).map(|d| d.trim().to_string());
            Ok(OperandMatcher {
                index,
                value: OperandValue::Number(NumberMatcher { value, description }),
            })
        }
        _ => Err(CapaError::SyntaxError(
            "Operand value must be number or string".to_string(),
        )),
    }
}

fn parse_operand_offset_feature(index: usize, value: &Value) -> Result<OperandMatcher> {
    match value {
        Value::Number(n) => {
            let val = n
                .as_i64()
                .ok_or_else(|| CapaError::SyntaxError("Invalid operand offset".to_string()))?;
            Ok(OperandMatcher {
                index,
                value: OperandValue::Offset(OffsetMatcher {
                    value: val,
                    arch: None,
                    description: None,
                }),
            })
        }
        Value::String(s) => {
            // Could be offset with description
            let value = parse_number_string(s.split('=').next().unwrap_or(s).trim())?;
            let description = s.split('=').nth(1).map(|d| d.trim().to_string());
            Ok(OperandMatcher {
                index,
                value: OperandValue::Offset(OffsetMatcher {
                    value,
                    arch: None,
                    description,
                }),
            })
        }
        _ => Err(CapaError::SyntaxError(
            "Operand offset must be number or string".to_string(),
        )),
    }
}

fn parse_count_constraint(value: &Value) -> Result<CountConstraint> {
    match value {
        Value::Number(n) => {
            let count = n
                .as_u64()
                .ok_or_else(|| CapaError::SyntaxError("Count must be positive integer".to_string()))?
                as usize;
            Ok(CountConstraint::Exact(count))
        }
        Value::String(s) => {
            let s = s.trim();
            if s.ends_with(" or more") {
                let n = s
                    .trim_end_matches(" or more")
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CapaError::SyntaxError(format!("Invalid count: {}", s)))?;
                Ok(CountConstraint::OrMore(n))
            } else if s.ends_with(" or fewer") {
                let n = s
                    .trim_end_matches(" or fewer")
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CapaError::SyntaxError(format!("Invalid count: {}", s)))?;
                Ok(CountConstraint::OrFewer(n))
            } else if s.starts_with('(') && s.ends_with(')') {
                // Range (min, max)
                let inner = &s[1..s.len() - 1];
                let parts: Vec<&str> = inner.split(',').collect();
                if parts.len() != 2 {
                    return Err(CapaError::SyntaxError(format!("Invalid range: {}", s)));
                }
                let min = parts[0]
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CapaError::SyntaxError(format!("Invalid range min: {}", s)))?;
                let max = parts[1]
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CapaError::SyntaxError(format!("Invalid range max: {}", s)))?;
                Ok(CountConstraint::Range(min, max))
            } else {
                let n = s
                    .parse::<usize>()
                    .map_err(|_| CapaError::SyntaxError(format!("Invalid count: {}", s)))?;
                Ok(CountConstraint::Exact(n))
            }
        }
        _ => Err(CapaError::SyntaxError(
            "Count constraint must be number or string".to_string(),
        )),
    }
}

fn parse_feature_from_count_spec(spec: &str) -> Result<FeatureNode> {
    // Parse feature specification like "api(CreateFile)", "characteristic(nzxor)", or "basic block"
    let paren_idx = spec.find('(');
    if let Some(idx) = paren_idx {
        if !spec.ends_with(')') {
            return Err(CapaError::SyntaxError(format!(
                "Invalid count feature spec: {}",
                spec
            )));
        }
        let feature_type = &spec[..idx];
        let feature_value = &spec[idx + 1..spec.len() - 1];

        match feature_type {
            "api" => Ok(FeatureNode::Feature(Feature::Api(StringMatcher::Exact(
                feature_value.to_string(),
            )))),
            "string" => Ok(FeatureNode::Feature(Feature::String(StringMatcher::Exact(
                feature_value.to_string(),
            )))),
            "import" => Ok(FeatureNode::Feature(Feature::Import(StringMatcher::Exact(
                feature_value.to_string(),
            )))),
            "export" => Ok(FeatureNode::Feature(Feature::Export(StringMatcher::Exact(
                feature_value.to_string(),
            )))),
            "characteristic" => {
                let char_type = CharacteristicType::from_str(feature_value).ok_or_else(|| {
                    CapaError::SyntaxError(format!("Unknown characteristic: {}", feature_value))
                })?;
                Ok(FeatureNode::Feature(Feature::Characteristic(char_type)))
            }
            "mnemonic" => Ok(FeatureNode::Feature(Feature::Mnemonic(
                feature_value.to_string(),
            ))),
            "number" => {
                // Handle "0x40 = description" format
                let (num_str, description) = if let Some(eq_idx) = feature_value.find(" = ") {
                    (&feature_value[..eq_idx], Some(feature_value[eq_idx + 3..].to_string()))
                } else {
                    (feature_value, None)
                };
                let value = parse_number_string(num_str)?;
                Ok(FeatureNode::Feature(Feature::Number(NumberMatcher {
                    value,
                    description,
                })))
            }
            "offset" => {
                // Handle "0x10 = description" format
                let (num_str, description) = if let Some(eq_idx) = feature_value.find(" = ") {
                    (&feature_value[..eq_idx], Some(feature_value[eq_idx + 3..].to_string()))
                } else {
                    (feature_value, None)
                };
                let value = parse_number_string(num_str)?;
                Ok(FeatureNode::Feature(Feature::Offset(OffsetMatcher {
                    value,
                    arch: None,
                    description,
                })))
            }
            "section" => Ok(FeatureNode::Feature(Feature::Section(StringMatcher::Exact(
                feature_value.to_string(),
            )))),
            // Match another rule (for count(match(rule_name)))
            "match" => Ok(FeatureNode::Match(feature_value.to_string())),
            _ => Err(CapaError::SyntaxError(format!(
                "Unknown count feature type: {}",
                feature_type
            ))),
        }
    } else {
        // Feature type without value (e.g., count(basic block), count(string))
        match spec {
            "basic block" | "basic blocks" => Ok(FeatureNode::Feature(Feature::BasicBlockFeature)),
            "string" => Ok(FeatureNode::Feature(Feature::String(StringMatcher::Exact(
                String::new(), // Empty matcher means match any string
            )))),
            _ => Err(CapaError::SyntaxError(format!(
                "Unknown count feature: {}",
                spec
            ))),
        }
    }
}

fn parse_simple_feature(s: &str) -> Result<FeatureNode> {
    // Handle inline feature like "api: CreateFile"
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(CapaError::SyntaxError(format!(
            "Invalid simple feature format: {}",
            s
        )));
    }

    let key = parts[0].trim();
    let value_str = parts[1].trim();
    let value = Value::String(value_str.to_string());

    parse_feature_by_key(key, &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
rule:
  meta:
    name: test rule
    namespace: test/example
    scopes:
      static: function
  features:
    - api: CreateFileA
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.meta.name, "test rule");
        assert_eq!(rule.meta.namespace, Some("test/example".to_string()));
    }

    #[test]
    fn test_parse_boolean_operators() {
        let yaml = r#"
rule:
  meta:
    name: boolean test
  features:
    - and:
      - api: CreateFileA
      - or:
        - api: WriteFile
        - api: WriteFileEx
"#;
        let rule = parse_rule(yaml).unwrap();
        match &rule.features {
            FeatureNode::And(children) => {
                assert_eq!(children.len(), 1);
            }
            _ => panic!("Expected And node"),
        }
    }

    #[test]
    fn test_parse_number_with_description() {
        let yaml = r#"
rule:
  meta:
    name: number test
  features:
    - number: 0x40 = PAGE_EXECUTE_READWRITE
"#;
        let rule = parse_rule(yaml).unwrap();
        // Just verify it parses
        assert_eq!(rule.meta.name, "number test");
    }

    #[test]
    fn test_parse_regex_pattern() {
        let yaml = r#"
rule:
  meta:
    name: regex test
  features:
    - string: /password/i
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.meta.name, "regex test");
    }

    #[test]
    fn test_parse_count_constraint() {
        let yaml = r#"
rule:
  meta:
    name: count test
  features:
    - count(api(SetHandleInformation)): 2 or more
"#;
        let rule = parse_rule(yaml).unwrap();
        assert_eq!(rule.meta.name, "count test");
    }
}
