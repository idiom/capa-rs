//! JSON output format
//!
//! Compatible with ida_claude_rev2 integration.

use crate::matcher::RuleMatch;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Timing information for benchmarking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingInfo {
    /// Time to load rules (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_ms: Option<u64>,
    /// Time to extract features (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extraction_ms: Option<u64>,
    /// Time to match rules (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matching_ms: Option<u64>,
    /// Total time (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<u64>,
}

/// Sample hash information (md5, sha1, sha256)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleInfo {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub path: String,
}

/// Main output structure matching ida_claude_rev2 requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapaOutput {
    /// Number of matched rules
    pub matched_rules: usize,
    /// Total number of rules evaluated
    pub total_rules: usize,
    /// Sample information (hashes, path)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample: Option<SampleInfo>,
    /// List of matched capabilities
    pub capabilities: Vec<Capability>,
    /// All unique MITRE ATT&CK technique IDs
    pub mitre_attack: Vec<String>,
    /// Rules grouped by namespace
    pub namespaces: HashMap<String, Vec<String>>,
    /// Timing information for benchmarking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingInfo>,
}

/// Single matched capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Rule name
    pub name: String,
    /// Rule namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Number of match locations
    pub matches: usize,
    /// Match location addresses
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    /// Function names where capability was found (for .NET and symbolic binaries)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub function_names: Vec<String>,
    /// ATT&CK technique IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<Vec<String>>,
}

impl CapaOutput {
    /// Create output from match results
    pub fn from_matches(matches: Vec<RuleMatch>, total_rules: usize) -> Self {
        // Filter out library rules, internal rules, and meta "runtime" rules
        let visible_matches: Vec<_> = matches.iter().filter(|m| {
            // Skip library rules
            if m.is_lib {
                return false;
            }
            // Skip internal rules (e.g., "(internal) .NET file limitation")
            if let Some(ref ns) = m.namespace {
                if ns.starts_with("internal/") {
                    return false;
                }
                // Skip generic runtime detection rules (noisy, match every function)
                if ns == "runtime/dotnet" && m.name == "compiled to the .NET platform" {
                    return false;
                }
            }
            true
        }).collect();

        // Collect all ATT&CK IDs
        let mut attack_ids: HashSet<String> = HashSet::new();
        for m in &visible_matches {
            for id in &m.attack {
                // Extract just the technique ID from strings like "Execution::... [T1059]"
                if let Some(extracted) = extract_technique_id(id) {
                    attack_ids.insert(extracted);
                }
            }
        }

        // Build capabilities list
        let capabilities: Vec<Capability> = visible_matches
            .iter()
            .map(|m| Capability {
                name: m.name.clone(),
                namespace: m.namespace.clone(),
                matches: m.match_count,
                locations: m.locations.iter().map(|a| {
                    // Address 0 indicates file-scope match (no specific location)
                    if a.0 == 0 {
                        "file".to_string()
                    } else {
                        format!("{}", a)
                    }
                }).collect(),
                function_names: m.function_names.clone(),
                attack: if m.attack.is_empty() {
                    None
                } else {
                    Some(m.attack.iter().filter_map(|s| extract_technique_id(s)).collect())
                },
            })
            .collect();

        // Group by namespace
        let mut namespaces: HashMap<String, Vec<String>> = HashMap::new();
        for m in &visible_matches {
            let ns = m.namespace.clone().unwrap_or_else(|| "uncategorized".to_string());
            namespaces.entry(ns).or_default().push(m.name.clone());
        }

        // Sort ATT&CK IDs
        let mut mitre_attack: Vec<_> = attack_ids.into_iter().collect();
        mitre_attack.sort();

        Self {
            matched_rules: visible_matches.len(),
            total_rules,
            sample: None,
            capabilities,
            mitre_attack,
            namespaces,
            timing: None,
        }
    }

    /// Set sample information (hashes, path)
    pub fn with_sample(mut self, sample: SampleInfo) -> Self {
        self.sample = Some(sample);
        self
    }

    /// Set timing information
    pub fn with_timing(mut self, timing: TimingInfo) -> Self {
        self.timing = Some(timing);
        self
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON string
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Extract technique ID from ATT&CK string like "Execution::Command [T1059]"
fn extract_technique_id(s: &str) -> Option<String> {
    let start = s.rfind('[')?;
    let end = s.rfind(']')?;
    if end > start {
        Some(s[start + 1..end].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::Address;

    #[test]
    fn test_output_from_matches() {
        let matches = vec![
            RuleMatch {
                name: "test rule".to_string(),
                namespace: Some("test/namespace".to_string()),
                match_count: 1,
                locations: vec![Address(0x1000)],
                function_names: vec!["TestFunc".to_string()],
                attack: vec!["Execution::Command [T1059]".to_string()],
                mbc: vec![],
                is_lib: false,
            },
        ];

        let output = CapaOutput::from_matches(matches, 100);
        assert_eq!(output.matched_rules, 1);
        assert_eq!(output.total_rules, 100);
        assert_eq!(output.mitre_attack, vec!["T1059"]);
        assert_eq!(output.capabilities[0].function_names, vec!["TestFunc"]);
    }

    #[test]
    fn test_lib_rules_filtered() {
        let matches = vec![
            RuleMatch {
                name: "lib rule".to_string(),
                namespace: None,
                match_count: 1,
                locations: vec![Address(0x1000)],
                function_names: vec![],
                attack: vec![],
                mbc: vec![],
                is_lib: true, // Library rule - should be filtered
            },
            RuleMatch {
                name: "visible rule".to_string(),
                namespace: None,
                match_count: 1,
                locations: vec![Address(0x2000)],
                function_names: vec!["VisibleFunc".to_string()],
                attack: vec![],
                mbc: vec![],
                is_lib: false,
            },
        ];

        let output = CapaOutput::from_matches(matches, 100);
        assert_eq!(output.matched_rules, 1); // Only visible rule
        assert_eq!(output.capabilities[0].name, "visible rule");
    }

    #[test]
    fn test_json_serialization() {
        let output = CapaOutput {
            matched_rules: 1,
            total_rules: 100,
            sample: None,
            capabilities: vec![Capability {
                name: "test".to_string(),
                namespace: Some("test/ns".to_string()),
                matches: 1,
                locations: vec![],
                function_names: vec![],
                attack: Some(vec!["T1059".to_string()]),
            }],
            mitre_attack: vec!["T1059".to_string()],
            namespaces: HashMap::new(),
            timing: None,
        };

        let json = output.to_json().unwrap();
        assert!(json.contains("\"matched_rules\": 1"));
    }

    #[test]
    fn test_timing_info() {
        let output = CapaOutput {
            matched_rules: 1,
            total_rules: 100,
            sample: None,
            capabilities: vec![],
            mitre_attack: vec![],
            namespaces: HashMap::new(),
            timing: None,
        }.with_timing(TimingInfo {
            rules_ms: Some(100),
            extraction_ms: Some(500),
            matching_ms: Some(200),
            total_ms: Some(800),
        });

        let json = output.to_json().unwrap();
        assert!(json.contains("\"total_ms\": 800"));
    }
}
