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
    pub attack: Option<Vec<AttackEntry>>,
    /// Malware Behavior Catalog entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbc: Option<Vec<MbcEntry>>,
    /// Reference URLs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
}

/// Structured ATT&CK entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEntry {
    /// Technique ID (e.g., "T1027", "T1547.001")
    pub id: String,
    /// Tactic name (e.g., "Defense Evasion")
    pub tactic: String,
    /// Technique name (e.g., "Obfuscated Files or Information")
    pub technique: String,
    /// Subtechnique name (e.g., "Registry Run Keys / Startup Folder")
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subtechnique: String,
}

/// Structured MBC entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbcEntry {
    /// MBC ID (e.g., "C0027.009")
    pub id: String,
    /// Objective (e.g., "Cryptography")
    pub objective: String,
    /// Behavior (e.g., "Encrypt Data")
    pub behavior: String,
    /// Method (e.g., "RC4")
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
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
                if let Some(extracted) = extract_id(id) {
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
                    Some(m.attack.iter().filter_map(|s| parse_attack_entry(s)).collect())
                },
                mbc: if m.mbc.is_empty() {
                    None
                } else {
                    Some(m.mbc.iter().filter_map(|s| parse_mbc_entry(s)).collect())
                },
                references: if m.references.is_empty() {
                    None
                } else {
                    Some(m.references.clone())
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

/// Extract technique ID from a bracketed string like "Execution::Command [T1059]"
fn extract_id(s: &str) -> Option<String> {
    let start = s.rfind('[')?;
    let end = s.rfind(']')?;
    if end > start {
        Some(s[start + 1..end].to_string())
    } else {
        None
    }
}

/// Parse ATT&CK string like "Defense Evasion::Obfuscated Files or Information [T1027]"
/// or "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
fn parse_attack_entry(s: &str) -> Option<AttackEntry> {
    let id = extract_id(s)?;
    // Strip the bracketed ID to get the hierarchy
    let bracket_start = s.rfind('[')?;
    let hierarchy = s[..bracket_start].trim();
    let parts: Vec<&str> = hierarchy.split("::").collect();

    Some(AttackEntry {
        id,
        tactic: parts.first().unwrap_or(&"").to_string(),
        technique: parts.get(1).unwrap_or(&"").to_string(),
        subtechnique: parts.get(2).unwrap_or(&"").to_string(),
    })
}

/// Parse MBC string like "Cryptography::Encrypt Data::RC4 [C0027.009]"
/// or "Defense Evasion::Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]"
fn parse_mbc_entry(s: &str) -> Option<MbcEntry> {
    let id = extract_id(s)?;
    let bracket_start = s.rfind('[')?;
    let hierarchy = s[..bracket_start].trim();
    let parts: Vec<&str> = hierarchy.split("::").collect();

    Some(MbcEntry {
        id,
        objective: parts.first().unwrap_or(&"").to_string(),
        behavior: parts.get(1).unwrap_or(&"").to_string(),
        method: parts.get(2).unwrap_or(&"").to_string(),
    })
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
                mbc: vec!["Cryptography::Encrypt Data::RC4 [C0027.009]".to_string()],
                references: vec!["https://example.com".to_string()],
                is_lib: false,
            },
        ];

        let output = CapaOutput::from_matches(matches, 100);
        assert_eq!(output.matched_rules, 1);
        assert_eq!(output.total_rules, 100);
        assert_eq!(output.mitre_attack, vec!["T1059"]);
        assert_eq!(output.capabilities[0].function_names, vec!["TestFunc"]);

        // Verify structured ATT&CK entry
        let attack = output.capabilities[0].attack.as_ref().unwrap();
        assert_eq!(attack[0].id, "T1059");
        assert_eq!(attack[0].tactic, "Execution");
        assert_eq!(attack[0].technique, "Command");

        // Verify structured MBC entry
        let mbc = output.capabilities[0].mbc.as_ref().unwrap();
        assert_eq!(mbc[0].id, "C0027.009");
        assert_eq!(mbc[0].objective, "Cryptography");
        assert_eq!(mbc[0].behavior, "Encrypt Data");
        assert_eq!(mbc[0].method, "RC4");

        // Verify references
        let refs = output.capabilities[0].references.as_ref().unwrap();
        assert_eq!(refs[0], "https://example.com");
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
                references: vec![],
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
                references: vec![],
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
                attack: Some(vec![AttackEntry {
                    id: "T1059".to_string(),
                    tactic: "Execution".to_string(),
                    technique: "Command".to_string(),
                    subtechnique: String::new(),
                }]),
                mbc: None,
                references: None,
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
