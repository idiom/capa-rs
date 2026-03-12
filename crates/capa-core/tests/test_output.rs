// Port of applicable tests from capa/tests/test_result_document.py
// and additional output/JSON serialization tests.
//
// Tests CapaOutput creation, JSON serialization/deserialization round-trips,
// lib rule filtering, ATT&CK technique extraction, namespace aggregation,
// and timing information.

use capa_core::feature::Address;
use capa_core::matcher::RuleMatch;
use capa_core::output::{CapaOutput, TimingInfo};

// ---------- test_output_from_matches ----------

#[test]
fn test_output_from_empty_matches() {
    let output = CapaOutput::from_matches(vec![], 0);
    assert_eq!(output.matched_rules, 0);
    assert_eq!(output.total_rules, 0);
    assert!(output.capabilities.is_empty());
    assert!(output.mitre_attack.is_empty());
}

#[test]
fn test_output_from_single_match() {
    let matches = vec![RuleMatch {
        name: "test rule".to_string(),
        namespace: Some("test/namespace".to_string()),
        match_count: 1,
        locations: vec![Address(0x1000)],
        function_names: vec!["TestFunc".to_string()],
        attack: vec!["Execution::Command [T1059]".to_string()],
        mbc: vec![],
        is_lib: false,
    }];

    let output = CapaOutput::from_matches(matches, 100);
    assert_eq!(output.matched_rules, 1);
    assert_eq!(output.total_rules, 100);
    assert_eq!(output.capabilities.len(), 1);
    assert_eq!(output.capabilities[0].name, "test rule");
    assert_eq!(output.capabilities[0].namespace, Some("test/namespace".to_string()));
    assert_eq!(output.capabilities[0].function_names, vec!["TestFunc"]);
    assert_eq!(output.mitre_attack, vec!["T1059"]);
}

// ---------- test_lib_rules_filtered ----------

#[test]
fn test_lib_rules_not_in_capabilities() {
    let matches = vec![
        RuleMatch {
            name: "lib rule".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![Address(0x1000)],
            function_names: vec![],
            attack: vec![],
            mbc: vec![],
            is_lib: true,
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
    assert_eq!(output.matched_rules, 1);
    assert_eq!(output.capabilities.len(), 1);
    assert_eq!(output.capabilities[0].name, "visible rule");
}

// ---------- test_json_round_trip (port of test_result_document.py::assert_round_trip concept) ----------

#[test]
fn test_json_round_trip() {
    let matches = vec![
        RuleMatch {
            name: "test rule one".to_string(),
            namespace: Some("test/ns".to_string()),
            match_count: 2,
            locations: vec![Address(0x1000), Address(0x2000)],
            function_names: vec!["func_a".to_string(), "func_b".to_string()],
            attack: vec!["Defense Evasion::Obfuscated Files [T1027]".to_string()],
            mbc: vec!["Anti-Behavioral Analysis::Debugger Detection [B0001]".to_string()],
            is_lib: false,
        },
        RuleMatch {
            name: "test rule two".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![Address(0x3000)],
            function_names: vec![],
            attack: vec![],
            mbc: vec![],
            is_lib: false,
        },
    ];

    let output = CapaOutput::from_matches(matches, 50);

    // Serialize to JSON
    let json_str = output.to_json().expect("JSON serialization failed");

    // Deserialize back
    // Parse as Value to verify fields (skip_serializing_if means some fields are absent)
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("JSON parse failed");
    let obj = val.as_object().unwrap();

    // Verify key fields survived round-trip
    assert_eq!(obj["matched_rules"].as_u64().unwrap(), output.matched_rules as u64);
    assert_eq!(obj["total_rules"].as_u64().unwrap(), output.total_rules as u64);
    let caps = obj["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), output.capabilities.len());
    assert_eq!(caps[0]["name"].as_str().unwrap(), "test rule one");
    assert_eq!(caps[1]["name"].as_str().unwrap(), "test rule two");

    // ATT&CK IDs preserved
    let attack = obj["mitre_attack"].as_array().unwrap();
    assert_eq!(attack.len(), 1);
    assert_eq!(attack[0].as_str().unwrap(), "T1027");
}

#[test]
fn test_json_compact() {
    let matches = vec![RuleMatch {
        name: "compact test".to_string(),
        namespace: None,
        match_count: 1,
        locations: vec![Address(0x1000)],
        function_names: vec![],
        attack: vec![],
        mbc: vec![],
        is_lib: false,
    }];

    let output = CapaOutput::from_matches(matches, 10);
    let compact = output.to_json_compact().expect("compact JSON failed");
    let pretty = output.to_json().expect("pretty JSON failed");

    // Compact should be shorter (no extra whitespace/indentation)
    assert!(compact.len() < pretty.len());

    // Both should deserialize to the same Value structure
    let c: serde_json::Value = serde_json::from_str(&compact).unwrap();
    let p: serde_json::Value = serde_json::from_str(&pretty).unwrap();
    assert_eq!(c["matched_rules"], p["matched_rules"]);
    assert_eq!(
        c["capabilities"].as_array().unwrap().len(),
        p["capabilities"].as_array().unwrap().len()
    );
}

// ---------- test_multiple_attack_techniques ----------

#[test]
fn test_multiple_attack_technique_extraction() {
    let matches = vec![
        RuleMatch {
            name: "rule a".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![Address(0x1000)],
            function_names: vec![],
            attack: vec![
                "Execution::Command [T1059]".to_string(),
                "Persistence::Boot or Logon [T1547]".to_string(),
            ],
            mbc: vec![],
            is_lib: false,
        },
        RuleMatch {
            name: "rule b".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![Address(0x2000)],
            function_names: vec![],
            attack: vec!["Defense Evasion::Obfuscated Files [T1027]".to_string()],
            mbc: vec![],
            is_lib: false,
        },
    ];

    let output = CapaOutput::from_matches(matches, 10);
    assert_eq!(output.mitre_attack.len(), 3);
    assert!(output.mitre_attack.contains(&"T1027".to_string()));
    assert!(output.mitre_attack.contains(&"T1059".to_string()));
    assert!(output.mitre_attack.contains(&"T1547".to_string()));
}

// ---------- test_duplicate_attack_techniques ----------

#[test]
fn test_duplicate_attack_techniques_deduplicated() {
    let matches = vec![
        RuleMatch {
            name: "rule a".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![],
            function_names: vec![],
            attack: vec!["Execution::Command [T1059]".to_string()],
            mbc: vec![],
            is_lib: false,
        },
        RuleMatch {
            name: "rule b".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![],
            function_names: vec![],
            attack: vec!["Execution::Command [T1059]".to_string()],
            mbc: vec![],
            is_lib: false,
        },
    ];

    let output = CapaOutput::from_matches(matches, 10);
    // T1059 appears in two rules but should be deduplicated
    assert_eq!(output.mitre_attack.len(), 1);
    assert_eq!(output.mitre_attack[0], "T1059");
}

// ---------- test_namespace_aggregation ----------

#[test]
fn test_namespace_grouping() {
    let matches = vec![
        RuleMatch {
            name: "rule 1".to_string(),
            namespace: Some("anti-analysis/anti-debugging".to_string()),
            match_count: 1,
            locations: vec![],
            function_names: vec![],
            attack: vec![],
            mbc: vec![],
            is_lib: false,
        },
        RuleMatch {
            name: "rule 2".to_string(),
            namespace: Some("persistence/registry".to_string()),
            match_count: 1,
            locations: vec![],
            function_names: vec![],
            attack: vec![],
            mbc: vec![],
            is_lib: false,
        },
        RuleMatch {
            name: "rule 3".to_string(),
            namespace: None,
            match_count: 1,
            locations: vec![],
            function_names: vec![],
            attack: vec![],
            mbc: vec![],
            is_lib: false,
        },
    ];

    let output = CapaOutput::from_matches(matches, 10);
    // namespaces is HashMap<String, Vec<String>>
    assert!(output.namespaces.contains_key("anti-analysis/anti-debugging"));
    assert!(output.namespaces.contains_key("persistence/registry"));
    assert_eq!(output.namespaces["anti-analysis/anti-debugging"], vec!["rule 1"]);
    assert_eq!(output.namespaces["persistence/registry"], vec!["rule 2"]);
}

// ---------- test_timing_info ----------

#[test]
fn test_output_with_timing() {
    let matches = vec![RuleMatch {
        name: "timed rule".to_string(),
        namespace: None,
        match_count: 1,
        locations: vec![],
        function_names: vec![],
        attack: vec![],
        mbc: vec![],
        is_lib: false,
    }];

    let timing = TimingInfo {
        rules_ms: Some(50),
        extraction_ms: Some(100),
        matching_ms: Some(75),
        total_ms: Some(250),
    };

    let output = CapaOutput::from_matches(matches, 100).with_timing(timing);
    assert!(output.timing.is_some());
    let t = output.timing.as_ref().unwrap();
    assert_eq!(t.total_ms, Some(250));

    // Timing should survive JSON round-trip
    let json = output.to_json().unwrap();
    assert!(json.contains("total_ms"));
}

// ---------- test_file_scope_location ----------

#[test]
fn test_file_scope_location_display() {
    let matches = vec![RuleMatch {
        name: "file scope rule".to_string(),
        namespace: None,
        match_count: 1,
        locations: vec![Address(0)], // Address(0) indicates file-scope
        function_names: vec![],
        attack: vec![],
        mbc: vec![],
        is_lib: false,
    }];

    let output = CapaOutput::from_matches(matches, 10);
    assert_eq!(output.capabilities[0].locations, vec!["file"]);
}

#[test]
fn test_function_scope_location_display() {
    let matches = vec![RuleMatch {
        name: "func scope rule".to_string(),
        namespace: None,
        match_count: 1,
        locations: vec![Address(0x401000)],
        function_names: vec![],
        attack: vec![],
        mbc: vec![],
        is_lib: false,
    }];

    let output = CapaOutput::from_matches(matches, 10);
    assert_eq!(output.capabilities[0].locations, vec!["0x401000"]);
}
