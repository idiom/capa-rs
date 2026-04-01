//! capa-rs CLI
//!
//! Command-line interface for capability detection.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use colored::Colorize;
use capa_core::feature::{ExtractedFeatures, FeatureExtractor};
use capa_core::matcher::MatchEngine;
use capa_core::output::{CapaOutput, SampleInfo, TimingInfo};
use capa_core::rule::{parse_rules_directory, FormatType};
use capa_backend::{BinaryExtractor, get_sample_hashes};
use tabled::{Table, Tabled, settings::{Style, Modify, object::Columns, Width, Alignment}};

/// Input format specification
#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    /// Auto-detect format from file contents
    Auto,
    /// Windows PE executable
    Pe,
    /// Linux ELF executable
    Elf,
    /// .NET assembly
    Dotnet,
    /// 32-bit x86 shellcode (raw bytes)
    Sc32,
    /// 64-bit x64 shellcode (raw bytes)
    Sc64,
}

impl InputFormat {
    fn to_format_type(self) -> Option<FormatType> {
        match self {
            InputFormat::Auto => None,
            InputFormat::Pe => Some(FormatType::Pe),
            InputFormat::Elf => Some(FormatType::Elf),
            InputFormat::Dotnet => Some(FormatType::DotNet),
            InputFormat::Sc32 => Some(FormatType::Sc32),
            InputFormat::Sc64 => Some(FormatType::Sc64),
        }
    }
}

/// Find rules directory by checking common locations
fn find_rules_directory() -> Option<PathBuf> {
    // Check CAPA_RULES environment variable first
    if let Ok(rules_path) = env::var("CAPA_RULES") {
        let path = PathBuf::from(&rules_path);
        if path.is_dir() {
            return Some(path);
        }
    }

    // Get the executable's directory
    let exe_path = env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?.to_path_buf();

    // Build list of candidates
    let mut candidates = vec![
        // Relative to current directory
        PathBuf::from("rules"),
        PathBuf::from("capa-rules"),
        // Relative to executable
        exe_dir.join("rules"),
        exe_dir.join("capa-rules"),
    ];

    // Walk up the directory tree from exe location (handles target/release/ case)
    let mut ancestor = exe_dir.as_path();
    for _ in 0..5 {
        if let Some(parent) = ancestor.parent() {
            candidates.push(parent.join("rules"));
            candidates.push(parent.join("capa-rules"));
            ancestor = parent;
        } else {
            break;
        }
    }

    for candidate in candidates {
        if candidate.is_dir() {
            // Check if it actually contains .yml/.yaml files or subdirectories
            if let Ok(entries) = fs::read_dir(&candidate) {
                let has_rules = entries
                    .filter_map(|e| e.ok())
                    .any(|e| {
                        let path = e.path();
                        path.extension()
                            .map(|ext| ext == "yml" || ext == "yaml")
                            .unwrap_or(false)
                            || path.is_dir()
                    });
                if has_rules {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

#[derive(Parser)]
#[command(name = "capa-rs")]
#[command(author = "yeti-sec")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Detect capabilities in executable files", long_about = None)]
struct Cli {
    /// Path to binary file to analyze
    #[arg(required = true)]
    binary: PathBuf,

    /// Path to rules directory (auto-detected if not specified)
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Input format (auto-detect if not specified)
    /// Use sc32/sc64 for shellcode analysis
    #[arg(short = 'f', long, value_enum, default_value = "auto")]
    format: InputFormat,

    /// Output JSON format
    #[arg(short, long)]
    json: bool,

    /// Verbose output with match details
    #[arg(short, long)]
    verbose: bool,

    /// Filter by namespace
    #[arg(short, long)]
    namespace: Option<String>,

    /// Read pre-extracted features from JSON file
    #[arg(short = 'F', long)]
    features: Option<PathBuf>,

    /// Number of threads for parallel matching (default: auto)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Dump extracted features to JSON file (for IDA integration)
    #[arg(long)]
    dump_features: Option<PathBuf>,

    /// Skip rule matching (use with --dump-features)
    #[arg(long)]
    extract_only: bool,

    /// Analysis backend: "goblin" (default) or "ida" (requires --features ida-backend)
    #[arg(long, default_value = "goblin")]
    backend: String,

    /// Save the IDB file after IDA analysis (only with --backend ida)
    #[arg(long)]
    save_idb: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let start = Instant::now();

    // Configure thread pool if specified
    if let Some(num_threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .unwrap_or_else(|e| eprintln!("Warning: failed to set thread pool size: {e}"));
    }

    // Find rules directory
    let rules_path = cli.rules.clone().or_else(find_rules_directory);
    let rules_path = match rules_path {
        Some(p) => p,
        None => {
            eprintln!("Error: Could not find rules directory.");
            eprintln!("Specify with -r/--rules or set CAPA_RULES environment variable.");
            eprintln!("Checked: ./rules, ./capa-rules, <exe_dir>/rules, <exe_dir>/capa-rules");
            std::process::exit(1);
        }
    };

    // Load rules
    let rules_start = Instant::now();
    eprintln!("Loading rules from {}...", rules_path.display());
    let mut rules = parse_rules_directory(&rules_path)
        .context("Failed to load rules")?;
    let rules_time = rules_start.elapsed();
    eprintln!("Loaded {} rules", rules.len());

    // Filter by namespace if specified
    if let Some(ref ns) = cli.namespace {
        let original_count = rules.len();
        rules.retain(|r| {
            r.meta.namespace.as_ref().map_or(false, |n| n.contains(ns))
        });
        eprintln!("Filtered to {} rules matching namespace '{}'", rules.len(), ns);
        for r in &rules {
            eprintln!("  - '{}' (scope: {:?})", r.meta.name, r.meta.scopes.static_scope);
        }
        if rules.is_empty() {
            eprintln!("Warning: No rules match namespace '{}' (had {} rules)", ns, original_count);
        }
    }

    // Get features - either from pre-extracted JSON or from binary
    let extract_start = Instant::now();
    // binary_bytes holds the raw file bytes when we read a binary (used for both
    // feature extraction and hash computation, avoiding a second read).
    let mut binary_bytes: Option<Vec<u8>> = None;
    let features = if let Some(ref features_path) = cli.features {
        eprintln!("Loading pre-extracted features from {}...", features_path.display());
        let features_json = fs::read_to_string(features_path)
            .context("Failed to read features file")?;
        serde_json::from_str::<ExtractedFeatures>(&features_json)
            .context("Failed to parse features JSON")?
    } else if cli.backend == "ida" {
        // IDA backend
        #[cfg(feature = "ida-backend")]
        {
            eprintln!("Extracting features via IDA backend for {}...", cli.binary.display());
            let ida = capa_backend::IdaExtractor::new()
                .with_save_idb(cli.save_idb);
            ida.extract_file(&cli.binary)
                .map_err(|e| anyhow::anyhow!("Failed to extract features via IDA: {e}"))?
        }
        #[cfg(not(feature = "ida-backend"))]
        {
            eprintln!("Error: IDA backend requires the 'ida-backend' feature.");
            eprintln!("Rebuild with: cargo build --features ida-backend");
            std::process::exit(1);
        }
    } else {
        // Goblin backend (default)
        eprintln!("Loading binary {}...", cli.binary.display());
        let binary = fs::read(&cli.binary)
            .context("Failed to read binary file")?;

        // Extract features (use format if specified)
        let extractor = BinaryExtractor::new();

        let result = if let Some(format) = cli.format.to_format_type() {
            eprintln!("Extracting features (format: {:?})...", format);
            extractor.extract_with_format(&binary, format)
                .context("Failed to extract features")?
        } else {
            eprintln!("Extracting features (auto-detecting format)...");
            extractor.extract(&binary)
                .context("Failed to extract features")?
        };

        // Retain bytes for hash computation below
        binary_bytes = Some(binary);
        result
    };
    let extract_time = extract_start.elapsed();

    eprintln!("Features:");
    eprintln!("  - {} imports", features.file.imports.len());
    eprintln!("  - {} exports", features.file.exports.len());
    eprintln!("  - {} strings", features.file.strings.len());
    eprintln!("  - {} functions", features.functions.len());
    eprintln!("  - {} characteristics", features.file.characteristics.len());

    if !features.file.characteristics.is_empty() {
        eprintln!("  Characteristics: {:?}", features.file.characteristics);
    }

    // Dump features if requested
    if let Some(ref dump_path) = cli.dump_features {
        eprintln!("Dumping features to {}...", dump_path.display());
        let features_json = serde_json::to_string_pretty(&features)
            .context("Failed to serialize features")?;
        fs::write(dump_path, features_json)
            .context("Failed to write features file")?;
        eprintln!("Features dumped successfully.");
    }

    // Skip matching if extract-only mode
    if cli.extract_only {
        let total = start.elapsed();
        eprintln!("\nTiming:");
        eprintln!("  Extraction:     {:>8.2?}", extract_time);
        eprintln!("  Total:          {:>8.2?}", total);
        return Ok(());
    }

    // Match rules
    let match_start = Instant::now();
    eprintln!("Matching rules...");
    let engine = MatchEngine::new(rules);
    let matches = engine.match_all(&features);
    let match_time = match_start.elapsed();

    // Generate output with timing
    let total_time = start.elapsed();
    let timing = TimingInfo {
        rules_ms: Some(rules_time.as_millis() as u64),
        extraction_ms: Some(extract_time.as_millis() as u64),
        matching_ms: Some(match_time.as_millis() as u64),
        total_ms: Some(total_time.as_millis() as u64),
    };

    // Compute sample hashes (matching Python's Metadata.sample)
    // Re-use binary_bytes from extraction to avoid reading the file a second time.
    let sample_info = binary_bytes.map(|bytes| {
        let hashes = get_sample_hashes(&bytes);
        SampleInfo {
            md5: hashes.md5,
            sha1: hashes.sha1,
            sha256: hashes.sha256,
            path: cli.binary.display().to_string(),
        }
    });

    let mut output = CapaOutput::from_matches(matches, engine.rule_count())
        .with_timing(timing);
    if let Some(sample) = sample_info {
        output = output.with_sample(sample);
    }

    if cli.json {
        println!("{}", output.to_json()?);
    } else {
        print_text_output(&output, cli.verbose);
        // Print timing at the end (to stdout so it appears after results)
        println!("\n{}:", "Timing".bright_cyan().bold());
        println!("  Rules loading:  {:>8.2?}", rules_time);
        println!("  Extraction:     {:>8.2?}", extract_time);
        println!("  Matching:       {:>8.2?}", match_time);
        println!("  {}:          {:>8.2?}", "Total".bright_white().bold(), total_time);
    }

    Ok(())
}

/// Row for the capabilities table
#[derive(Tabled)]
struct CapabilityRow {
    #[tabled(rename = "Rule")]
    rule: String,
    #[tabled(rename = "Namespace")]
    namespace: String,
    #[tabled(rename = "ATT&CK")]
    attack: String,
}

/// Row for the ATT&CK summary table
#[derive(Tabled)]
struct AttackRow {
    #[tabled(rename = "Technique")]
    technique: String,
}

fn print_text_output(output: &CapaOutput, verbose: bool) {
    let banner = "=".repeat(80);
    println!("\n{}", banner.bright_cyan());
    println!("{}", " CAPA Analysis Results".bright_white().bold());
    println!("{}\n", banner.bright_cyan());
    println!("Matched: {}/{} rules\n",
        output.matched_rules.to_string().bright_green().bold(),
        output.total_rules);

    // Build capability rows sorted by namespace then name
    let mut rows: Vec<CapabilityRow> = output.capabilities
        .iter()
        .map(|cap| CapabilityRow {
            rule: cap.name.clone(),
            namespace: cap.namespace.clone().unwrap_or_else(|| "uncategorized".to_string()),
            attack: cap.attack.as_ref().map(|a| a.join(", ")).unwrap_or_default(),
        })
        .collect();

    // Sort by namespace, then by rule name
    rows.sort_by(|a, b| {
        a.namespace.cmp(&b.namespace)
            .then_with(|| a.rule.cmp(&b.rule))
    });

    if !rows.is_empty() {
        let table = Table::new(&rows)
            .with(Style::rounded())
            .with(Modify::new(Columns::single(0)).with(Width::truncate(50).suffix("...")))
            .with(Modify::new(Columns::single(1)).with(Width::truncate(40).suffix("...")))
            .with(Modify::new(Columns::single(2)).with(Alignment::left()))
            .to_string();
        println!("{}", table);
    }

    // ATT&CK summary
    if !output.mitre_attack.is_empty() {
        println!("\n{}", "MITRE ATT&CK Coverage:".bright_yellow().bold());
        let attack_rows: Vec<AttackRow> = output.mitre_attack
            .iter()
            .map(|t| AttackRow { technique: t.clone() })
            .collect();
        let attack_table = Table::new(&attack_rows)
            .with(Style::rounded())
            .to_string();
        println!("{}", attack_table);
    }

    if verbose {
        let divider = "-".repeat(80);
        println!("\n{}", divider.bright_cyan());
        println!("{}", " Detailed Matches".bright_white().bold());
        println!("{}", divider.bright_cyan());
        for cap in &output.capabilities {
            let match_suffix = if cap.matches > 1 {
                format!(" ({} matches)", cap.matches).dimmed().to_string()
            } else {
                String::new()
            };
            println!("\n  {}{}", cap.name.bright_green(), match_suffix);
            println!("    {}: {}",
                "namespace".bright_cyan(),
                cap.namespace.as_deref().unwrap_or("uncategorized"));
            if let Some(ref attack) = cap.attack {
                println!("    {}:    {}",
                    "ATT&CK".bright_yellow(),
                    attack.join(", ").bright_yellow());
            }
            if !cap.locations.is_empty() {
                // Limit displayed addresses to 25 (like Python capa)
                const MAX_DISPLAY: usize = 25;
                let display_count = cap.locations.len().min(MAX_DISPLAY);

                // Build location strings with function names if available
                let format_location = |idx: usize, loc: &str| -> String {
                    if let Some(name) = cap.function_names.get(idx) {
                        format!("{} ({})", loc.bright_white(), name.dimmed())
                    } else {
                        loc.bright_white().to_string()
                    }
                };

                println!("    {}:   {}",
                    "matches".bright_cyan(),
                    format_location(0, &cap.locations[0]));
                for (idx, loc) in cap.locations.iter().enumerate().skip(1).take(MAX_DISPLAY - 1) {
                    println!("               {}", format_location(idx, loc));
                }
                if cap.locations.len() > MAX_DISPLAY {
                    println!("               {}",
                        format!("... and {} more", cap.locations.len() - display_count).dimmed());
                }
            }
        }
    }
}
