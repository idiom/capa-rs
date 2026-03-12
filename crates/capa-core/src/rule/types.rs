//! CAPA rule type definitions
//!
//! These types represent the complete CAPA rule schema.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Internal regex representation - standard regex for most patterns,
/// fancy-regex for patterns with look-around (lookahead/lookbehind)
#[derive(Clone)]
enum RegexInner {
    Standard(Regex),
    Fancy(fancy_regex::Regex),
}

impl std::fmt::Debug for RegexInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegexInner::Standard(r) => write!(f, "Standard({})", r.as_str()),
            RegexInner::Fancy(r) => write!(f, "Fancy({})", r.as_str()),
        }
    }
}

impl RegexInner {
    fn is_match(&self, text: &str) -> bool {
        match self {
            RegexInner::Standard(r) => r.is_match(text),
            RegexInner::Fancy(r) => r.is_match(text).unwrap_or(false),
        }
    }
}

/// Complete CAPA rule representation
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule metadata
    pub meta: RuleMeta,
    /// Feature tree (AST for matching logic)
    pub features: FeatureNode,
    /// Source file path (for debugging)
    pub source_path: Option<String>,
}

/// Rule metadata block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMeta {
    /// Rule name (required, unique identifier)
    pub name: String,
    /// Hierarchical namespace (e.g., "communication/socket/tcp")
    #[serde(default)]
    pub namespace: Option<String>,
    /// List of author emails
    #[serde(default)]
    pub authors: Vec<String>,
    /// Rule description
    #[serde(default)]
    pub description: Option<String>,
    /// Analysis scopes
    #[serde(default)]
    pub scopes: Scopes,
    /// Legacy scope field (deprecated, use scopes)
    #[serde(default)]
    pub scope: Option<String>,
    /// MITRE ATT&CK mappings
    #[serde(default, rename = "att&ck")]
    pub attack: Vec<String>,
    /// Malware Behavior Catalog mappings
    #[serde(default)]
    pub mbc: Vec<String>,
    /// Reference URLs
    #[serde(default)]
    pub references: Vec<String>,
    /// Example hashes/offsets
    #[serde(default)]
    pub examples: Vec<String>,
    /// Library rule flag (not shown in output, used by other rules)
    #[serde(default, rename = "lib")]
    pub is_lib: bool,
    /// MAEC metadata
    #[serde(default)]
    pub maec: Option<MaecMeta>,
}

/// Static and dynamic scope definitions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scopes {
    /// Static analysis scope
    #[serde(default, rename = "static")]
    pub static_scope: StaticScope,
    /// Dynamic analysis scope
    #[serde(default)]
    pub dynamic: DynamicScope,
}

/// Static analysis scope hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaticScope {
    /// Single assembly instruction
    Instruction,
    /// Contiguous block of code
    #[serde(rename = "basic block")]
    BasicBlock,
    /// Complete function
    #[default]
    Function,
    /// Entire executable file
    File,
    /// Unsupported/unspecified
    Unsupported,
}

/// Dynamic analysis scope hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DynamicScope {
    /// Single API/function call
    #[default]
    Call,
    /// Series of related calls
    #[serde(rename = "span of calls")]
    SpanOfCalls,
    /// Single thread of execution
    Thread,
    /// Entire process
    Process,
    /// Entire file
    File,
    /// Unsupported/unspecified
    Unsupported,
}

/// MAEC metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaecMeta {
    #[serde(default)]
    pub analysis_conclusion: Option<String>,
    #[serde(default)]
    pub analysis_conclusion_ov: Option<String>,
    #[serde(default)]
    pub malware_family: Option<String>,
    #[serde(default)]
    pub malware_category: Option<String>,
    #[serde(default)]
    pub malware_category_ov: Option<String>,
}

/// Feature tree node (AST for rule logic)
#[derive(Debug, Clone)]
pub enum FeatureNode {
    // Boolean operators
    /// All children must match
    And(Vec<FeatureNode>),
    /// At least one child must match
    Or(Vec<FeatureNode>),
    /// Child must not match
    Not(Box<FeatureNode>),
    /// At least N children must match
    NOrMore(usize, Vec<FeatureNode>),
    /// Optional children (0 or more)
    Optional(Vec<FeatureNode>),

    // Counting operator
    /// Count occurrences with constraint
    Count(Box<FeatureNode>, CountConstraint),

    // Leaf features
    /// Concrete feature to match
    Feature(Feature),

    // Description annotation
    /// Description wrapping another node
    Description(String, Box<FeatureNode>),

    // Match prior rule
    /// Reference to another rule by name
    Match(String),

    // Subscopes
    /// All child features must match the same instruction
    Instruction(Vec<FeatureNode>),
    /// All child features must match within a basic block
    BasicBlock(Vec<FeatureNode>),
    /// All child features must match within a function
    Function(Vec<FeatureNode>),
}

/// Counting constraint for count() operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountConstraint {
    /// Exact count
    Exact(usize),
    /// At least N
    OrMore(usize),
    /// At most N
    OrFewer(usize),
    /// Range (inclusive)
    Range(usize, usize),
}

/// Individual feature types
#[derive(Debug, Clone)]
pub enum Feature {
    // API/Import features
    /// API/function call
    Api(StringMatcher),
    /// Imported function
    Import(StringMatcher),
    /// Exported function
    Export(StringMatcher),
    /// Library function name (FLIRT/.NET)
    FunctionName(StringMatcher),

    // String features
    /// Exact string match
    String(StringMatcher),
    /// Substring match (implied wildcards)
    Substring(StringMatcher),

    // Numeric features
    /// Numeric constant
    Number(NumberMatcher),
    /// Structure offset
    Offset(OffsetMatcher),

    // Byte sequence
    /// Byte pattern (max 0x100 bytes)
    Bytes(Vec<u8>),

    // Instruction features
    /// Assembly mnemonic
    Mnemonic(String),
    /// Operand value at index
    Operand(OperandMatcher),

    // Characteristics
    /// Special code pattern
    Characteristic(CharacteristicType),

    // Section
    /// PE/ELF section name
    Section(StringMatcher),

    // .NET specific
    /// .NET namespace
    Namespace(StringMatcher),
    /// .NET class
    Class(StringMatcher),
    /// .NET property
    Property(PropertyMatcher),

    // COM
    /// COM class
    ComClass(String),
    /// COM interface
    ComInterface(String),

    // Scope features (used for counting)
    /// Basic block (for count(basic block))
    BasicBlockFeature,

    // Global features (apply to all scopes)
    /// Target operating system
    Os(OsType),
    /// CPU architecture
    Arch(ArchType),
    /// File format
    Format(FormatType),
}

/// String matching modes
#[derive(Debug, Clone)]
pub enum StringMatcher {
    /// Exact string match (case-sensitive by default)
    Exact(String),
    /// Regex pattern match
    Regex(CompiledRegex),
}

/// Compiled regex with original pattern for serialization
#[derive(Debug, Clone)]
pub struct CompiledRegex {
    pub pattern: String,
    inner: RegexInner,
    pub case_insensitive: bool,
}

impl CompiledRegex {
    pub fn new(pattern: &str, case_insensitive: bool) -> Result<Self, regex::Error> {
        // Try standard regex first (faster)
        let try_compile = |p: &str| {
            if case_insensitive {
                regex::RegexBuilder::new(p)
                    .case_insensitive(true)
                    .build()
            } else {
                Regex::new(p)
            }
        };

        // First attempt: standard regex
        match try_compile(pattern) {
            Ok(r) => {
                return Ok(Self {
                    pattern: pattern.to_string(),
                    inner: RegexInner::Standard(r),
                    case_insensitive,
                });
            }
            Err(e) => {
                // Check if error is about repetition quantifier (unescaped curly braces)
                let err_msg = e.to_string();
                if err_msg.contains("repetition") {
                    let escaped = Self::escape_literal_braces(pattern);
                    if let Ok(r) = try_compile(&escaped) {
                        return Ok(Self {
                            pattern: pattern.to_string(),
                            inner: RegexInner::Standard(r),
                            case_insensitive,
                        });
                    }
                }

                // Fall back to fancy-regex for look-around and other advanced features
                let fancy_pattern = if case_insensitive {
                    format!("(?i){}", pattern)
                } else {
                    pattern.to_string()
                };
                match fancy_regex::Regex::new(&fancy_pattern) {
                    Ok(r) => {
                        log::debug!("Using fancy-regex for pattern with advanced features: {}", pattern);
                        Ok(Self {
                            pattern: pattern.to_string(),
                            inner: RegexInner::Fancy(r),
                            case_insensitive,
                        })
                    }
                    Err(_) => {
                        // Both failed, return the original regex error
                        Err(e)
                    }
                }
            }
        }
    }

    /// Escape curly braces that are likely meant as literals (not quantifiers)
    /// Valid quantifiers: {n}, {n,}, {n,m} where n and m are digits
    fn escape_literal_braces(pattern: &str) -> String {
        let mut result = String::with_capacity(pattern.len() * 2);
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '{' {
                // Check if this looks like a valid quantifier
                let mut j = i + 1;
                let mut is_quantifier = false;

                // Skip digits
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }

                // Check for valid quantifier endings
                if j > i + 1 {
                    // We have digits
                    if j < chars.len() && chars[j] == '}' {
                        is_quantifier = true; // {n}
                    } else if j < chars.len() && chars[j] == ',' {
                        j += 1;
                        // Skip more digits
                        while j < chars.len() && chars[j].is_ascii_digit() {
                            j += 1;
                        }
                        if j < chars.len() && chars[j] == '}' {
                            is_quantifier = true; // {n,} or {n,m}
                        }
                    }
                }

                if is_quantifier {
                    result.push(chars[i]);
                } else {
                    result.push('\\');
                    result.push('{');
                }
            } else if chars[i] == '}' && !result.ends_with('\\') {
                // Check if there's an unescaped opening brace before this
                // If not, escape this closing brace
                if !result.contains('{') || result.rfind('{').map_or(false, |pos| {
                    result[pos..].starts_with("\\{")
                }) {
                    result.push('\\');
                }
                result.push('}');
            } else {
                result.push(chars[i]);
            }
            i += 1;
        }
        result
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.inner.is_match(text)
    }
}

/// Number matcher with optional description
#[derive(Debug, Clone)]
pub struct NumberMatcher {
    /// Numeric value
    pub value: i64,
    /// Optional description (e.g., "PAGE_EXECUTE_READWRITE")
    pub description: Option<String>,
}

/// Offset matcher
#[derive(Debug, Clone)]
pub struct OffsetMatcher {
    /// Offset value
    pub value: i64,
    /// Architecture-specific offset
    pub arch: Option<ArchType>,
    /// Optional description
    pub description: Option<String>,
}

/// Operand index and value matcher
#[derive(Debug, Clone)]
pub struct OperandMatcher {
    /// Operand index (0-based)
    pub index: usize,
    /// Value to match
    pub value: OperandValue,
}

/// Operand value types
#[derive(Debug, Clone)]
pub enum OperandValue {
    /// Numeric immediate
    Number(NumberMatcher),
    /// Memory offset
    Offset(OffsetMatcher),
}

/// Property access modes
#[derive(Debug, Clone)]
pub struct PropertyMatcher {
    /// Full property name
    pub name: String,
    /// Access type
    pub access: PropertyAccess,
}

/// Property access types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyAccess {
    Read,
    Write,
    Any,
}

/// Characteristic types from CAPA spec
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CharacteristicType {
    // File scope
    EmbeddedPe,
    MixedMode,
    ForwardedExport,

    // Function scope
    Loop,
    RecursiveCall,
    CallsFrom,
    CallsTo,
    Nzxor,
    Peb,
    FsAccess,
    GsAccess,
    CrossSectionFlow,

    // Basic block scope
    TightLoop,
    StackString,
    CallsFromShellcode,

    // Instruction scope
    IndirectCall,
    CallPlus5,
    UnmanagedCall,
    UnmangledCall,

    // Additional characteristics
    Switch,
    Packer,
}

impl CharacteristicType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "embedded pe" => Some(Self::EmbeddedPe),
            "mixed mode" => Some(Self::MixedMode),
            "forwarded export" => Some(Self::ForwardedExport),
            "loop" => Some(Self::Loop),
            "recursive call" => Some(Self::RecursiveCall),
            "calls from" => Some(Self::CallsFrom),
            "calls to" => Some(Self::CallsTo),
            "nzxor" => Some(Self::Nzxor),
            "peb access" => Some(Self::Peb),
            "fs access" => Some(Self::FsAccess),
            "gs access" => Some(Self::GsAccess),
            "cross section flow" => Some(Self::CrossSectionFlow),
            "tight loop" => Some(Self::TightLoop),
            "stack string" => Some(Self::StackString),
            "calls from shellcode" => Some(Self::CallsFromShellcode),
            "indirect call" => Some(Self::IndirectCall),
            "call $+5" => Some(Self::CallPlus5),
            "unmanaged call" => Some(Self::UnmanagedCall),
            "unmangled call" => Some(Self::UnmangledCall),
            "switch" => Some(Self::Switch),
            "packer" => Some(Self::Packer),
            _ => None,
        }
    }
}

/// Operating system types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Windows,
    Linux,
    MacOS,
    Android,
    Any,
}

impl OsType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            "macos" | "osx" => Some(Self::MacOS),
            "android" => Some(Self::Android),
            "any" => Some(Self::Any),
            _ => None,
        }
    }
}

/// Architecture types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchType {
    I386,
    Amd64,
    Arm,
    Arm64,
    Mips,
    Ppc,
    Ppc64,
    Any,
}

impl ArchType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "i386" | "x86" => Some(Self::I386),
            "amd64" | "x86_64" | "x64" => Some(Self::Amd64),
            "arm" | "arm32" => Some(Self::Arm),
            "arm64" | "aarch64" => Some(Self::Arm64),
            "mips" | "mips32" | "mips64" => Some(Self::Mips),
            "ppc" | "powerpc" => Some(Self::Ppc),
            "ppc64" | "powerpc64" => Some(Self::Ppc64),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    /// Check if this is an x86 architecture (usable with iced)
    pub fn is_x86(&self) -> bool {
        matches!(self, Self::I386 | Self::Amd64)
    }

    /// Check if this is an ARM architecture
    pub fn is_arm(&self) -> bool {
        matches!(self, Self::Arm | Self::Arm64)
    }
}

/// File format types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatType {
    Pe,
    Elf,
    MachO,
    DotNet,
    /// 32-bit shellcode (raw x86 machine code)
    Sc32,
    /// 64-bit shellcode (raw x64 machine code)
    Sc64,
    Any,
}

impl FormatType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pe" => Some(Self::Pe),
            "elf" => Some(Self::Elf),
            "macho" | "mach-o" => Some(Self::MachO),
            "dotnet" | ".net" => Some(Self::DotNet),
            "sc32" | "raw32" => Some(Self::Sc32),
            "sc64" | "raw64" => Some(Self::Sc64),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    /// Check if this is a shellcode format
    pub fn is_shellcode(&self) -> bool {
        matches!(self, Self::Sc32 | Self::Sc64)
    }

    /// Get the architecture for shellcode formats
    pub fn shellcode_arch(&self) -> Option<ArchType> {
        match self {
            Self::Sc32 => Some(ArchType::I386),
            Self::Sc64 => Some(ArchType::Amd64),
            _ => None,
        }
    }
}

/// Parsed ATT&CK technique reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub tactic: String,
    pub technique: String,
    pub technique_id: String,
    pub subtechnique_id: Option<String>,
}

impl AttackTechnique {
    /// Parse ATT&CK string like "Execution::Command and Scripting Interpreter [T1059]"
    pub fn parse(s: &str) -> Option<Self> {
        // Extract technique ID from brackets
        let id_start = s.rfind('[')?;
        let id_end = s.rfind(']')?;
        let full_id = &s[id_start + 1..id_end];

        // Split ID into technique and subtechnique
        let (technique_id, subtechnique_id) = if full_id.contains('.') {
            let parts: Vec<&str> = full_id.splitn(2, '.').collect();
            (parts[0].to_string(), Some(parts[1].to_string()))
        } else {
            (full_id.to_string(), None)
        };

        // Parse tactic and technique from the rest
        let desc = s[..id_start].trim();
        let parts: Vec<&str> = desc.splitn(2, "::").collect();
        if parts.len() >= 2 {
            Some(Self {
                tactic: parts[0].trim().to_string(),
                technique: parts[1].trim().to_string(),
                technique_id,
                subtechnique_id,
            })
        } else {
            Some(Self {
                tactic: String::new(),
                technique: desc.to_string(),
                technique_id,
                subtechnique_id,
            })
        }
    }
}
