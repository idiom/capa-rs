//! Error types for capa-core

use thiserror::Error;

/// Result type alias for capa-core operations
pub type Result<T> = std::result::Result<T, CapaError>;

/// Main error type for capa-core
#[derive(Error, Debug)]
pub enum CapaError {
    #[error("Failed to parse rule: {0}")]
    ParseError(String),

    #[error("Invalid rule syntax: {0}")]
    SyntaxError(String),

    #[error("Invalid regex pattern '{pattern}': {source}")]
    RegexError {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("Rule validation failed: {0}")]
    ValidationError(String),

    #[error("Feature extraction failed: {0}")]
    ExtractionError(String),

    #[error("Matching error: {0}")]
    MatchError(String),

    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}
