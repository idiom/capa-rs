//! capa-core: Core library for CAPA capability detection
//!
//! This crate provides:
//! - Rule parsing from YAML format
//! - Feature extraction trait definitions
//! - Rule matching engine
//! - Output formatting

pub mod error;
pub mod feature;
pub mod matcher;
pub mod output;
pub mod rule;

pub use error::{CapaError, Result};
pub use feature::{ExtractedFeatures, FeatureExtractor, FeatureSet};
pub use matcher::MatchEngine;
pub use output::CapaOutput;
pub use rule::{Rule, RuleMeta, Scopes};
