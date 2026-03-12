//! Feature extractor trait
//!
//! Defines the interface for backend-specific feature extraction.

use crate::error::Result;
use crate::feature::types::*;

/// Backend-agnostic feature extraction trait
///
/// Implementations of this trait provide the bridge between
/// binary analysis backends and the CAPA matching engine.
pub trait FeatureExtractor: Send + Sync {
    /// Extract all features from a binary
    fn extract(&self, binary: &[u8]) -> Result<ExtractedFeatures>;

    /// Get file-level features only
    fn extract_file_features(&self, binary: &[u8]) -> Result<FeatureSet>;

    /// Get function-level features for a specific address
    fn extract_function_features(&self, binary: &[u8], addr: Address) -> Result<FunctionFeatures>;
}

/// Placeholder extractor that returns empty features
/// Used for testing and as a fallback
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct NullExtractor;

impl FeatureExtractor for NullExtractor {
    fn extract(&self, _binary: &[u8]) -> Result<ExtractedFeatures> {
        Ok(ExtractedFeatures::new(
            crate::rule::OsType::Any,
            crate::rule::ArchType::Any,
            crate::rule::FormatType::Any,
        ))
    }

    fn extract_file_features(&self, _binary: &[u8]) -> Result<FeatureSet> {
        Ok(FeatureSet::new())
    }

    fn extract_function_features(&self, _binary: &[u8], addr: Address) -> Result<FunctionFeatures> {
        Ok(FunctionFeatures::new(addr))
    }
}
