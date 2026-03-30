//! IDA Pro feature extractor — top-level entry point.
//!
//! Opens a binary via idalib, loads metadata, lifts to LiftedProgram,
//! and reuses BinaryExtractor::extract_from_lifted() for feature detection.

use std::path::Path;

use crate::extractor::BinaryExtractor;
use crate::ida_lifter::lift_from_idb;
use crate::ida_loader::load_from_idb;
use capa_core::feature::ExtractedFeatures;

/// IDA-backed feature extractor.
///
/// Uses IDA Pro (via idalib-rs) for disassembly and analysis,
/// then feeds the result through the same feature detection pipeline.
pub struct IdaExtractor {
    extractor: BinaryExtractor,
}

impl IdaExtractor {
    pub fn new() -> Self {
        Self {
            extractor: BinaryExtractor::new(),
        }
    }

    /// Extract features from a binary file using IDA as the analysis backend.
    ///
    /// This opens the file in IDA, runs auto-analysis, extracts metadata
    /// and instructions, then applies the standard feature detection pipeline.
    pub fn extract_file(&self, path: &Path) -> anyhow::Result<ExtractedFeatures> {
        todo!("Phase 4: implement IDA extractor")
    }
}
