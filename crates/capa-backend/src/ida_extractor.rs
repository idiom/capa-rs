//! IDA Pro feature extractor — top-level entry point.
//!
//! Opens a binary via idalib, loads metadata, lifts to LiftedProgram,
//! and reuses BinaryExtractor::extract_from_lifted() for feature detection.

use std::fs;
use std::path::Path;

use idalib::idb::IDB;

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
    save_idb: bool,
}

impl IdaExtractor {
    pub fn new() -> Self {
        Self {
            extractor: BinaryExtractor::new(),
            save_idb: false,
        }
    }

    /// Set whether to save the IDB file after analysis.
    pub fn with_save_idb(mut self, save: bool) -> Self {
        self.save_idb = save;
        self
    }

    /// Extract features from a binary file using IDA as the analysis backend.
    ///
    /// This opens the file in IDA, runs auto-analysis, extracts metadata
    /// and instructions, then applies the standard feature detection pipeline.
    pub fn extract_file(&self, path: &Path) -> Result<ExtractedFeatures, Box<dyn std::error::Error + Send + Sync>> {
        // Must be called before any IDA initialization to suppress GUI/dialogs
        idalib::force_batch_mode();

        // Read the binary bytes (needed for extract_from_lifted)
        let bytes = fs::read(path)
            .map_err(|e| format!("Failed to read binary {}: {}", path.display(), e))?;

        // Open the binary in IDA with auto-analysis, optionally saving the IDB
        let idb = IDB::open_with(path, true, self.save_idb)
            .map_err(|e| format!("Failed to open IDB for {}: {}", path.display(), e))?;

        // Extract metadata from IDA
        let info = load_from_idb(&idb);

        // Lift all functions into the intermediate representation
        let program = lift_from_idb(&idb, info);

        // Reuse the standard feature extraction pipeline
        let features = self.extractor.extract_from_lifted(&program, &bytes);

        Ok(features)
    }
}
