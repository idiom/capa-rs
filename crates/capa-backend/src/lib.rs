//! Binary analysis backend for capa-rs
//!
//! This crate provides feature extraction for capability detection.
//!
//! Features:
//! - PE/ELF binary loading via goblin
//! - Disassembly via iced-x86 (blazingly fast, >250 MB/s)
//! - Optional vivisect integration for function detection matching Python capa
//! - Function enumeration and basic block detection
//! - Loop detection for characteristic analysis
//! - Multi-pattern byte matching with Aho-Corasick
//! - .NET analysis via dotscope (optional)

mod extractor;
mod hashing;
pub mod helpers;
mod lifter;
mod loader;
pub mod strings;
mod dotnet_extractor;

pub use extractor::{BytePatternMatcher, BinaryExtractor, GoblinExtractor};
pub use hashing::{SampleHashes, get_sample_hashes, get_file_hashes};
pub use lifter::{lift_binary, ILOperation, LiftedBasicBlock, LiftedFunction, LiftedInstruction, LiftedProgram};
pub use loader::{load_binary, load_binary_with_format, BinaryInfo, ImportInfo, ExportInfo, SectionInfo, StringInfo};
pub use dotnet_extractor::{DotNetExtractedFeatures, DotNetMethodFeatures, extract_dotnet_features, merge_dotnet_features, merge_dotnet_method_features};
