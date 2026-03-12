//! Feature type definitions
//!
//! Types representing extracted features from binaries.

use crate::rule::{ArchType, CharacteristicType, FormatType, OsType, PropertyAccess};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Address in the binary
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub u64);

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Collection of features at a specific scope
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeatureSet {
    /// API calls
    pub apis: HashSet<String>,
    /// Imported functions
    pub imports: HashSet<String>,
    /// Exported functions
    pub exports: HashSet<String>,
    /// Function names (from FLIRT/.NET)
    pub function_names: HashSet<String>,
    /// String literals
    pub strings: HashSet<String>,
    /// Numeric constants
    pub numbers: HashSet<i64>,
    /// Offset values
    pub offsets: HashSet<i64>,
    /// Byte sequences found
    pub bytes_sequences: Vec<Vec<u8>>,
    /// Mnemonic counts
    pub mnemonics: HashMap<String, usize>,
    /// Operand values: (index, number, offset)
    pub operands: Vec<(usize, Option<i64>, Option<i64>)>,
    /// Characteristics
    pub characteristics: HashSet<CharacteristicType>,
    /// Section names
    pub sections: HashSet<String>,
    /// .NET namespaces
    pub namespaces: HashSet<String>,
    /// .NET classes
    pub classes: HashSet<String>,
    /// .NET properties: (name, access)
    pub properties: Vec<(String, PropertyAccess)>,
    /// Basic block count (for function scope)
    pub basic_block_count: usize,
}

impl FeatureSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another feature set into this one
    pub fn merge(&mut self, other: &FeatureSet) {
        self.apis.extend(other.apis.iter().cloned());
        self.imports.extend(other.imports.iter().cloned());
        self.exports.extend(other.exports.iter().cloned());
        self.function_names.extend(other.function_names.iter().cloned());
        self.strings.extend(other.strings.iter().cloned());
        self.numbers.extend(other.numbers.iter().cloned());
        self.offsets.extend(other.offsets.iter().cloned());
        self.bytes_sequences.extend(other.bytes_sequences.iter().cloned());
        for (k, v) in &other.mnemonics {
            *self.mnemonics.entry(k.clone()).or_insert(0) += v;
        }
        self.operands.extend(other.operands.iter().cloned());
        self.characteristics.extend(other.characteristics.iter().cloned());
        self.sections.extend(other.sections.iter().cloned());
        self.namespaces.extend(other.namespaces.iter().cloned());
        self.classes.extend(other.classes.iter().cloned());
        self.properties.extend(other.properties.iter().cloned());
        self.basic_block_count += other.basic_block_count;
    }
}

/// Features for a single function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFeatures {
    /// Function address
    pub address: Address,
    /// Function name (if known)
    pub name: Option<String>,
    /// Function-level features
    pub features: FeatureSet,
    /// Basic block features by index
    pub basic_blocks: HashMap<usize, FeatureSet>,
    /// Instruction features by address
    pub instructions: HashMap<Address, FeatureSet>,
}

impl FunctionFeatures {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            name: None,
            features: FeatureSet::new(),
            basic_blocks: HashMap::new(),
            instructions: HashMap::new(),
        }
    }

    /// Get all features merged (function + basic blocks + instructions)
    pub fn all_features(&self) -> FeatureSet {
        let mut merged = self.features.clone();
        for bb in self.basic_blocks.values() {
            merged.merge(bb);
        }
        for inst in self.instructions.values() {
            merged.merge(inst);
        }
        merged
    }
}

/// Complete extracted features from a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFeatures {
    /// File-level features
    pub file: FeatureSet,
    /// Function features by address
    pub functions: HashMap<Address, FunctionFeatures>,
    /// Detected operating system
    pub os: OsType,
    /// Detected architecture
    pub arch: ArchType,
    /// Detected file format
    pub format: FormatType,
}

impl ExtractedFeatures {
    pub fn new(os: OsType, arch: ArchType, format: FormatType) -> Self {
        Self {
            file: FeatureSet::new(),
            functions: HashMap::new(),
            os,
            arch,
            format,
        }
    }

    /// Get all features merged across all scopes
    pub fn all_features(&self) -> FeatureSet {
        let mut merged = self.file.clone();
        for func in self.functions.values() {
            merged.merge(&func.all_features());
        }
        merged
    }
}
