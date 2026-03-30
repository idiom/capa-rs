//! IDA Pro binary loader — produces BinaryInfo from an IDB.
//!
//! This module uses idalib-rs to extract the same metadata
//! (imports, exports, sections, strings) that goblin+loader.rs provides,
//! but leverages IDA's analysis for richer results.

use crate::loader::BinaryInfo;

/// Load binary metadata from an IDA database.
///
/// Opens the binary at `path` using idalib, runs auto-analysis,
/// and extracts imports, exports, sections, strings, and format info.
pub(crate) fn load_from_idb(idb: &idalib::idb::IDB) -> BinaryInfo {
    todo!("Phase 2: implement IDA loader")
}
