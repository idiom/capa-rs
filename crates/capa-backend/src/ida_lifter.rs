//! IDA Pro lifter — produces LiftedProgram from an IDB.
//!
//! This module walks IDA's function/CFG/instruction model
//! and produces the same LiftedProgram IR that lifter.rs creates
//! from goblin+iced-x86, so that extract_from_lifted() can be reused.

use crate::lifter::LiftedProgram;
use crate::loader::BinaryInfo;

/// Lift all functions in the IDB into a LiftedProgram.
///
/// Iterates over IDA's functions, builds CFGs via flow charts,
/// decodes instructions, and maps them to ILOperations.
pub(crate) fn lift_from_idb(idb: &idalib::idb::IDB, info: BinaryInfo) -> LiftedProgram {
    todo!("Phase 3: implement IDA lifter")
}
