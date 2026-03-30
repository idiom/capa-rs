//! IDA Pro lifter — produces LiftedProgram from an IDB.
//!
//! This module walks IDA's function/CFG/instruction model
//! and produces the same LiftedProgram IR that lifter.rs creates
//! from goblin+iced-x86, so that extract_from_lifted() can be reused.

use std::collections::HashMap;

use idalib::idb::IDB;
use idalib::func::FunctionFlags;

use crate::lifter::{
    ILOperation, LiftedBasicBlock, LiftedFunction, LiftedInstruction, LiftedProgram,
};
use crate::loader::BinaryInfo;

/// Lift all functions in the IDB into a LiftedProgram.
///
/// Iterates over IDA's functions, builds CFGs via flow charts,
/// decodes instructions, and maps them to ILOperations.
pub(crate) fn lift_from_idb(idb: &IDB, info: BinaryInfo) -> LiftedProgram {
    let mut functions = HashMap::new();
    let entry_point = info.entry_point;

    for (_id, func) in idb.functions() {
        let func_addr = func.start_address();
        let func_name = func.name();
        let flags = func.flags();
        let is_thunk = flags.contains(FunctionFlags::THUNK);
        let is_library = flags.contains(FunctionFlags::LIB);

        // Build CFG and lift basic blocks
        let (basic_blocks, callees) = match func.cfg() {
            Ok(cfg) => lift_cfg(idb, &cfg, func_addr),
            Err(_) => {
                // Fallback: create a single basic block for the function
                let (bb, callees) = lift_linear(idb, func_addr, func.end_address());
                (vec![bb], callees)
            }
        };

        // Detect thunk target
        let thunk_target = if is_thunk {
            func.calc_thunk_target().and_then(|target_addr| {
                idb.function_at(target_addr)
                    .and_then(|f| f.name())
                    .map(|n| n.trim_start_matches(['.', '_']).to_string())
            })
        } else {
            None
        };

        functions.insert(
            func_addr,
            LiftedFunction {
                address: func_addr,
                name: func_name,
                basic_blocks,
                callees,
                callers: Vec::new(), // Populated below
                is_thunk,
                thunk_target,
                is_library,
            },
        );
    }

    // Build caller lists from callee lists
    let callee_map: Vec<(u64, Vec<u64>)> = functions
        .iter()
        .map(|(&addr, f)| (addr, f.callees.clone()))
        .collect();

    for (caller_addr, callees) in &callee_map {
        for callee in callees {
            if let Some(callee_func) = functions.get_mut(callee) {
                callee_func.callers.push(*caller_addr);
            }
        }
    }

    // Build IAT entries and string maps from BinaryInfo
    let iat_entries = build_iat_map(&info);
    let strings_at = build_string_map(idb, &info);
    let thunk_targets = build_thunk_map(&functions);

    LiftedProgram {
        functions,
        entry_point,
        info,
        strings_at,
        iat_entries,
        thunk_targets,
    }
}

/// Lift a function's CFG into basic blocks.
fn lift_cfg(
    idb: &IDB,
    cfg: &idalib::func::FunctionCFG<'_>,
    _func_addr: u64,
) -> (Vec<LiftedBasicBlock>, Vec<u64>) {
    let mut blocks = Vec::new();
    let mut all_callees = Vec::new();

    for (block_idx, block) in cfg.blocks().enumerate() {
        let start = block.start_address();
        let end = block.end_address();

        let (instructions, callees) = lift_instructions(idb, start, end);
        all_callees.extend(callees);

        let successors: Vec<usize> = block.succs().collect();
        let predecessors: Vec<usize> = block.preds().collect();

        // Detect loop headers: block is a loop header if any predecessor has a higher address
        let is_loop_header = predecessors.iter().any(|&pred_idx| {
            cfg.block_by_id(pred_idx)
                .map_or(false, |pred| pred.start_address() >= start)
        });

        blocks.push(LiftedBasicBlock {
            index: block_idx,
            address: start,
            end_address: if end > start { end - 1 } else { start },
            instructions,
            successors,
            predecessors,
            is_loop_header,
        });
    }

    (blocks, all_callees)
}

/// Fallback: lift a linear range of instructions as a single basic block.
fn lift_linear(idb: &IDB, start: u64, end: u64) -> (LiftedBasicBlock, Vec<u64>) {
    let (instructions, callees) = lift_instructions(idb, start, end);

    let bb = LiftedBasicBlock {
        index: 0,
        address: start,
        end_address: if end > start { end - 1 } else { start },
        instructions,
        successors: Vec::new(),
        predecessors: Vec::new(),
        is_loop_header: false,
    };

    (bb, callees)
}

/// Lift instructions in an address range [start, end).
fn lift_instructions(idb: &IDB, start: u64, end: u64) -> (Vec<LiftedInstruction>, Vec<u64>) {
    let mut instructions = Vec::new();
    let mut callees = Vec::new();
    let mut ea = start;

    while ea < end {
        let insn = match idb.insn_at(ea) {
            Some(insn) => insn,
            None => {
                // Skip to next head if we can't decode here
                ea = match idb.next_head(ea) {
                    Some(next) => next,
                    None => break,
                };
                continue;
            }
        };

        let insn_len = insn.len();
        if insn_len == 0 {
            ea = match idb.next_head(ea) {
                Some(next) => next,
                None => break,
            };
            continue;
        }

        // Get mnemonic from IDA
        let mnemonic = insn
            .mnemonic()
            .unwrap_or_default()
            .to_lowercase();

        // Get operands from IDA's print_operand
        let mut operands = Vec::new();
        let mut operand_values = Vec::new();

        for n in 0..insn.operand_count() {
            let op_str = insn
                .print_operand(n)
                .map(|s| normalize_operand_string(&s))
                .unwrap_or_default();

            let op_val = insn.operand(n).and_then(|op| {
                use idalib::insn::OperandType;
                match op.type_() {
                    OperandType::Imm => op.value().map(|v| v as i64),
                    OperandType::Near | OperandType::Far => op.addr().map(|v| v as i64),
                    OperandType::Mem | OperandType::Displ => op.addr().map(|v| v as i64),
                    _ => None,
                }
            });

            operands.push(op_str);
            operand_values.push(op_val);
        }

        // Build IL operations
        let mut operations = Vec::new();

        // Branch/call detection
        if insn.is_call() {
            let target = insn.operand(0).and_then(|op| {
                use idalib::insn::OperandType;
                match op.type_() {
                    OperandType::Near | OperandType::Far => op.addr(),
                    OperandType::Mem => op.addr(),
                    _ => None,
                }
            });
            operations.push(ILOperation::Branch {
                target,
                is_call: true,
            });
            if let Some(t) = target {
                callees.push(t);
            }
        } else if mnemonic.starts_with('j') || insn.is_ret() {
            let target = insn.operand(0).and_then(|op| {
                use idalib::insn::OperandType;
                match op.type_() {
                    OperandType::Near | OperandType::Far => op.addr(),
                    _ => None,
                }
            });
            operations.push(ILOperation::Branch {
                target,
                is_call: false,
            });
        }

        // XOR detection for nzxor
        if mnemonic == "xor" || mnemonic == "eor" || mnemonic == "pxor" {
            operations.push(ILOperation::Xor {
                operands: operands.clone(),
                constants: Vec::new(),
            });
        }

        // Get raw bytes
        let raw_bytes = idb.get_bytes(ea, insn_len);

        instructions.push(LiftedInstruction {
            address: ea,
            mnemonic,
            operands,
            operand_values,
            bytes: raw_bytes,
            operations,
        });

        ea += insn_len as u64;
    }

    (instructions, callees)
}

/// Normalize IDA operand strings to match the format expected by the extractor.
///
/// IDA uses Intel hex notation (e.g., `0FFFFh`, `[rbp+8h]`), but the extractor
/// expects 0x-prefix notation (e.g., `0xffff`, `[rbp+0x8]`).
fn normalize_operand_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Look for hex numbers in IDA format: digits followed by 'h'
        if chars[i].is_ascii_hexdigit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i < chars.len() && (chars[i] == 'h' || chars[i] == 'H') {
                // Convert "0FFFFh" -> "0xffff"
                let hex_str = &s[start..i];
                // Strip leading zeros but keep at least one digit
                let trimmed = hex_str.trim_start_matches('0');
                let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
                result.push_str("0x");
                result.push_str(&trimmed.to_lowercase());
                i += 1; // skip the 'h'
            } else {
                // Not a hex number, just copy as-is
                result.push_str(&s[start..i]);
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

/// Build IAT entry map from imports.
fn build_iat_map(info: &BinaryInfo) -> HashMap<u64, (Option<String>, String)> {
    let mut iat = HashMap::new();
    for import in &info.imports {
        if import.address > 0 {
            let module = import.module.as_ref().map(|m| normalize_module(m));
            iat.insert(import.address, (module, import.name.clone()));
        }
    }
    iat
}

/// Build string address map from IDA's string list.
fn build_string_map(idb: &IDB, info: &BinaryInfo) -> HashMap<u64, String> {
    let mut strings_at = HashMap::new();

    // Add strings from loader (which uses IDA's string list)
    for si in &info.strings {
        if si.address > 0 && !si.value.is_empty() {
            strings_at.insert(si.address, si.value.clone());
        }
    }

    strings_at
}

/// Build thunk target map from lifted functions.
fn build_thunk_map(functions: &HashMap<u64, LiftedFunction>) -> HashMap<u64, String> {
    functions
        .iter()
        .filter_map(|(&addr, f)| {
            if f.is_thunk {
                f.thunk_target.as_ref().map(|t| (addr, t.clone()))
            } else {
                None
            }
        })
        .collect()
}

/// Normalize module names (strip .dll suffix, lowercase).
fn normalize_module(module: &str) -> String {
    module
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_operand_hex_suffix() {
        assert_eq!(normalize_operand_string("0FFFFh"), "0xffff");
        assert_eq!(normalize_operand_string("0h"), "0x0");
        assert_eq!(normalize_operand_string("1234h"), "0x1234");
    }

    #[test]
    fn test_normalize_operand_memory_ref() {
        assert_eq!(
            normalize_operand_string("[rbp+8h]"),
            "[rbp+0x8]"
        );
        assert_eq!(
            normalize_operand_string("[rax+10h]"),
            "[rax+0x10]"
        );
    }

    #[test]
    fn test_normalize_operand_no_hex() {
        assert_eq!(normalize_operand_string("eax"), "eax");
        assert_eq!(normalize_operand_string("[rbp+rax]"), "[rbp+rax]");
    }

    #[test]
    fn test_normalize_operand_mixed() {
        assert_eq!(
            normalize_operand_string("dword ptr [401000h]"),
            "dword ptr [0x401000]"
        );
    }

    #[test]
    fn test_normalize_module() {
        assert_eq!(normalize_module("kernel32.dll"), "kernel32");
        assert_eq!(normalize_module("NTDLL.DLL"), "ntdll");
        assert_eq!(normalize_module("user32"), "user32");
    }
}
