//! IDA Pro lifter — produces LiftedProgram from an IDB.
//!
//! This module walks IDA's function/CFG/instruction model
//! and produces the same LiftedProgram IR that lifter.rs creates
//! from goblin+iced-x86, so that extract_from_lifted() can be reused.

use std::collections::HashMap;

use idalib::idb::IDB;
use idalib::func::FunctionFlags;
use idalib::insn::{Operand, OperandType, OperandDataType};

use capa_core::rule::ArchType;

use crate::lifter::{
    ILOperation, LiftedBasicBlock, LiftedFunction, LiftedInstruction, LiftedProgram,
};
use crate::loader::BinaryInfo;

// ---------------------------------------------------------------------------
// x86 register name lookup — maps IDA register ID + operand data type to name.
//
// IDA register IDs from intel.hpp (SDK):
//   0-7:   ax,cx,dx,bx,sp,bp,si,di  (GPR base)
//   8-15:  r8-r15
//   16-23: al,cl,dl,bl,ah,ch,dh,bh  (explicit byte regs)
//   24-27: spl,bpl,sil,dil
//   28-33: es,cs,ss,ds,fs,gs         (segment regs)
// ---------------------------------------------------------------------------

/// 64/32/16/8-bit names for GPR IDs 0-15.
/// Index by [reg_id][size_idx] where size_idx: 0=64, 1=32, 2=16, 3=8.
const GPR_NAMES: [[&str; 4]; 16] = [
    ["rax", "eax", "ax",  "al"],
    ["rcx", "ecx", "cx",  "cl"],
    ["rdx", "edx", "dx",  "dl"],
    ["rbx", "ebx", "bx",  "bl"],
    ["rsp", "esp", "sp",  "spl"],
    ["rbp", "ebp", "bp",  "bpl"],
    ["rsi", "esi", "si",  "sil"],
    ["rdi", "edi", "di",  "dil"],
    ["r8",  "r8d", "r8w", "r8b"],
    ["r9",  "r9d", "r9w", "r9b"],
    ["r10", "r10d","r10w","r10b"],
    ["r11", "r11d","r11w","r11b"],
    ["r12", "r12d","r12w","r12b"],
    ["r13", "r13d","r13w","r13b"],
    ["r14", "r14d","r14w","r14b"],
    ["r15", "r15d","r15w","r15b"],
];

/// Explicit byte register names for IDA IDs 16-27.
const BYTE_REG_NAMES: [&str; 12] = [
    "al", "cl", "dl", "bl",   // 16-19
    "ah", "ch", "dh", "bh",   // 20-23
    "spl", "bpl", "sil", "dil", // 24-27
];

/// Segment register names for IDA IDs 29-34.
/// From intel.hpp enum: R_es=29, R_cs=30, R_ss=31, R_ds=32, R_fs=33, R_gs=34.
/// (R_ip=28 sits between byte regs and segment regs.)
const SEG_REG_NAMES: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];

/// IDA segment register IDs for FS and GS (from intel.hpp: R_fs=33, R_gs=34).
/// insn_t.segpref stores the register ID directly.
const SEGPREF_FS: i32 = 33;
const SEGPREF_GS: i32 = 34;

/// Map operand data type to size index for GPR lookup.
fn dtype_to_size_idx(dtype: OperandDataType) -> usize {
    match dtype {
        OperandDataType::QWord => 0,  // 64-bit
        OperandDataType::DWord => 1,  // 32-bit
        OperandDataType::Word => 2,   // 16-bit
        OperandDataType::Byte => 3,   // 8-bit
        _ => 0,                        // default to 64-bit
    }
}

/// Get x86 register name from IDA register ID and operand data type.
fn x86_reg_name(reg_id: u16, dtype: OperandDataType) -> &'static str {
    let id = reg_id as usize;
    if id < 16 {
        GPR_NAMES[id][dtype_to_size_idx(dtype)]
    } else if id >= 16 && id < 28 {
        BYTE_REG_NAMES[id - 16]
    } else if id >= 29 && id < 35 {
        SEG_REG_NAMES[id - 29]
    } else {
        // XMM/YMM/ST/CR/DR etc — return empty, caller will use fallback
        ""
    }
}

/// Format an operand string from op_t POD fields — no FFI, pure Rust.
///
/// Produces strings compatible with what the extractor expects:
/// - Register: "rax", "esp", etc.
/// - Immediate: "0x1234"
/// - Memory: "[0x401000]" or "fs:[0x30]"
/// - Displacement: "[rbp+0x10]" or "[rsp-0x8]"
/// - Phrase: "[rax]"
/// - Near/Far: "0x401000"
fn format_operand(op: &Operand, segpref: Option<i32>, addr_dtype: OperandDataType) -> String {
    let seg_prefix = match segpref {
        Some(SEGPREF_FS) => "fs:",
        Some(SEGPREF_GS) => "gs:",
        _ => "",
    };

    match op.type_() {
        OperandType::Reg => {
            let name = x86_reg_name(op.reg().unwrap_or(0), op.dtype());
            if name.is_empty() {
                format!("reg{}", op.reg().unwrap_or(0))
            } else {
                name.to_string()
            }
        }
        OperandType::Imm => {
            let val = op.value().unwrap_or(0);
            format!("0x{:x}", val)
        }
        OperandType::Mem => {
            let addr = op.addr().unwrap_or(0);
            format!("{}[0x{:x}]", seg_prefix, addr)
        }
        OperandType::Displ => {
            let base = op.phrase().unwrap_or(0);
            let base_name = x86_reg_name(base, addr_dtype);
            let disp = op.addr().unwrap_or(0);
            let base_str = if base_name.is_empty() {
                format!("reg{}", base)
            } else {
                base_name.to_string()
            };
            if disp == 0 {
                format!("{}[{}]", seg_prefix, base_str)
            } else {
                // Check if displacement looks negative (high bit set in a
                // reasonably-sized value).  IDA stores displacements as unsigned
                // ea_t, but the extractor expects signed formatting.
                let signed = disp as i64;
                if signed < 0 && signed > -0x1_0000_0000 {
                    format!("{}[{}-0x{:x}]", seg_prefix, base_str, -signed)
                } else {
                    format!("{}[{}+0x{:x}]", seg_prefix, base_str, disp)
                }
            }
        }
        OperandType::Phrase => {
            let base = op.phrase().unwrap_or(0);
            let base_name = x86_reg_name(base, addr_dtype);
            if base_name.is_empty() {
                format!("{}[reg{}]", seg_prefix, base)
            } else {
                format!("{}[{}]", seg_prefix, base_name)
            }
        }
        OperandType::Near | OperandType::Far => {
            let addr = op.addr().unwrap_or(0);
            format!("0x{:x}", addr)
        }
        _ => {
            // IdpSpec0-5 and other processor-specific operands
            String::new()
        }
    }
}

/// Lift all functions in the IDB into a LiftedProgram.
///
/// Iterates over IDA's functions, builds CFGs via flow charts,
/// decodes instructions, and maps them to ILOperations.
pub(crate) fn lift_from_idb(idb: &IDB, info: BinaryInfo) -> LiftedProgram {
    let mut functions = HashMap::new();
    let entry_point = info.entry_point;

    // Determine addressing register size from binary architecture.
    // 32-bit binaries use esp/ebp (DWord), 64-bit use rsp/rbp (QWord).
    let addr_dtype = match info.arch {
        ArchType::I386 => OperandDataType::DWord,
        _ => OperandDataType::QWord,
    };

    for (_id, func) in idb.functions() {
        let func_addr = func.start_address();
        let func_name = func.name();
        let flags = func.flags();
        let is_thunk = flags.contains(FunctionFlags::THUNK);
        let is_library = flags.contains(FunctionFlags::LIB);

        // Build CFG and lift basic blocks
        let (basic_blocks, callees) = match func.cfg() {
            Ok(cfg) => lift_cfg(idb, &cfg, func_addr, addr_dtype),
            Err(_) => {
                // Fallback: create a single basic block for the function
                let (bb, callees) = lift_linear(idb, func_addr, func.end_address(), addr_dtype);
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
    addr_dtype: OperandDataType,
) -> (Vec<LiftedBasicBlock>, Vec<u64>) {
    let mut blocks = Vec::new();
    let mut all_callees = Vec::new();

    for (block_idx, block) in cfg.blocks().enumerate() {
        let start = block.start_address();
        let end = block.end_address();

        let (instructions, callees) = lift_instructions(idb, start, end, addr_dtype);
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
fn lift_linear(idb: &IDB, start: u64, end: u64, addr_dtype: OperandDataType) -> (LiftedBasicBlock, Vec<u64>) {
    let (instructions, callees) = lift_instructions(idb, start, end, addr_dtype);

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
fn lift_instructions(idb: &IDB, start: u64, end: u64, addr_dtype: OperandDataType) -> (Vec<LiftedInstruction>, Vec<u64>) {
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

        // Get mnemonic from IDA (1 FFI call — the only one per instruction)
        let mnemonic = insn
            .mnemonic()
            .unwrap_or_default()
            .to_lowercase();

        // Build operands from op_t POD fields — zero FFI, pure Rust formatting.
        // Previously called insn.print_operand(n) per operand (~6 FFI round-trips
        // + heap allocs), now formats directly from the decoded insn_t struct.
        let mut operands = Vec::new();
        let mut operand_values = Vec::new();
        let segpref = insn.segpref();

        for n in 0..insn.operand_count() {
            let (op_str, op_val) = if let Some(op) = insn.operand(n) {
                let s = format_operand(&op, segpref, addr_dtype);
                let v = match op.type_() {
                    OperandType::Imm => op.value().map(|v| v as i64),
                    OperandType::Near | OperandType::Far => op.addr().map(|v| v as i64),
                    OperandType::Mem | OperandType::Displ => op.addr().map(|v| v as i64),
                    _ => None,
                };
                (s, v)
            } else {
                (String::new(), None)
            };

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
    fn test_x86_reg_name_64bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::QWord), "rax");
        assert_eq!(x86_reg_name(4, OperandDataType::QWord), "rsp");
        assert_eq!(x86_reg_name(5, OperandDataType::QWord), "rbp");
        assert_eq!(x86_reg_name(8, OperandDataType::QWord), "r8");
        assert_eq!(x86_reg_name(15, OperandDataType::QWord), "r15");
    }

    #[test]
    fn test_x86_reg_name_32bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::DWord), "eax");
        assert_eq!(x86_reg_name(4, OperandDataType::DWord), "esp");
        assert_eq!(x86_reg_name(5, OperandDataType::DWord), "ebp");
        assert_eq!(x86_reg_name(8, OperandDataType::DWord), "r8d");
    }

    #[test]
    fn test_x86_reg_name_16bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::Word), "ax");
        assert_eq!(x86_reg_name(4, OperandDataType::Word), "sp");
    }

    #[test]
    fn test_x86_reg_name_8bit() {
        assert_eq!(x86_reg_name(0, OperandDataType::Byte), "al");
        assert_eq!(x86_reg_name(3, OperandDataType::Byte), "bl");
    }

    #[test]
    fn test_x86_reg_name_explicit_byte_regs() {
        assert_eq!(x86_reg_name(16, OperandDataType::Byte), "al");
        assert_eq!(x86_reg_name(20, OperandDataType::Byte), "ah");
        assert_eq!(x86_reg_name(24, OperandDataType::Byte), "spl");
    }

    #[test]
    fn test_x86_reg_name_segment_regs() {
        assert_eq!(x86_reg_name(29, OperandDataType::Word), "es");
        assert_eq!(x86_reg_name(33, OperandDataType::Word), "fs");
        assert_eq!(x86_reg_name(34, OperandDataType::Word), "gs");
    }

    #[test]
    fn test_x86_reg_name_unknown() {
        assert_eq!(x86_reg_name(100, OperandDataType::QWord), "");
    }

    #[test]
    fn test_dtype_to_size_idx() {
        assert_eq!(dtype_to_size_idx(OperandDataType::QWord), 0);
        assert_eq!(dtype_to_size_idx(OperandDataType::DWord), 1);
        assert_eq!(dtype_to_size_idx(OperandDataType::Word), 2);
        assert_eq!(dtype_to_size_idx(OperandDataType::Byte), 3);
    }

    #[test]
    fn test_normalize_module() {
        assert_eq!(normalize_module("kernel32.dll"), "kernel32");
        assert_eq!(normalize_module("NTDLL.DLL"), "ntdll");
        assert_eq!(normalize_module("user32"), "user32");
    }
}
