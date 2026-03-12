//! Binary lifting and disassembly
//!
//! Provides disassembly backends:
//! - iced (default): Blazingly fast pure Rust x86/x64 disassembler (>250 MB/s)
//! - capstone: Multi-architecture disassembler for ARM, AArch64, MIPS, PPC
//!
//! Implements proper function boundary detection using:
//! - Export addresses
//! - Entry point
//! - PE .pdata exception data (x64)
//! - Call target discovery during recursive descent disassembly
//! - Function prologue pattern matching

use crate::loader::{BinaryInfo, LoaderError};
use capa_core::rule::ArchType;
use goblin::Object;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

/// Lifted program representation
#[derive(Debug)]
pub struct LiftedProgram {
    /// Functions by address
    pub functions: HashMap<u64, LiftedFunction>,
    /// Entry point address
    pub entry_point: u64,
    /// Binary metadata
    pub info: BinaryInfo,
    /// Map of address -> string value found at that address (for pointer-based string detection)
    pub strings_at: HashMap<u64, String>,
    /// Map of IAT entry address -> (module, function_name) for resolving indirect calls
    pub iat_entries: HashMap<u64, (Option<String>, String)>,
    /// Map of thunk function address -> API name it jumps to
    pub thunk_targets: HashMap<u64, String>,
}

/// Lifted function with IL
#[derive(Debug)]
pub struct LiftedFunction {
    /// Function address
    pub address: u64,
    /// Function name (if known)
    pub name: Option<String>,
    /// Basic blocks
    pub basic_blocks: Vec<LiftedBasicBlock>,
    /// Addresses of called functions
    pub callees: Vec<u64>,
    /// Addresses of calling functions
    pub callers: Vec<u64>,
    /// Whether this function is a thunk (single jmp to IAT/import)
    pub is_thunk: bool,
    /// If this is a thunk, the resolved API name
    pub thunk_target: Option<String>,
    /// Whether this function was identified as a library function (e.g., via FLIRT)
    pub is_library: bool,
}

/// Lifted basic block
#[derive(Debug)]
pub struct LiftedBasicBlock {
    /// Block index within function
    pub index: usize,
    /// Start address
    pub address: u64,
    /// End address
    pub end_address: u64,
    /// Instructions in this block
    pub instructions: Vec<LiftedInstruction>,
    /// Successor block indices
    pub successors: Vec<usize>,
    /// Predecessor block indices
    pub predecessors: Vec<usize>,
    /// Is this a loop header?
    pub is_loop_header: bool,
}

/// Lifted instruction with IL operations
#[derive(Debug)]
pub struct LiftedInstruction {
    /// Instruction address
    pub address: u64,
    /// Original mnemonic
    pub mnemonic: String,
    /// Operand strings
    pub operands: Vec<String>,
    /// Numeric operand values
    pub operand_values: Vec<Option<i64>>,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// IL operations for this instruction
    pub operations: Vec<ILOperation>,
}

/// Simplified IL operation for feature extraction
#[derive(Debug, Clone)]
pub enum ILOperation {
    /// Assignment: dst = src
    Assign { dst: String, src_constants: Vec<i64> },
    /// Memory store
    Store { address_constants: Vec<i64> },
    /// Memory load
    Load { dst: String, address_constants: Vec<i64> },
    /// Branch/call
    Branch { target: Option<u64>, is_call: bool },
    /// XOR operation (for nzxor detection)
    Xor { operands: Vec<String>, constants: Vec<i64> },
    /// Other operation
    Other,
}

/// Lift a binary - selects backend based on architecture
///
/// - x86/x64: Uses iced (blazingly fast)
/// - ARM/AArch64/MIPS/PPC: Uses capstone (multi-arch support)
/// - Shellcode: Treated as raw code starting at offset 0
pub fn lift_binary(bytes: &[u8], info: &BinaryInfo) -> Result<LiftedProgram, LoaderError> {
    // Handle shellcode specially - no binary format to parse
    if info.format.is_shellcode() {
        return lift_shellcode(bytes, info);
    }

    // Route to appropriate disassembler based on architecture
    if info.arch.is_x86() {
        lift_with_iced(bytes, info)
    } else {
        // ARM, AArch64, MIPS, PPC: Use capstone
        lift_with_capstone(bytes, info)
    }
}

/// Lift raw shellcode (no PE/ELF headers)
/// Treats the entire file as executable code starting at offset 0
fn lift_shellcode(bytes: &[u8], info: &BinaryInfo) -> Result<LiftedProgram, LoaderError> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Mnemonic, OpKind};
    use capa_core::rule::ArchType;

    let bitness = match info.arch {
        ArchType::I386 => 32,
        ArchType::Amd64 => 64,
        _ => return Err(LoaderError::ParseError("Shellcode only supports x86/x64 architecture".to_string())),
    };

    log::info!("[shellcode] Lifting {}-bit shellcode ({} bytes)", bitness, bytes.len());

    let mut functions = HashMap::new();
    let entry_point = 0u64; // Shellcode starts at offset 0
    let mut function_starts: HashSet<u64> = HashSet::new();

    // Entry point is the start of shellcode
    function_starts.insert(entry_point);

    // Entire shellcode is one executable section
    let _executable_sections = vec![ExecutableSection {
        rva: 0,
        file_offset: 0,
        size: bytes.len(),
    }];

    // Build section lookup helpers
    let is_executable = |addr: u64| -> bool {
        addr < bytes.len() as u64
    };

    let get_bytes_at_rva = |rva: u64| -> Option<&[u8]> {
        if rva < bytes.len() as u64 {
            Some(&bytes[rva as usize..])
        } else {
            None
        }
    };

    // Discover functions via call target analysis
    let mut discovered_functions: HashSet<u64> = function_starts.clone();
    let mut worklist: VecDeque<u64> = function_starts.iter().copied().collect();
    let mut processed: HashSet<u64> = HashSet::new();
    let mut all_callees: HashMap<u64, Vec<u64>> = HashMap::new();

    while let Some(func_addr) = worklist.pop_front() {
        if processed.contains(&func_addr) {
            continue;
        }
        processed.insert(func_addr);

        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let mut decoder = Decoder::with_ip(bitness, func_bytes, func_addr, DecoderOptions::NONE);
            let mut _seen_ret = false;
            let max_instructions = 10000; // Limit for shellcode
            let mut insn_count = 0;

            while decoder.can_decode() && insn_count < max_instructions {
                let instruction = decoder.decode();
                insn_count += 1;

                // Look for call targets to add as function starts
                if instruction.mnemonic() == Mnemonic::Call {
                    let target = if instruction.op0_kind() == OpKind::NearBranch64 ||
                                   instruction.op0_kind() == OpKind::NearBranch32 {
                        Some(instruction.near_branch_target())
                    } else {
                        None
                    };

                    if let Some(target) = target {
                        if is_executable(target) && !discovered_functions.contains(&target) {
                            discovered_functions.insert(target);
                            worklist.push_back(target);
                        }
                    }
                }

                // Stop at return
                if instruction.flow_control() == FlowControl::Return {
                    _seen_ret = true;
                    break;
                }

                // Stop if we hit another function
                if discovered_functions.contains(&instruction.ip()) && instruction.ip() != func_addr {
                    break;
                }
            }
        }
    }

    log::info!("[shellcode] Discovered {} functions", discovered_functions.len());

    // Now disassemble each function
    for func_addr in discovered_functions.iter().copied() {
        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let mut decoder = Decoder::with_ip(bitness, func_bytes, func_addr, DecoderOptions::NONE);
            let mut instructions = Vec::new();
            let mut branch_targets: HashSet<u64> = HashSet::new();
            let mut callees = Vec::new();
            let max_instructions = 10000;

            for _ in 0..max_instructions {
                if !decoder.can_decode() {
                    break;
                }

                let instruction = decoder.decode();
                let mnemonic = format!("{:?}", instruction.mnemonic()).to_lowercase();

                // Collect operand info
                let mut op_parts = Vec::new();
                let mut operand_values = Vec::new();
                for i in 0..instruction.op_count() {
                    let mut formatter = iced_x86::IntelFormatter::new();
                    let mut op_str = String::new();
                    let _ = formatter.format_operand(&instruction, &mut op_str, i);
                    let op_val = match instruction.op_kind(i) {
                        OpKind::Immediate8 | OpKind::Immediate16 |
                        OpKind::Immediate32 | OpKind::Immediate64 |
                        OpKind::Immediate8to16 | OpKind::Immediate8to32 |
                        OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
                            Some(instruction.immediate(i) as i64)
                        }
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                            Some(instruction.near_branch_target() as i64)
                        }
                        _ => None,
                    };
                    op_parts.push(op_str);
                    operand_values.push(op_val);
                }

                // Track branches for basic block splitting
                match instruction.flow_control() {
                    FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                        if instruction.op0_kind() == OpKind::NearBranch64 ||
                           instruction.op0_kind() == OpKind::NearBranch32 ||
                           instruction.op0_kind() == OpKind::NearBranch16 {
                            let target = instruction.near_branch_target();
                            branch_targets.insert(target);
                            if instruction.mnemonic() == Mnemonic::Call {
                                callees.push(target);
                            }
                        }
                    }
                    _ => {}
                }

                let mut operations = Vec::new();
                let is_call = instruction.mnemonic() == Mnemonic::Call;
                let is_branch = matches!(instruction.flow_control(),
                    FlowControl::Call | FlowControl::ConditionalBranch |
                    FlowControl::UnconditionalBranch | FlowControl::Return);

                if is_branch {
                    let target = if instruction.op0_kind() == OpKind::NearBranch64 ||
                                    instruction.op0_kind() == OpKind::NearBranch32 {
                        Some(instruction.near_branch_target())
                    } else {
                        None
                    };
                    operations.push(ILOperation::Branch { target, is_call });
                }

                // XOR detection for nzxor
                if instruction.mnemonic() == Mnemonic::Xor {
                    operations.push(ILOperation::Xor {
                        operands: op_parts.clone(),
                        constants: vec![],
                    });
                }

                // Get raw bytes
                let insn_start = (instruction.ip() - func_addr) as usize;
                let insn_len = instruction.len();
                let raw_bytes = if insn_start + insn_len <= func_bytes.len() {
                    func_bytes[insn_start..insn_start + insn_len].to_vec()
                } else {
                    vec![]
                };

                instructions.push(LiftedInstruction {
                    address: instruction.ip(),
                    mnemonic,
                    operands: op_parts,
                    operand_values,
                    bytes: raw_bytes,
                    operations,
                });

                // Stop at ret
                if instruction.flow_control() == FlowControl::Return {
                    break;
                }
            }

            // Build basic blocks
            let mut basic_blocks = Vec::new();
            let mut current_block_instrs = Vec::new();
            let mut current_block_start = func_addr;
            let mut block_index = 0;

            for insn in instructions {
                let is_new_block = branch_targets.contains(&insn.address) && !current_block_instrs.is_empty();

                if is_new_block {
                    let end_addr = current_block_instrs.last().map(|i: &LiftedInstruction| i.address).unwrap_or(current_block_start);
                    basic_blocks.push(LiftedBasicBlock {
                        index: block_index,
                        address: current_block_start,
                        end_address: end_addr,
                        instructions: current_block_instrs,
                        successors: vec![],
                        predecessors: vec![],
                        is_loop_header: false,
                    });
                    block_index += 1;
                    current_block_instrs = Vec::new();
                    current_block_start = insn.address;
                }

                let is_terminator = insn.mnemonic.starts_with('j') ||
                                   insn.mnemonic == "ret" ||
                                   insn.mnemonic == "call";
                current_block_instrs.push(insn);

                if is_terminator && !current_block_instrs.is_empty() {
                    let end_addr = current_block_instrs.last().map(|i| i.address).unwrap_or(current_block_start);
                    basic_blocks.push(LiftedBasicBlock {
                        index: block_index,
                        address: current_block_start,
                        end_address: end_addr,
                        instructions: current_block_instrs,
                        successors: vec![],
                        predecessors: vec![],
                        is_loop_header: false,
                    });
                    block_index += 1;
                    current_block_instrs = Vec::new();
                    current_block_start = end_addr + 1;
                }
            }

            // Add remaining instructions as final block
            if !current_block_instrs.is_empty() {
                let end_addr = current_block_instrs.last().map(|i| i.address).unwrap_or(current_block_start);
                basic_blocks.push(LiftedBasicBlock {
                    index: block_index,
                    address: current_block_start,
                    end_address: end_addr,
                    instructions: current_block_instrs,
                    successors: vec![],
                    predecessors: vec![],
                    is_loop_header: false,
                });
            }

            // Detect loops
            detect_loops(&mut basic_blocks);

            if !basic_blocks.is_empty() {
                all_callees.insert(func_addr, callees.clone());
                functions.insert(func_addr, LiftedFunction {
                    address: func_addr,
                    name: None,
                    basic_blocks,
                    callees,
                    callers: vec![],
                    is_thunk: false,
                    thunk_target: None,
                    is_library: false,
                });
            }
        }
    }

    // Build caller relationships
    for (&caller_addr, callees) in &all_callees {
        for &callee_addr in callees {
            if let Some(callee_func) = functions.get_mut(&callee_addr) {
                if !callee_func.callers.contains(&caller_addr) {
                    callee_func.callers.push(caller_addr);
                }
            }
        }
    }

    log::info!("[shellcode] Created {} function objects", functions.len());

    Ok(LiftedProgram {
        functions,
        entry_point,
        info: info.clone(),
        strings_at: HashMap::new(),
        iat_entries: HashMap::new(),
        thunk_targets: HashMap::new(),
    })
}

/// Lift using iced disassembler (blazingly fast, >250 MB/s)
fn lift_with_iced(bytes: &[u8], info: &BinaryInfo) -> Result<LiftedProgram, LoaderError> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};
    use capa_core::rule::ArchType;

    let bitness = match info.arch {
        ArchType::I386 => 32,
        ArchType::Amd64 => 64,
        _ => return Err(LoaderError::ParseError("Unsupported architecture".to_string())),
    };

    // Parse binary to find code sections and function entry points
    let obj = Object::parse(bytes).map_err(|e| LoaderError::ParseError(e.to_string()))?;

    let mut functions = HashMap::new();
    let mut entry_point = 0u64;
    let mut function_starts: HashSet<u64> = HashSet::new();
    let mut executable_sections: Vec<ExecutableSection> = Vec::new();

    match &obj {
        Object::PE(pe) => {
            entry_point = pe.entry as u64;

            // 1. Add entry point as function start
            function_starts.insert(entry_point);

            // 2. Add all exports as function starts
            for export in &info.exports {
                if export.address > 0 && !export.is_forwarded {
                    function_starts.insert(export.address);
                }
            }

            // 3. Parse .pdata section for x64 PE (contains runtime function table)
            if bitness == 64 {
                if let Some(pdata_funcs) = parse_pdata_section(pe, bytes) {
                    for rf in pdata_funcs {
                        function_starts.insert(rf.begin_address as u64);
                    }
                }
            }

            // Collect executable sections
            for section in &pe.sections {
                if section.characteristics & 0x20000000 != 0 {
                    let section_offset = section.pointer_to_raw_data as usize;
                    let section_size = section.size_of_raw_data as usize;

                    if section_offset + section_size <= bytes.len() {
                        executable_sections.push(ExecutableSection {
                            rva: section.virtual_address as u64,
                            file_offset: section_offset,
                            size: section_size,
                        });
                    }
                }
            }
        }
        Object::Elf(elf) => {
            entry_point = elf.entry;
            function_starts.insert(entry_point);

            // Add exports as function starts
            for export in &info.exports {
                if export.address > 0 {
                    function_starts.insert(export.address);
                }
            }

            // Parse symbol table for function symbols (critical for static binaries)
            for sym in &elf.syms {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value > 0 {
                    function_starts.insert(sym.st_value);
                }
            }

            // Also check dynamic symbols
            for sym in &elf.dynsyms {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value > 0 {
                    function_starts.insert(sym.st_value);
                }
            }

            // Collect executable sections
            for section in &elf.section_headers {
                if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
                    let section_offset = section.sh_offset as usize;
                    let section_size = section.sh_size as usize;

                    if section_offset + section_size <= bytes.len() {
                        executable_sections.push(ExecutableSection {
                            rva: section.sh_addr,
                            file_offset: section_offset,
                            size: section_size,
                        });
                    }
                }
            }

            // Check for Go binary and parse gopclntab
            let mut is_go_binary = false;
            for section in &elf.section_headers {
                let section_offset = section.sh_offset as usize;
                let section_size = section.sh_size as usize;
                if section_offset + section_size <= bytes.len() && section_size > 0 {
                    let section_bytes = &bytes[section_offset..section_offset + section_size.min(10000)];
                    if section_bytes.windows(13).any(|w| w == b"Go build ID: ") {
                        is_go_binary = true;
                        break;
                    }
                }
            }

            if is_go_binary {
                eprintln!("[ELF] Detected Go ELF binary, parsing gopclntab...");
                if let Some(go_funcs) = find_go_functions_from_pclntab_elf(bytes, elf) {
                    eprintln!("[ELF] Found {} functions from gopclntab", go_funcs.len());
                    for func_addr in go_funcs {
                        if func_addr > 0 {
                            function_starts.insert(func_addr);
                        }
                    }
                }
            }

            // Parse .eh_frame_hdr for function discovery (critical for stripped binaries)
            if let Some(eh_funcs) = parse_eh_frame_hdr(bytes, elf) {
                eprintln!("[ELF] Found {} functions from .eh_frame_hdr", eh_funcs.len());
                for func_addr in eh_funcs {
                    function_starts.insert(func_addr);
                }
            }

            // Parse .init_array and .fini_array for additional entry points
            for section in &elf.section_headers {
                let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
                if section_name == ".init_array" || section_name == ".fini_array" {
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    let ptr_size = if elf.is_64 { 8 } else { 4 };

                    if offset + size <= bytes.len() {
                        let arr_bytes = &bytes[offset..offset + size];
                        for i in (0..size).step_by(ptr_size) {
                            if i + ptr_size <= arr_bytes.len() {
                                let addr = if ptr_size == 8 {
                                    u64::from_le_bytes(arr_bytes[i..i+8].try_into().unwrap_or([0;8]))
                                } else {
                                    u32::from_le_bytes(arr_bytes[i..i+4].try_into().unwrap_or([0;4])) as u64
                                };
                                if addr > 0 {
                                    function_starts.insert(addr);
                                }
                            }
                        }
                    }
                }
            }

            eprintln!("[ELF] ELF function seeds: {} (from symtab + gopclntab + eh_frame)", function_starts.len());
        }
        _ => {}
    }

    // Build section lookup helpers
    let section_ranges: Vec<(u64, u64)> = executable_sections.iter()
        .map(|s| (s.rva, s.rva + s.size as u64))
        .collect();

    let is_executable = |addr: u64| -> bool {
        section_ranges.iter().any(|(start, end)| addr >= *start && addr < *end)
    };

    let get_bytes_at_rva = |rva: u64| -> Option<&[u8]> {
        for section in &executable_sections {
            let section_end = section.rva + section.size as u64;
            if rva >= section.rva && rva < section_end {
                let offset = (rva - section.rva) as usize;
                let section_bytes = &bytes[section.file_offset..section.file_offset + section.size];
                return Some(&section_bytes[offset..]);
            }
        }
        None
    };

    // 4. Discover more functions via call target analysis using iced
    let mut discovered_functions: HashSet<u64> = function_starts.clone();
    let mut worklist: VecDeque<u64> = function_starts.iter().copied().collect();
    let mut processed: HashSet<u64> = HashSet::new();

    while let Some(func_addr) = worklist.pop_front() {
        if processed.contains(&func_addr) {
            continue;
        }
        processed.insert(func_addr);

        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let max_size = func_bytes.len().min(65536);
            let mut decoder = Decoder::with_ip(bitness, &func_bytes[..max_size], func_addr, DecoderOptions::NONE);

            for instruction in &mut decoder {
                // Check for call instructions
                if instruction.mnemonic() == Mnemonic::Call {
                    if instruction.op0_kind() == OpKind::NearBranch64 ||
                       instruction.op0_kind() == OpKind::NearBranch32 ||
                       instruction.op0_kind() == OpKind::NearBranch16 {
                        let target = instruction.near_branch_target();
                        if is_executable(target) && !discovered_functions.contains(&target) {
                            discovered_functions.insert(target);
                            worklist.push_back(target);
                        }
                    }
                }

                // Stop at ret
                match instruction.flow_control() {
                    FlowControl::Return => break,
                    FlowControl::UnconditionalBranch => {
                        // Check for tail calls
                        if instruction.op0_kind() == OpKind::NearBranch64 ||
                           instruction.op0_kind() == OpKind::NearBranch32 {
                            let target = instruction.near_branch_target();
                            if target < func_addr || target > func_addr + max_size as u64 {
                                if is_executable(target) && !discovered_functions.contains(&target) {
                                    discovered_functions.insert(target);
                                    worklist.push_back(target);
                                }
                                break;
                            }
                        } else {
                            break; // Indirect jump
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 5. Limited prologue-based gap analysis (only for true gaps)
    let initial_count = discovered_functions.len();
    let skip_gap_analysis = initial_count > 100;

    if !skip_gap_analysis {
        let mut sorted_funcs: Vec<u64> = discovered_functions.iter().copied().collect();
        sorted_funcs.sort();

        for section in &executable_sections {
            let section_start = section.rva;
            let section_end = section.rva + section.size as u64;
            let section_bytes = &bytes[section.file_offset..section.file_offset + section.size];

            let mut gap_start = section_start;
            for &func_addr in &sorted_funcs {
                if func_addr < section_start {
                    continue;
                }
                if func_addr >= section_end {
                    break;
                }

                if func_addr > gap_start {
                    let gap_size = func_addr - gap_start;
                    if gap_size >= 16 && gap_size <= 4096 {
                        let gap_offset = (gap_start - section.rva) as usize;
                        if gap_offset < section_bytes.len() {
                            let gap_bytes = &section_bytes[gap_offset..];
                            if let Some(func_offset) = find_function_in_gap(gap_bytes, gap_start, bitness, gap_size as usize) {
                                discovered_functions.insert(gap_start + func_offset as u64);
                            }
                        }
                    }
                }
                gap_start = func_addr + 1;
            }
        }
    }

    log::info!("iced discovered {} function entry points", discovered_functions.len());

    // 6. Create function objects
    let mut all_callees: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut func_addrs: Vec<u64> = discovered_functions.iter().copied().collect();
    func_addrs.sort();

    for (i, &func_addr) in func_addrs.iter().enumerate() {
        let estimated_end = func_addrs.get(i + 1).copied().unwrap_or_else(|| {
            section_ranges.iter()
                .find(|(start, end)| func_addr >= *start && func_addr < *end)
                .map(|(_, end)| *end)
                .unwrap_or(func_addr + 4096)
        });

        let max_size = (estimated_end - func_addr).min(65536) as usize;

        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let actual_size = func_bytes.len().min(max_size);
            let mut decoder = Decoder::with_ip(bitness, &func_bytes[..actual_size], func_addr, DecoderOptions::NONE);

            let mut instructions = Vec::new();
            let mut callees = Vec::new();
            let mut branch_targets: HashSet<u64> = HashSet::new();

            for instruction in &mut decoder {
                if instruction.is_invalid() {
                    break;
                }

                let mnemonic = format!("{:?}", instruction.mnemonic()).to_lowercase();
                let mut op_parts = Vec::new();
                let mut operand_values: Vec<Option<i64>> = Vec::new();

                for i in 0..instruction.op_count() {
                    let op_kind = instruction.op_kind(i);
                    let (op_str, op_val) = format_operand(&instruction, i, op_kind);
                    if !op_str.is_empty() {
                        op_parts.push(op_str);
                    }
                    operand_values.push(op_val);
                }

                // Track branches
                match instruction.flow_control() {
                    FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                        if instruction.op0_kind() == OpKind::NearBranch64 ||
                           instruction.op0_kind() == OpKind::NearBranch32 ||
                           instruction.op0_kind() == OpKind::NearBranch16 {
                            let target = instruction.near_branch_target();
                            branch_targets.insert(target);
                            if instruction.mnemonic() == Mnemonic::Call {
                                callees.push(target);
                            }
                        }
                    }
                    _ => {}
                }

                let mut operations = Vec::new();
                let is_call = instruction.mnemonic() == Mnemonic::Call;
                let is_branch = matches!(instruction.flow_control(),
                    FlowControl::Call | FlowControl::ConditionalBranch |
                    FlowControl::UnconditionalBranch | FlowControl::Return);

                if is_branch {
                    let target = if instruction.op0_kind() == OpKind::NearBranch64 ||
                                    instruction.op0_kind() == OpKind::NearBranch32 {
                        Some(instruction.near_branch_target())
                    } else {
                        None
                    };
                    operations.push(ILOperation::Branch { target, is_call });
                }

                // XOR detection
                if instruction.mnemonic() == Mnemonic::Xor {
                    operations.push(ILOperation::Xor {
                        operands: op_parts.clone(),
                        constants: vec![],
                    });
                }

                // Get raw bytes
                let insn_start = (instruction.ip() - func_addr) as usize;
                let insn_len = instruction.len();
                let raw_bytes = if insn_start + insn_len <= func_bytes.len() {
                    func_bytes[insn_start..insn_start + insn_len].to_vec()
                } else {
                    vec![]
                };

                instructions.push(LiftedInstruction {
                    address: instruction.ip(),
                    mnemonic,
                    operands: op_parts,
                    operand_values,
                    bytes: raw_bytes,
                    operations,
                });

                // Stop at ret or next function
                if instruction.flow_control() == FlowControl::Return {
                    break;
                }
                if discovered_functions.contains(&(instruction.ip() + instruction.len() as u64)) {
                    break;
                }
            }

            // Build basic blocks
            let mut basic_blocks = Vec::new();
            let mut current_block_instrs = Vec::new();
            let mut current_block_start = func_addr;
            let mut block_index = 0;

            for insn in instructions {
                let is_new_block = branch_targets.contains(&insn.address) && !current_block_instrs.is_empty();

                if is_new_block {
                    let end_addr = current_block_instrs.last().map(|i: &LiftedInstruction| i.address).unwrap_or(current_block_start);
                    basic_blocks.push(LiftedBasicBlock {
                        index: block_index,
                        address: current_block_start,
                        end_address: end_addr,
                        instructions: current_block_instrs,
                        successors: vec![],
                        predecessors: vec![],
                        is_loop_header: false,
                    });
                    block_index += 1;
                    current_block_instrs = Vec::new();
                    current_block_start = insn.address;
                }

                let is_terminator = insn.mnemonic.starts_with('j') ||
                                   insn.mnemonic == "ret" ||
                                   insn.mnemonic == "call";
                current_block_instrs.push(insn);

                if is_terminator && !current_block_instrs.is_empty() {
                    let end_addr = current_block_instrs.last().map(|i| i.address).unwrap_or(current_block_start);
                    basic_blocks.push(LiftedBasicBlock {
                        index: block_index,
                        address: current_block_start,
                        end_address: end_addr,
                        instructions: current_block_instrs,
                        successors: vec![],
                        predecessors: vec![],
                        is_loop_header: false,
                    });
                    block_index += 1;
                    current_block_instrs = Vec::new();
                    current_block_start = end_addr + 1;
                }
            }

            if !current_block_instrs.is_empty() {
                let end_addr = current_block_instrs.last().map(|i| i.address).unwrap_or(current_block_start);
                basic_blocks.push(LiftedBasicBlock {
                    index: block_index,
                    address: current_block_start,
                    end_address: end_addr,
                    instructions: current_block_instrs,
                    successors: vec![],
                    predecessors: vec![],
                    is_loop_header: false,
                });
            }

            detect_loops(&mut basic_blocks);

            if !basic_blocks.is_empty() {
                let func_name = info.exports.iter()
                    .find(|e| e.address == func_addr)
                    .map(|e| e.name.clone());

                all_callees.insert(func_addr, callees.clone());
                functions.insert(func_addr, LiftedFunction {
                    address: func_addr,
                    name: func_name,
                    basic_blocks,
                    callees,
                    callers: vec![],
                    is_thunk: false,
                    thunk_target: None,
                    is_library: false,
                });
            }
        }
    }

    // 7. Build caller relationships
    for (&caller_addr, callees) in &all_callees {
        for &callee_addr in callees {
            if let Some(callee_func) = functions.get_mut(&callee_addr) {
                if !callee_func.callers.contains(&caller_addr) {
                    callee_func.callers.push(caller_addr);
                }
            }
        }
    }

    log::info!("iced created {} function objects", functions.len());

    // 8. Build IAT entry map and detect thunks
    let iat_entries = build_iat_map(info);
    let strings_at = build_string_map(bytes, info);
    let thunk_targets = detect_thunks(&mut functions, &iat_entries);

    Ok(LiftedProgram {
        functions,
        entry_point,
        info: info.clone(),
        strings_at,
        iat_entries,
        thunk_targets,
    })
}

/// Lift using capstone disassembler for non-x86 architectures (ARM, AArch64, MIPS, PPC)
fn lift_with_capstone(bytes: &[u8], info: &BinaryInfo) -> Result<LiftedProgram, LoaderError> {
    use capstone::prelude::*;

    // Create capstone instance based on architecture
    let cs = match info.arch {
        ArchType::Arm => {
            Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| LoaderError::ParseError(format!("Failed to create ARM disassembler: {}", e)))?
        }
        ArchType::Arm64 => {
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| LoaderError::ParseError(format!("Failed to create AArch64 disassembler: {}", e)))?
        }
        ArchType::Mips => {
            // Detect endianness from ELF - default to little endian
            let mode = arch::mips::ArchMode::Mips32;
            Capstone::new()
                .mips()
                .mode(mode)
                .detail(true)
                .build()
                .map_err(|e| LoaderError::ParseError(format!("Failed to create MIPS disassembler: {}", e)))?
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            let mode = if matches!(info.arch, ArchType::Ppc64) {
                arch::ppc::ArchMode::Mode64
            } else {
                arch::ppc::ArchMode::Mode32
            };
            Capstone::new()
                .ppc()
                .mode(mode)
                .detail(true)
                .build()
                .map_err(|e| LoaderError::ParseError(format!("Failed to create PPC disassembler: {}", e)))?
        }
        _ => {
            return Err(LoaderError::ParseError(format!(
                "Unsupported architecture for capstone: {:?}",
                info.arch
            )));
        }
    };

    // Parse binary to find code sections and entry points
    let obj = Object::parse(bytes).map_err(|e| LoaderError::ParseError(e.to_string()))?;

    let mut functions = HashMap::new();
    let mut entry_point = 0u64;
    let mut function_starts: HashSet<u64> = HashSet::new();
    let mut executable_sections: Vec<ExecutableSection> = Vec::new();

    match &obj {
        Object::Elf(elf) => {
            entry_point = elf.entry;
            function_starts.insert(entry_point);

            // Add all exports as function starts
            for export in &info.exports {
                if export.address > 0 {
                    function_starts.insert(export.address);
                }
            }

            // Add symbols from symbol table
            for sym in &elf.syms {
                if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value > 0 {
                    function_starts.insert(sym.st_value);
                }
            }

            // Collect executable sections
            for section in &elf.section_headers {
                if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
                    let section_offset = section.sh_offset as usize;
                    let section_size = section.sh_size as usize;

                    if section_offset + section_size <= bytes.len() {
                        executable_sections.push(ExecutableSection {
                            rva: section.sh_addr,
                            file_offset: section_offset,
                            size: section_size,
                        });
                    }
                }
            }
        }
        Object::PE(pe) => {
            entry_point = pe.entry as u64;
            function_starts.insert(entry_point);

            for export in &info.exports {
                if export.address > 0 && !export.is_forwarded {
                    function_starts.insert(export.address);
                }
            }

            for section in &pe.sections {
                if section.characteristics & 0x20000000 != 0 {
                    let section_offset = section.pointer_to_raw_data as usize;
                    let section_size = section.size_of_raw_data as usize;

                    if section_offset + section_size <= bytes.len() {
                        executable_sections.push(ExecutableSection {
                            rva: section.virtual_address as u64,
                            file_offset: section_offset,
                            size: section_size,
                        });
                    }
                }
            }
        }
        _ => {}
    }

    // Build section lookup helpers
    let section_ranges: Vec<(u64, u64)> = executable_sections
        .iter()
        .map(|s| (s.rva, s.rva + s.size as u64))
        .collect();

    let is_executable = |addr: u64| -> bool {
        section_ranges
            .iter()
            .any(|(start, end)| addr >= *start && addr < *end)
    };

    let get_bytes_at_rva = |rva: u64| -> Option<&[u8]> {
        for section in &executable_sections {
            let section_end = section.rva + section.size as u64;
            if rva >= section.rva && rva < section_end {
                let offset = (rva - section.rva) as usize;
                let section_bytes = &bytes[section.file_offset..section.file_offset + section.size];
                return Some(&section_bytes[offset..]);
            }
        }
        None
    };

    eprintln!(
        "[capstone] Disassembling {:?} binary with {} initial function seeds",
        info.arch,
        function_starts.len()
    );

    // Discover more functions via call target analysis
    let mut discovered_functions: HashSet<u64> = function_starts.clone();
    let mut worklist: VecDeque<u64> = function_starts.iter().copied().collect();
    let mut processed: HashSet<u64> = HashSet::new();

    while let Some(func_addr) = worklist.pop_front() {
        if processed.contains(&func_addr) {
            continue;
        }
        processed.insert(func_addr);

        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let max_size = func_bytes.len().min(65536);

            if let Ok(insns) = cs.disasm_all(&func_bytes[..max_size], func_addr) {
                for insn in insns.iter() {
                    // Check for branch/call instructions to discover new functions
                    if let Some(target) = get_capstone_branch_target(&cs, &insn, info.arch) {
                        if is_executable(target) && !discovered_functions.contains(&target) {
                            // Only add if it looks like a call (not a conditional branch)
                            if is_capstone_call_instruction(&insn, info.arch) {
                                discovered_functions.insert(target);
                                worklist.push_back(target);
                            }
                        }
                    }

                    // Stop at return instructions
                    if is_capstone_return_instruction(&insn, info.arch) {
                        break;
                    }
                }
            }
        }
    }

    eprintln!("[capstone] Discovered {} functions", discovered_functions.len());

    // Create function objects with full disassembly
    let mut all_callees: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut func_addrs: Vec<u64> = discovered_functions.iter().copied().collect();
    func_addrs.sort();

    for (i, &func_addr) in func_addrs.iter().enumerate() {
        let estimated_end = func_addrs.get(i + 1).copied().unwrap_or_else(|| {
            section_ranges
                .iter()
                .find(|(start, end)| func_addr >= *start && func_addr < *end)
                .map(|(_, end)| *end)
                .unwrap_or(func_addr + 4096)
        });

        let max_size = (estimated_end - func_addr).min(65536) as usize;

        if let Some(func_bytes) = get_bytes_at_rva(func_addr) {
            let actual_size = func_bytes.len().min(max_size);

            if let Ok(insns) = cs.disasm_all(&func_bytes[..actual_size], func_addr) {
                let mut instructions = Vec::new();
                let mut callees = Vec::new();
                let mut branch_targets: HashSet<u64> = HashSet::new();

                for insn in insns.iter() {
                    let mnemonic = insn.mnemonic().unwrap_or("").to_lowercase();
                    let op_str = insn.op_str().unwrap_or("");

                    // Parse operands
                    let (operands, operand_values) = parse_capstone_operands(op_str);

                    // Track branches for basic block splitting
                    if let Some(target) = get_capstone_branch_target(&cs, &insn, info.arch) {
                        branch_targets.insert(target);
                        if is_capstone_call_instruction(&insn, info.arch) {
                            callees.push(target);
                        }
                    }

                    // Build IL operations
                    let mut operations = Vec::new();
                    let is_call = is_capstone_call_instruction(&insn, info.arch);
                    let is_branch = is_capstone_branch_instruction(&insn, info.arch);

                    if is_branch || is_call {
                        let target = get_capstone_branch_target(&cs, &insn, info.arch);
                        operations.push(ILOperation::Branch { target, is_call });
                    }

                    // XOR detection for feature extraction
                    if mnemonic.starts_with("eor") || mnemonic == "xor" {
                        operations.push(ILOperation::Xor {
                            operands: operands.clone(),
                            constants: vec![],
                        });
                    }

                    instructions.push(LiftedInstruction {
                        address: insn.address(),
                        mnemonic,
                        operands,
                        operand_values,
                        bytes: insn.bytes().to_vec(),
                        operations,
                    });

                    // Stop at return or next function
                    if is_capstone_return_instruction(&insn, info.arch) {
                        break;
                    }
                    if discovered_functions.contains(&(insn.address() + insn.len() as u64)) {
                        break;
                    }
                }

                // Build basic blocks
                let mut basic_blocks = Vec::new();
                let mut current_block_instrs = Vec::new();
                let mut current_block_start = func_addr;
                let mut block_index = 0;

                for insn in instructions {
                    let is_new_block =
                        branch_targets.contains(&insn.address) && !current_block_instrs.is_empty();

                    if is_new_block {
                        let end_addr = current_block_instrs
                            .last()
                            .map(|i: &LiftedInstruction| i.address)
                            .unwrap_or(current_block_start);
                        basic_blocks.push(LiftedBasicBlock {
                            index: block_index,
                            address: current_block_start,
                            end_address: end_addr,
                            instructions: current_block_instrs,
                            successors: vec![],
                            predecessors: vec![],
                            is_loop_header: false,
                        });
                        block_index += 1;
                        current_block_instrs = Vec::new();
                        current_block_start = insn.address;
                    }

                    let is_terminator = is_capstone_terminator(&insn.mnemonic, info.arch);
                    current_block_instrs.push(insn);

                    if is_terminator && !current_block_instrs.is_empty() {
                        let end_addr = current_block_instrs
                            .last()
                            .map(|i| i.address)
                            .unwrap_or(current_block_start);
                        basic_blocks.push(LiftedBasicBlock {
                            index: block_index,
                            address: current_block_start,
                            end_address: end_addr,
                            instructions: current_block_instrs,
                            successors: vec![],
                            predecessors: vec![],
                            is_loop_header: false,
                        });
                        block_index += 1;
                        current_block_instrs = Vec::new();
                        current_block_start = end_addr + 1;
                    }
                }

                // Add remaining instructions as final block
                if !current_block_instrs.is_empty() {
                    let end_addr = current_block_instrs
                        .last()
                        .map(|i| i.address)
                        .unwrap_or(current_block_start);
                    basic_blocks.push(LiftedBasicBlock {
                        index: block_index,
                        address: current_block_start,
                        end_address: end_addr,
                        instructions: current_block_instrs,
                        successors: vec![],
                        predecessors: vec![],
                        is_loop_header: false,
                    });
                }

                // Detect loops
                detect_loops(&mut basic_blocks);

                if !basic_blocks.is_empty() {
                    let func_name = info
                        .exports
                        .iter()
                        .find(|e| e.address == func_addr)
                        .map(|e| e.name.clone());

                    all_callees.insert(func_addr, callees.clone());
                    functions.insert(
                        func_addr,
                        LiftedFunction {
                            address: func_addr,
                            name: func_name,
                            basic_blocks,
                            callees,
                            callers: vec![],
                            is_thunk: false,
                            thunk_target: None,
                            is_library: false,
                        },
                    );
                }
            }
        }
    }

    // Build caller relationships
    for (&caller_addr, callees) in &all_callees {
        for &callee_addr in callees {
            if let Some(callee_func) = functions.get_mut(&callee_addr) {
                if !callee_func.callers.contains(&caller_addr) {
                    callee_func.callers.push(caller_addr);
                }
            }
        }
    }

    log::info!("[capstone] Created {} function objects", functions.len());

    let iat_entries = build_iat_map(info);
    let strings_at = build_string_map(bytes, info);
    let thunk_targets = detect_thunks(&mut functions, &iat_entries);

    Ok(LiftedProgram {
        functions,
        entry_point,
        info: info.clone(),
        strings_at,
        iat_entries,
        thunk_targets,
    })
}

/// Get branch target from capstone instruction
fn get_capstone_branch_target(
    _cs: &capstone::Capstone,
    insn: &capstone::Insn,
    arch: ArchType,
) -> Option<u64> {
    let op_str = insn.op_str().unwrap_or("");

    match arch {
        ArchType::Arm | ArchType::Arm64 => {
            // ARM: bl 0x1234, b 0x1234, etc.
            // Look for #0x prefix or just hex number
            if let Some(addr_str) = op_str.strip_prefix('#') {
                parse_hex_address(addr_str)
            } else {
                parse_hex_address(op_str)
            }
        }
        ArchType::Mips => {
            // MIPS: jal 0x1234, j 0x1234
            parse_hex_address(op_str.trim())
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            // PPC: bl 0x1234, b 0x1234
            parse_hex_address(op_str.trim())
        }
        _ => None,
    }
}

/// Check if instruction is a call (function call, not branch)
fn is_capstone_call_instruction(insn: &capstone::Insn, arch: ArchType) -> bool {
    let mnemonic = insn.mnemonic().unwrap_or("");
    match arch {
        ArchType::Arm | ArchType::Arm64 => {
            // BL, BLX are calls in ARM
            mnemonic.starts_with("bl")
        }
        ArchType::Mips => {
            // JAL, JALR are calls in MIPS
            mnemonic.starts_with("jal")
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            // BL is call in PPC
            mnemonic == "bl" || mnemonic == "bla"
        }
        _ => false,
    }
}

/// Check if instruction is any kind of branch
fn is_capstone_branch_instruction(insn: &capstone::Insn, arch: ArchType) -> bool {
    let mnemonic = insn.mnemonic().unwrap_or("");
    match arch {
        ArchType::Arm | ArchType::Arm64 => {
            mnemonic.starts_with('b') || mnemonic.starts_with("cb")
        }
        ArchType::Mips => {
            mnemonic.starts_with('b') || mnemonic.starts_with('j')
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            mnemonic.starts_with('b')
        }
        _ => false,
    }
}

/// Check if instruction is a return
fn is_capstone_return_instruction(insn: &capstone::Insn, arch: ArchType) -> bool {
    let mnemonic = insn.mnemonic().unwrap_or("");
    let op_str = insn.op_str().unwrap_or("");

    match arch {
        ArchType::Arm => {
            // ARM: bx lr, pop {pc}, mov pc, lr
            mnemonic == "bx" && op_str.contains("lr")
                || (mnemonic == "pop" && op_str.contains("pc"))
                || (mnemonic == "mov" && op_str.starts_with("pc"))
        }
        ArchType::Arm64 => {
            // AArch64: ret
            mnemonic == "ret"
        }
        ArchType::Mips => {
            // MIPS: jr $ra
            mnemonic == "jr" && op_str.contains("ra")
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            // PPC: blr
            mnemonic == "blr"
        }
        _ => false,
    }
}

/// Check if mnemonic is a block terminator
fn is_capstone_terminator(mnemonic: &str, arch: ArchType) -> bool {
    match arch {
        ArchType::Arm | ArchType::Arm64 => {
            mnemonic.starts_with('b') || mnemonic.starts_with("cb") || mnemonic == "ret"
        }
        ArchType::Mips => {
            mnemonic.starts_with('b') || mnemonic.starts_with('j')
        }
        ArchType::Ppc | ArchType::Ppc64 => {
            mnemonic.starts_with('b')
        }
        _ => false,
    }
}

/// Parse operands from capstone operand string
fn parse_capstone_operands(op_str: &str) -> (Vec<String>, Vec<Option<i64>>) {
    let mut operands = Vec::new();
    let mut values = Vec::new();

    for part in op_str.split(',') {
        let trimmed = part.trim();
        operands.push(trimmed.to_string());

        // Try to extract numeric value
        let value = if let Some(hex) = trimmed.strip_prefix("#0x") {
            i64::from_str_radix(hex, 16).ok()
        } else if let Some(hex) = trimmed.strip_prefix("0x") {
            i64::from_str_radix(hex, 16).ok()
        } else if let Some(num) = trimmed.strip_prefix('#') {
            num.parse::<i64>().ok()
        } else {
            None
        };
        values.push(value);
    }

    (operands, values)
}

/// Parse hex address from string
fn parse_hex_address(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && !s.is_empty() {
        u64::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

/// Format an operand from iced instruction
fn format_operand(instruction: &iced_x86::Instruction, idx: u32, op_kind: iced_x86::OpKind) -> (String, Option<i64>) {
    use iced_x86::{OpKind, Register};

    match op_kind {
        OpKind::Register => {
            (format!("{:?}", instruction.op_register(idx)).to_lowercase(), None)
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target = instruction.near_branch_target();
            (format!("0x{:x}", target), Some(target as i64))
        }
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 => {
            let imm = instruction.immediate(idx);
            (format!("0x{:x}", imm), Some(imm as i64))
        }
        OpKind::Memory => {
            let seg = instruction.memory_segment();
            let base = instruction.memory_base();
            let disp = instruction.memory_displacement64();

            // Include segment prefix for FS/GS access detection
            let seg_prefix = match seg {
                Register::FS => "fs:",
                Register::GS => "gs:",
                Register::CS => "cs:",
                Register::DS => "",  // Default, don't show
                Register::ES => "es:",
                Register::SS => "",  // Stack segment, don't show
                _ => "",
            };

            let mem_str = if disp != 0 {
                if base == Register::None {
                    format!("{}[0x{:x}]", seg_prefix, disp)
                } else {
                    format!("{}[{:?}+0x{:x}]", seg_prefix, base, disp).to_lowercase()
                }
            } else {
                format!("{}[{:?}]", seg_prefix, base).to_lowercase()
            };
            (mem_str, if disp != 0 { Some(disp as i64) } else { None })
        }
        _ => (String::new(), None),
    }
}

/// Find a function start in a gap between known functions
fn find_function_in_gap(gap_bytes: &[u8], _gap_start: u64, bitness: u32, max_scan: usize) -> Option<usize> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    // Stricter prologue patterns (multi-byte only to reduce false positives)
    const STRICT_PROLOGUES: &[&[u8]] = &[
        &[0x48, 0x89, 0x5C, 0x24],       // mov [rsp+X], rbx
        &[0x48, 0x83, 0xEC],             // sub rsp, imm8
        &[0x48, 0x81, 0xEC],             // sub rsp, imm32
        &[0x55, 0x8B, 0xEC],             // push ebp; mov ebp, esp
        &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp (AT&T)
        &[0x55, 0x48, 0x8B, 0xEC],       // push rbp; mov rbp, rsp
        &[0x48, 0x8B, 0xEC],             // mov rbp, rsp
    ];

    let scan_limit = gap_bytes.len().min(max_scan);

    for offset in 0..scan_limit {
        let remaining = &gap_bytes[offset..];
        if remaining.len() < 8 {
            break;
        }

        for pattern in STRICT_PROLOGUES {
            if remaining.len() >= pattern.len() && remaining.starts_with(pattern) {
                let mut decoder = Decoder::with_ip(bitness, remaining, 0, DecoderOptions::NONE);
                let mut valid_count = 0;
                let mut has_stack_setup = false;

                for _ in 0..8 {
                    let insn = decoder.decode();
                    if insn.is_invalid() {
                        break;
                    }
                    valid_count += 1;

                    let mnemonic = insn.mnemonic();
                    if matches!(mnemonic,
                        iced_x86::Mnemonic::Push |
                        iced_x86::Mnemonic::Sub |
                        iced_x86::Mnemonic::Mov) {
                        has_stack_setup = true;
                    }

                    if matches!(insn.flow_control(), FlowControl::Return | FlowControl::UnconditionalBranch) {
                        break;
                    }
                }

                if valid_count >= 4 && has_stack_setup {
                    return Some(offset);
                }
            }
        }
    }

    None
}

/// Executable section information for disassembly
struct ExecutableSection {
    rva: u64,
    file_offset: usize,
    size: usize,
}

/// PE .pdata runtime function entry (x64)
#[derive(Debug, Clone, Copy)]
struct RuntimeFunction {
    begin_address: u32,
    #[allow(dead_code)]
    end_address: u32,
    #[allow(dead_code)]
    unwind_info: u32,
}

/// Parse PE .pdata section for x64 runtime function entries
fn parse_pdata_section(pe: &goblin::pe::PE, bytes: &[u8]) -> Option<Vec<RuntimeFunction>> {
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        if name == ".pdata" {
            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            if offset + size > bytes.len() {
                return None;
            }

            let pdata_bytes = &bytes[offset..offset + size];
            let mut funcs = Vec::new();

            let entry_size = 12;
            let num_entries = pdata_bytes.len() / entry_size;

            for i in 0..num_entries {
                let entry_offset = i * entry_size;
                if entry_offset + entry_size > pdata_bytes.len() {
                    break;
                }

                let begin = u32::from_le_bytes([
                    pdata_bytes[entry_offset],
                    pdata_bytes[entry_offset + 1],
                    pdata_bytes[entry_offset + 2],
                    pdata_bytes[entry_offset + 3],
                ]);
                let end = u32::from_le_bytes([
                    pdata_bytes[entry_offset + 4],
                    pdata_bytes[entry_offset + 5],
                    pdata_bytes[entry_offset + 6],
                    pdata_bytes[entry_offset + 7],
                ]);
                let unwind = u32::from_le_bytes([
                    pdata_bytes[entry_offset + 8],
                    pdata_bytes[entry_offset + 9],
                    pdata_bytes[entry_offset + 10],
                    pdata_bytes[entry_offset + 11],
                ]);

                if begin > 0 && end > begin {
                    funcs.push(RuntimeFunction {
                        begin_address: begin,
                        end_address: end,
                        unwind_info: unwind,
                    });
                }
            }

            log::info!("Parsed {} runtime functions from .pdata", funcs.len());
            return Some(funcs);
        }
    }

    None
}

/// Detect loops in basic blocks (simple back-edge detection)
fn detect_loops(blocks: &mut [LiftedBasicBlock]) {
    let addr_to_idx: HashMap<u64, usize> = blocks
        .iter()
        .map(|b| (b.address, b.index))
        .collect();

    let mut loop_header_indices: Vec<usize> = Vec::new();

    for block in blocks.iter() {
        if let Some(last_insn) = block.instructions.last() {
            for op in &last_insn.operations {
                if let ILOperation::Branch { target: Some(target), is_call: false } = op {
                    if *target <= block.address {
                        if let Some(&target_idx) = addr_to_idx.get(target) {
                            loop_header_indices.push(target_idx);
                        }
                    }
                }
            }
        }
    }

    for idx in loop_header_indices {
        if let Some(block) = blocks.get_mut(idx) {
            block.is_loop_header = true;
        }
    }
}

/// Parse operand values from operand string
#[allow(dead_code)]
fn parse_operand_values(op_str: &str) -> Vec<Option<i64>> {
    op_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") {
                i64::from_str_radix(&s[2..], 16).ok()
            } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 1 {
                i64::from_str_radix(s, 16).ok()
            } else {
                s.parse::<i64>().ok()
            }
        })
        .collect()
}

/// Parse branch target from operand string
#[allow(dead_code)]
fn parse_branch_target(op_str: &str) -> Option<u64> {
    let s = op_str.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) {
        u64::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

/// Parse .eh_frame_hdr section for function discovery in ELF binaries
/// The .eh_frame_hdr contains a sorted table of function start addresses
fn parse_eh_frame_hdr(bytes: &[u8], elf: &goblin::elf::Elf) -> Option<Vec<u64>> {
    // Find .eh_frame_hdr section
    let mut eh_frame_hdr_section = None;
    let mut eh_frame_hdr_addr = 0u64;

    for section in &elf.section_headers {
        let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if section_name == ".eh_frame_hdr" {
            eh_frame_hdr_section = Some(section);
            eh_frame_hdr_addr = section.sh_addr;
            break;
        }
    }

    let section = eh_frame_hdr_section?;
    let offset = section.sh_offset as usize;
    let size = section.sh_size as usize;

    if offset + size > bytes.len() || size < 12 {
        return None;
    }

    let hdr = &bytes[offset..offset + size];

    // .eh_frame_hdr format:
    // byte 0: version (should be 1)
    // byte 1: eh_frame_ptr_enc (encoding of eh_frame pointer)
    // byte 2: fde_count_enc (encoding of FDE count)
    // byte 3: table_enc (encoding of table entries)
    // then: eh_frame_ptr (encoded)
    // then: fde_count (encoded)
    // then: table of (initial_loc, fde_ptr) pairs

    let version = hdr[0];
    if version != 1 {
        return None;
    }

    let fde_count_enc = hdr[2];
    let table_enc = hdr[3];

    // Common encodings:
    // 0x03 = DW_EH_PE_udata4 (4-byte unsigned)
    // 0x0b = DW_EH_PE_sdata4 (4-byte signed)
    // 0x1b = DW_EH_PE_pcrel | DW_EH_PE_sdata4 (PC-relative 4-byte signed)
    // 0x03 | 0x10 = DW_EH_PE_datarel | DW_EH_PE_udata4

    // Read FDE count (at offset 8 for most encodings)
    let fde_count_offset = 8; // After version(1) + encodings(3) + eh_frame_ptr(4)
    if fde_count_offset + 4 > hdr.len() {
        return None;
    }

    let fde_count = match fde_count_enc & 0x0f {
        0x03 | 0x0b => {
            // 4-byte value
            u32::from_le_bytes([
                hdr[fde_count_offset],
                hdr[fde_count_offset + 1],
                hdr[fde_count_offset + 2],
                hdr[fde_count_offset + 3],
            ]) as usize
        }
        _ => return None, // Unsupported encoding
    };

    if fde_count == 0 || fde_count > 100000 {
        return None;
    }

    // Table starts after fde_count
    let table_offset = fde_count_offset + 4;
    let entry_size = 8; // Each entry is (initial_loc, fde_ptr), typically 4+4 bytes

    let mut functions = Vec::with_capacity(fde_count);

    // Determine if addresses are PC-relative
    let is_pcrel = (table_enc & 0x10) != 0;
    let is_datarel = (table_enc & 0x30) == 0x30;

    for i in 0..fde_count {
        let entry_offset = table_offset + i * entry_size;
        if entry_offset + 4 > hdr.len() {
            break;
        }

        // Read initial_loc (4-byte signed or unsigned depending on encoding)
        let raw_loc = i32::from_le_bytes([
            hdr[entry_offset],
            hdr[entry_offset + 1],
            hdr[entry_offset + 2],
            hdr[entry_offset + 3],
        ]);

        // Calculate actual address based on encoding
        let func_addr = if is_datarel {
            // Data-relative: offset from .eh_frame_hdr base
            (eh_frame_hdr_addr as i64 + raw_loc as i64) as u64
        } else if is_pcrel {
            // PC-relative: offset from entry location
            let entry_va = eh_frame_hdr_addr + entry_offset as u64;
            (entry_va as i64 + raw_loc as i64) as u64
        } else {
            // Absolute (rare)
            raw_loc as u64
        };

        if func_addr > 0 {
            functions.push(func_addr);
        }
    }

    if functions.is_empty() {
        None
    } else {
        Some(functions)
    }
}

/// Find Go functions from gopclntab for ELF binaries (non-vivisect path)
/// This is a simplified version that works without the vivisect feature flag
fn find_go_functions_from_pclntab_elf(bytes: &[u8], elf: &goblin::elf::Elf) -> Option<Vec<u64>> {
    // Go runtime places function info in the .gopclntab section or embedded in .text/.rodata
    // The gopclntab has magic headers for different Go versions
    let go_magic_12: &[u8] = &[0xFB, 0xFF, 0xFF, 0xFF];  // Go 1.2-1.15
    let go_magic_116: &[u8] = &[0xF0, 0xFF, 0xFF, 0xFF]; // Go 1.16-1.17
    let go_magic_118: &[u8] = &[0xF1, 0xFF, 0xFF, 0xFF]; // Go 1.18+
    let go_magic_120: &[u8] = &[0xFA, 0xFF, 0xFF, 0xFF]; // Go 1.20+

    let mut pclntab_offset: Option<usize> = None;
    let mut pclntab_size: usize = 0;
    let mut go_version = 0u32;

    // Scan ELF sections for gopclntab
    for section in &elf.section_headers {
        let offset = section.sh_offset as usize;
        let size = section.sh_size as usize;

        if offset + size > bytes.len() || size < 8 {
            continue;
        }

        // Get section name
        let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");

        // Check for explicit .gopclntab section
        if section_name == ".gopclntab" || section_name == "gopclntab" {
            pclntab_offset = Some(offset);
            pclntab_size = size;
            if size >= 8 {
                let magic = &bytes[offset..offset + 4];
                let min_lc = bytes[offset + 6];
                let ptr_size = bytes[offset + 7];

                if (ptr_size == 4 || ptr_size == 8) && (min_lc == 1 || min_lc == 2 || min_lc == 4) {
                    if magic == go_magic_120 {
                        go_version = 120;
                    } else if magic == go_magic_118 {
                        go_version = 118;
                    } else if magic == go_magic_116 {
                        go_version = 116;
                    } else if magic == go_magic_12 {
                        go_version = 12;
                    }
                }
            }
            break;
        }

        // Scan .rodata or other sections for embedded pclntab
        if section_name == ".rodata" || section_name == ".noptrdata" || section_name == ".data.rel.ro" {
            let section_bytes = &bytes[offset..offset + size.min(bytes.len() - offset)];
            for (i, window) in section_bytes.windows(8).enumerate() {
                let magic = &window[0..4];
                let min_lc = window[6];
                let ptr_size = window[7];

                if !(ptr_size == 4 || ptr_size == 8) {
                    continue;
                }
                if !(min_lc == 1 || min_lc == 2 || min_lc == 4) {
                    continue;
                }

                if magic == go_magic_120 {
                    pclntab_offset = Some(offset + i);
                    pclntab_size = size - i;
                    go_version = 120;
                    break;
                } else if magic == go_magic_118 {
                    pclntab_offset = Some(offset + i);
                    pclntab_size = size - i;
                    go_version = 118;
                    break;
                } else if magic == go_magic_116 {
                    pclntab_offset = Some(offset + i);
                    pclntab_size = size - i;
                    go_version = 116;
                    break;
                } else if magic == go_magic_12 {
                    pclntab_offset = Some(offset + i);
                    pclntab_size = size - i;
                    go_version = 12;
                    break;
                }
            }
            if pclntab_offset.is_some() {
                break;
            }
        }
    }

    let pclntab_start = pclntab_offset?;
    if go_version == 0 {
        return None;
    }

    eprintln!("[ELF] Found gopclntab at offset 0x{:x}, Go version 1.{}", pclntab_start, go_version % 100);

    let pclntab = &bytes[pclntab_start..pclntab_start + pclntab_size.min(bytes.len() - pclntab_start)];
    let mut functions = Vec::new();

    if go_version >= 118 {
        // Go 1.18+ format
        if pclntab.len() < 16 {
            return None;
        }

        let ptr_size = pclntab[7] as usize;
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }

        // Read nfunc at offset 8
        let nfunc_offset = 8;
        let nfunc = if ptr_size == 4 && pclntab.len() >= nfunc_offset + 4 {
            u32::from_le_bytes([
                pclntab[nfunc_offset],
                pclntab[nfunc_offset + 1],
                pclntab[nfunc_offset + 2],
                pclntab[nfunc_offset + 3],
            ]) as usize
        } else if ptr_size == 8 && pclntab.len() >= nfunc_offset + 8 {
            u64::from_le_bytes([
                pclntab[nfunc_offset],
                pclntab[nfunc_offset + 1],
                pclntab[nfunc_offset + 2],
                pclntab[nfunc_offset + 3],
                pclntab[nfunc_offset + 4],
                pclntab[nfunc_offset + 5],
                pclntab[nfunc_offset + 6],
                pclntab[nfunc_offset + 7],
            ]) as usize
        } else {
            return None;
        };

        eprintln!("[ELF] gopclntab reports {} functions", nfunc);

        // Read textStart
        let text_start_offset = 8 + ptr_size * 2;
        let text_start = if ptr_size == 4 && pclntab.len() >= text_start_offset + 4 {
            u32::from_le_bytes([
                pclntab[text_start_offset],
                pclntab[text_start_offset + 1],
                pclntab[text_start_offset + 2],
                pclntab[text_start_offset + 3],
            ]) as u64
        } else if ptr_size == 8 && pclntab.len() >= text_start_offset + 8 {
            u64::from_le_bytes([
                pclntab[text_start_offset],
                pclntab[text_start_offset + 1],
                pclntab[text_start_offset + 2],
                pclntab[text_start_offset + 3],
                pclntab[text_start_offset + 4],
                pclntab[text_start_offset + 5],
                pclntab[text_start_offset + 6],
                pclntab[text_start_offset + 7],
            ])
        } else {
            0
        };

        // Read pclnOffset
        let pcln_offset_loc = 8 + ptr_size * 7;
        let pcln_offset = if ptr_size == 4 && pclntab.len() >= pcln_offset_loc + 4 {
            u32::from_le_bytes([
                pclntab[pcln_offset_loc],
                pclntab[pcln_offset_loc + 1],
                pclntab[pcln_offset_loc + 2],
                pclntab[pcln_offset_loc + 3],
            ]) as usize
        } else if ptr_size == 8 && pclntab.len() >= pcln_offset_loc + 8 {
            u64::from_le_bytes([
                pclntab[pcln_offset_loc],
                pclntab[pcln_offset_loc + 1],
                pclntab[pcln_offset_loc + 2],
                pclntab[pcln_offset_loc + 3],
                pclntab[pcln_offset_loc + 4],
                pclntab[pcln_offset_loc + 5],
                pclntab[pcln_offset_loc + 6],
                pclntab[pcln_offset_loc + 7],
            ]) as usize
        } else {
            return None;
        };

        if pcln_offset >= pclntab.len() {
            return None;
        }

        // Read function entries
        let entry_size = 8;
        for i in 0..nfunc.min(50000) {
            let entry_offset = pcln_offset + i * entry_size;
            if entry_offset + 8 > pclntab.len() {
                break;
            }

            let pc_offset = u32::from_le_bytes([
                pclntab[entry_offset],
                pclntab[entry_offset + 1],
                pclntab[entry_offset + 2],
                pclntab[entry_offset + 3],
            ]) as u64;

            let funcinfo_offset = u32::from_le_bytes([
                pclntab[entry_offset + 4],
                pclntab[entry_offset + 5],
                pclntab[entry_offset + 6],
                pclntab[entry_offset + 7],
            ]);

            if funcinfo_offset == 0 {
                continue;
            }

            // For ELF, addresses are usually already virtual addresses
            // textStart + pc_offset gives the function VA
            let func_va = text_start + pc_offset;
            functions.push(func_va);
        }
    } else if go_version >= 12 {
        // Go 1.2-1.15 format
        if pclntab.len() < 16 {
            return None;
        }

        let ptr_size = pclntab[7] as usize;
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }

        let nfunc_offset = 8;
        let nfunc = if ptr_size == 4 && pclntab.len() >= nfunc_offset + 4 {
            u32::from_le_bytes([
                pclntab[nfunc_offset],
                pclntab[nfunc_offset + 1],
                pclntab[nfunc_offset + 2],
                pclntab[nfunc_offset + 3],
            ]) as usize
        } else if ptr_size == 8 && pclntab.len() >= nfunc_offset + 8 {
            u64::from_le_bytes([
                pclntab[nfunc_offset],
                pclntab[nfunc_offset + 1],
                pclntab[nfunc_offset + 2],
                pclntab[nfunc_offset + 3],
                pclntab[nfunc_offset + 4],
                pclntab[nfunc_offset + 5],
                pclntab[nfunc_offset + 6],
                pclntab[nfunc_offset + 7],
            ]) as usize
        } else {
            return None;
        };

        eprintln!("[ELF] gopclntab reports {} functions", nfunc);

        let functab_offset = 8 + ptr_size;
        let entry_size = ptr_size * 2;

        for i in 0..nfunc.min(50000) {
            let entry_offset = functab_offset + i * entry_size;
            if entry_offset + ptr_size > pclntab.len() {
                break;
            }

            let func_pc = if ptr_size == 4 {
                u32::from_le_bytes([
                    pclntab[entry_offset],
                    pclntab[entry_offset + 1],
                    pclntab[entry_offset + 2],
                    pclntab[entry_offset + 3],
                ]) as u64
            } else {
                u64::from_le_bytes([
                    pclntab[entry_offset],
                    pclntab[entry_offset + 1],
                    pclntab[entry_offset + 2],
                    pclntab[entry_offset + 3],
                    pclntab[entry_offset + 4],
                    pclntab[entry_offset + 5],
                    pclntab[entry_offset + 6],
                    pclntab[entry_offset + 7],
                ])
            };

            if func_pc > 0 {
                functions.push(func_pc);
            }
        }
    }

    if functions.is_empty() {
        None
    } else {
        Some(functions)
    }
}

/// Build a map of IAT entry addresses to (module, function_name) tuples.
/// This enables resolving indirect calls through the IAT (call [addr] where addr is IAT entry).
/// Normalize a DLL module name by stripping the `.dll` extension.
/// CAPA rules use `kernel32.VirtualAlloc` not `KERNEL32.dll.VirtualAlloc`.
fn normalize_module(module: &str) -> String {
    module.strip_suffix(".dll")
        .or_else(|| module.strip_suffix(".DLL"))
        .or_else(|| module.strip_suffix(".Dll"))
        .unwrap_or(module)
        .to_string()
}

fn build_iat_map(info: &BinaryInfo) -> HashMap<u64, (Option<String>, String)> {
    let mut iat = HashMap::new();
    for import in &info.imports {
        if import.address > 0 {
            let module = import.module.as_ref().map(|m| normalize_module(m));
            iat.insert(import.address, (module, import.name.clone()));
        }
    }
    log::info!("Built IAT map with {} entries", iat.len());
    iat
}

/// Build a map of address -> string for all known string locations.
/// Used for detecting strings referenced by memory operands.
fn build_string_map(bytes: &[u8], info: &BinaryInfo) -> HashMap<u64, String> {
    let mut strings_at: HashMap<u64, String> = HashMap::new();

    // Add strings from loader
    for si in &info.strings {
        if si.address > 0 && !si.value.is_empty() {
            strings_at.insert(si.address, si.value.clone());
        }
    }

    // For PE files, also scan readable data sections for additional strings at known offsets
    if let Ok(obj) = goblin::Object::parse(bytes) {
        if let goblin::Object::PE(pe) = obj {
            for section in &pe.sections {
                // Only scan data sections (not executable)
                let is_data = section.characteristics & 0x20000000 == 0
                    && section.characteristics & 0x40000000 != 0; // readable but not executable
                if !is_data {
                    continue;
                }
                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let rva = section.virtual_address as u64;
                if offset + size > bytes.len() {
                    continue;
                }
                let section_bytes = &bytes[offset..offset + size];

                // Scan for null-terminated ASCII strings (min 4 chars)
                let mut i = 0;
                while i < section_bytes.len() {
                    if section_bytes[i] >= 0x20 && section_bytes[i] <= 0x7e {
                        let start = i;
                        while i < section_bytes.len() && section_bytes[i] >= 0x20 && section_bytes[i] <= 0x7e {
                            i += 1;
                        }
                        if i - start >= 4 && i < section_bytes.len() && section_bytes[i] == 0 {
                            let s = String::from_utf8_lossy(&section_bytes[start..i]).to_string();
                            let addr = rva + start as u64;
                            strings_at.entry(addr).or_insert(s);
                        }
                    }
                    i += 1;
                }
            }
        }
    }

    log::info!("Built string map with {} entries", strings_at.len());
    strings_at
}

/// Detect thunk functions: functions that consist of a single `jmp [IAT_entry]` instruction.
/// Returns a map of thunk address -> resolved API name.
fn detect_thunks(
    functions: &mut HashMap<u64, LiftedFunction>,
    iat_entries: &HashMap<u64, (Option<String>, String)>,
) -> HashMap<u64, String> {
    let mut thunk_targets: HashMap<u64, String> = HashMap::new();

    // Collect thunk info first to avoid borrow issues
    let thunk_info: Vec<(u64, String)> = functions
        .iter()
        .filter_map(|(&addr, func)| {
            // A thunk function starts with a jmp [IAT_addr] as its first instruction.
            // It may have additional basic blocks from NOP padding after the jmp.
            if func.basic_blocks.is_empty() {
                return None;
            }
            let bb = &func.basic_blocks[0];
            if bb.instructions.is_empty() {
                return None;
            }
            let insn = &bb.instructions[0];

            // Check for jmp mnemonic
            if insn.mnemonic != "jmp" {
                return None;
            }

            // Check if the operand is an IAT reference [addr]
            for operand in &insn.operands {
                if operand.starts_with('[') && operand.ends_with(']') {
                    // Extract address from [0xABCD] or [rip+0xABCD]
                    // Note: iced-x86's memory_displacement64() returns the resolved absolute
                    // address for RIP-relative, so [rip+0xABCD] means the target IS 0xABCD
                    let inner = &operand[1..operand.len() - 1];
                    let target_addr = if let Some(hex_start) = inner.find("0x") {
                        let hex = &inner[hex_start + 2..];
                        let hex_end = hex.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex.len());
                        u64::from_str_radix(&hex[..hex_end], 16).ok()
                    } else {
                        None
                    };

                    if let Some(target_addr) = target_addr {
                        if let Some((module, name)) = iat_entries.get(&target_addr) {
                            let api_name = if let Some(m) = module {
                                format!("{}.{}", m, name)
                            } else {
                                name.clone()
                            };
                            return Some((addr, api_name));
                        }
                    }
                }
            }

            // Also check operand_values for the IAT address
            for val in insn.operand_values.iter().flatten() {
                let target_addr = *val as u64;
                if let Some((module, name)) = iat_entries.get(&target_addr) {
                    let api_name = if let Some(m) = module {
                        format!("{}.{}", m, name)
                    } else {
                        name.clone()
                    };
                    return Some((addr, api_name));
                }
            }

            None
        })
        .collect();

    // Now apply thunk info
    for (addr, api_name) in thunk_info {
        if let Some(func) = functions.get_mut(&addr) {
            func.is_thunk = true;
            func.thunk_target = Some(api_name.clone());
        }
        thunk_targets.insert(addr, api_name);
    }

    log::info!("Detected {} thunk functions", thunk_targets.len());
    thunk_targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_operand_values() {
        let values = parse_operand_values("eax, 0x40");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], None); // eax is not a number
        assert_eq!(values[1], Some(0x40));
    }

    #[test]
    fn test_parse_branch_target() {
        assert_eq!(parse_branch_target("0x401000"), Some(0x401000));
        assert_eq!(parse_branch_target("401000"), Some(0x401000));
        assert_eq!(parse_branch_target("eax"), None);
    }
}
