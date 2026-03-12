//! Feature extraction from binaries
//!
//! Extracts CAPA features from lifted binary code using iced/vivisect.

use aho_corasick::AhoCorasick;
use capa_core::error::Result;
use capa_core::feature::{Address, ExtractedFeatures, FeatureExtractor, FeatureSet, FunctionFeatures};
use capa_core::rule::{ArchType, CharacteristicType, OsType};
use log::debug;
use memchr::memmem;

/// Normalize module name by stripping the `.dll`/`.DLL` extension.
/// CAPA rules use `kernel32.VirtualAlloc` not `KERNEL32.dll.VirtualAlloc`.
fn normalize_module(module: &str) -> String {
    let m = module.strip_suffix(".dll")
        .or_else(|| module.strip_suffix(".DLL"))
        .or_else(|| module.strip_suffix(".Dll"))
        .unwrap_or(module);
    m.to_string()
}

/// Format a qualified API name as `module.function` with normalized module name.
fn format_api(module: &Option<String>, name: &str) -> String {
    if let Some(ref m) = module {
        format!("{}.{}", normalize_module(m), name)
    } else {
        name.to_string()
    }
}

/// Insert an API name into a set using `helpers::generate_symbols` for variant generation.
/// This matches Python's `pefile.py` which calls `generate_symbols(module, name, include_dll=True)`
/// for import features. Also handles Ex suffix variants for broader matching.
fn insert_api(apis: &mut std::collections::HashSet<String>, module: &Option<String>, name: &str) {
    let module_str = module.as_ref().map(|m| normalize_module(m)).unwrap_or_default();

    // Use generate_symbols for standard variant generation (A/W stripping, dll.api forms)
    // include_dll=true for imports (matching Python's pefile.py:94)
    for symbol in crate::helpers::generate_symbols(&module_str, name, module.is_some()) {
        apis.insert(symbol);
    }

    // Also handle Ex suffix variants: CreateFileExW -> CreateFileEx, CreateFile
    // This extends beyond generate_symbols to match capa's broader API normalization
    if name.len() > 2 && name.ends_with("Ex") {
        let base = &name[..name.len() - 2];
        if !base.is_empty() {
            apis.insert(base.to_string());
            apis.insert(format_api(module, base));
        }
    }
    if name.len() > 3 && (name.ends_with("ExA") || name.ends_with("ExW")) {
        let base = &name[..name.len() - 3];
        if !base.is_empty() {
            apis.insert(format!("{}Ex", base));
            apis.insert(format_api(module, &format!("{}Ex", base)));
            apis.insert(base.to_string());
            apis.insert(format_api(module, base));
        }
    }
}
use std::collections::HashMap;

use crate::lifter::{lift_binary, ILOperation, LiftedBasicBlock, LiftedFunction, LiftedProgram};
use crate::loader::{load_binary, BinaryInfo};
use crate::dotnet_extractor::{extract_dotnet_features, merge_dotnet_features, merge_dotnet_method_features};

/// Multi-pattern byte matcher for efficient batch searching
#[derive(Debug)]
pub struct BytePatternMatcher {
    patterns: Vec<Vec<u8>>,
    automaton: Option<AhoCorasick>,
}

impl BytePatternMatcher {
    /// Create a new matcher with the given patterns
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        let automaton = if !patterns.is_empty() {
            AhoCorasick::new(&patterns).ok()
        } else {
            None
        };
        Self { patterns, automaton }
    }

    /// Find all matches in the binary
    /// Returns a map of pattern index -> list of match offsets
    pub fn find_all(&self, bytes: &[u8]) -> HashMap<usize, Vec<u64>> {
        let mut results: HashMap<usize, Vec<u64>> = HashMap::new();

        if let Some(ref automaton) = self.automaton {
            for mat in automaton.find_iter(bytes) {
                results
                    .entry(mat.pattern().as_usize())
                    .or_default()
                    .push(mat.start() as u64);
            }
        }

        results
    }

    /// Check if any pattern matches in the binary
    pub fn has_any_match(&self, bytes: &[u8]) -> bool {
        if let Some(ref automaton) = self.automaton {
            automaton.find(bytes).is_some()
        } else {
            false
        }
    }

    /// Get pattern by index
    pub fn get_pattern(&self, index: usize) -> Option<&[u8]> {
        self.patterns.get(index).map(|v| v.as_slice())
    }
}

/// Feature extractor using goblin for PE/ELF parsing (basic)
#[derive(Debug, Default)]
pub struct GoblinExtractor;

impl GoblinExtractor {
    pub fn new() -> Self {
        Self
    }

    fn binary_info_to_features(&self, info: &BinaryInfo) -> ExtractedFeatures {
        let mut features = ExtractedFeatures::new(info.os, info.arch, info.format);

        // Add imports (with A/W suffix normalization)
        for import in &info.imports {
            insert_api(&mut features.file.imports, &import.module, &import.name);
        }

        // Add exports
        for export in &info.exports {
            features.file.exports.insert(export.name.clone());
        }

        // Add sections
        for section in &info.sections {
            features.file.sections.insert(section.name.clone());
        }

        // Add strings
        for string_info in &info.strings {
            features.file.strings.insert(string_info.value.clone());
        }

        features
    }
}

impl FeatureExtractor for GoblinExtractor {
    fn extract(&self, binary: &[u8]) -> Result<ExtractedFeatures> {
        let info = load_binary(binary).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.binary_info_to_features(&info);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                merge_dotnet_features(&dotnet_features, &mut features.file);
                debug!(
                    ".NET extraction complete: {} user strings, {} types, {} API calls",
                    dotnet_features.user_strings.len(),
                    dotnet_features.types.len(),
                    dotnet_features.api_calls.len()
                );
            }
        }

        Ok(features)
    }

    fn extract_file_features(&self, binary: &[u8]) -> Result<FeatureSet> {
        let features = self.extract(binary)?;
        Ok(features.file)
    }

    fn extract_function_features(&self, _binary: &[u8], addr: Address) -> Result<FunctionFeatures> {
        Ok(FunctionFeatures::new(addr))
    }
}

/// Full-featured extractor using iced/vivisect disassembly
#[derive(Debug, Default)]
pub struct BinaryExtractor;

impl BinaryExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract features from a lifted program
    fn extract_from_lifted(&self, program: &LiftedProgram, bytes: &[u8]) -> ExtractedFeatures {
        let info = &program.info;
        let mut features = ExtractedFeatures::new(info.os, info.arch, info.format);

        // File-level features from binary info (with A/W suffix normalization)
        for import in &info.imports {
            insert_api(&mut features.file.imports, &import.module, &import.name);
        }

        for export in &info.exports {
            features.file.exports.insert(export.name.clone());
            // Issue 10: Also add forwarded export target names as function names
            if export.is_forwarded {
                if let Some(ref target) = export.forward_target {
                    features.file.function_names.insert(target.clone());
                }
            }
        }

        for section in &info.sections {
            features.file.sections.insert(section.name.clone());
        }

        for string_info in &info.strings {
            features.file.strings.insert(string_info.value.clone());
        }

        // Issue 8: Improved PE carving - scan raw bytes for embedded PE files
        if self.has_embedded_pe_bytes(bytes) {
            features.file.characteristics.insert(CharacteristicType::EmbeddedPe);
        }

        // Check for forwarded exports
        if info.has_forwarded_exports {
            features.file.characteristics.insert(CharacteristicType::ForwardedExport);
        }

        // Check for mixed-mode assembly (.NET + native)
        if info.is_mixed_mode {
            features.file.characteristics.insert(CharacteristicType::MixedMode);
        }

        // Issue 9: COM detection - check for COM-related imports
        self.detect_com_features(info, &mut features.file);

        // Extract function-level features
        for (addr, func) in &program.functions {
            // Issue 1: Skip library/thunk functions from feature extraction
            if func.is_library || func.is_thunk {
                continue;
            }

            let mut func_features = FunctionFeatures::new(Address(*addr));
            func_features.name = func.name.clone();

            // Check for loops at function level
            let has_loop = func.basic_blocks.iter().any(|bb| bb.is_loop_header);
            if has_loop {
                func_features.features.characteristics.insert(CharacteristicType::Loop);
            }

            // Check for recursive calls
            if func.callees.contains(addr) {
                func_features.features.characteristics.insert(CharacteristicType::RecursiveCall);
            }

            // Check for stack string construction
            if self.detect_stack_strings(func) {
                func_features.features.characteristics.insert(CharacteristicType::StackString);
            }

            // Extract basic block features
            for bb in &func.basic_blocks {
                let bb_features = self.extract_basic_block_features(bb, info, program);

                // Debug: Check for blocks with both TightLoop and Nzxor
                if bb_features.characteristics.contains(&CharacteristicType::TightLoop)
                    && bb_features.characteristics.contains(&CharacteristicType::Nzxor) {
                    // This block has tight loop with nzxor - good for XOR encryption detection
                }

                func_features.basic_blocks.insert(bb.index, bb_features.clone());

                // Merge to function level
                func_features.features.merge(&bb_features);
            }

            // Set basic block count for count(basic block) feature
            func_features.features.basic_block_count = func.basic_blocks.len();

            // Extract instruction features
            for bb in &func.basic_blocks {
                for insn in &bb.instructions {
                    let insn_features = self.extract_instruction_features(insn, info);
                    func_features.instructions.insert(Address(insn.address), insn_features.clone());
                }
            }

            features.functions.insert(Address(*addr), func_features);
        }

        // Merge all function features to file level
        for func in features.functions.values() {
            features.file.merge(&func.features);
        }

        // Log extraction summary
        log::debug!("Extraction: {} functions, {} APIs, {} thunks, {} IAT entries, {} strings_at",
            features.functions.len(), features.file.apis.len(),
            program.thunk_targets.len(), program.iat_entries.len(), program.strings_at.len());

        features
    }

    /// Extract features from a basic block
    fn extract_basic_block_features(&self, bb: &LiftedBasicBlock, info: &BinaryInfo, program: &LiftedProgram) -> FeatureSet {
        let mut features = FeatureSet::new();

        // Check for tight loop (small loop)
        if bb.is_loop_header && bb.instructions.len() <= 10 {
            features.characteristics.insert(CharacteristicType::TightLoop);
        }

        // Check for nzxor in block
        for insn in &bb.instructions {
            if self.is_nzxor(insn) {
                features.characteristics.insert(CharacteristicType::Nzxor);
            }
        }

        // Collect mnemonics
        for insn in &bb.instructions {
            *features.mnemonics.entry(insn.mnemonic.clone()).or_insert(0) += 1;
        }

        // Collect numeric constants
        for insn in &bb.instructions {
            for val in insn.operand_values.iter().flatten() {
                features.numbers.insert(*val);
            }
        }

        // Check for API calls
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                // Try to resolve call target to import (direct call)
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // First check if target is a direct import
                        if let Some(import) = info.imports.iter().find(|i| i.address == *target) {
                            insert_api(&mut features.apis, &import.module, &import.name);
                        }
                        // Issue 5/6: Check if target is a thunk function
                        else if let Some(api_name) = program.thunk_targets.get(target) {
                            // Thunk targets are already formatted as "module.name"
                            if let Some(dot_pos) = api_name.rfind('.') {
                                let module = Some(api_name[..dot_pos].to_string());
                                let name = &api_name[dot_pos + 1..];
                                insert_api(&mut features.apis, &module, name);
                            } else {
                                insert_api(&mut features.apis, &None, api_name);
                            }
                        }
                    }
                }

                // Check for indirect call through IAT (call [rip+X] or call [address])
                for operand in &insn.operands {
                    if operand.contains('[') && operand.contains("0x") {
                        if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                            // Issue 5: Check IAT map for indirect calls
                            if let Some((module, name)) = program.iat_entries.get(&addr) {
                                insert_api(&mut features.apis, module, name);
                            }
                            // Legacy: also check imports directly
                            else if let Some(import) = info.imports.iter().find(|i| i.address == addr) {
                                insert_api(&mut features.apis, &import.module, &import.name);
                            }
                        }
                    }
                }
            }

            // Issue 4: Detect strings referenced by memory operands (any instruction, not just call)
            for operand in &insn.operands {
                if operand.contains('[') && operand.contains("0x") {
                    if let Some(addr) = self.parse_memory_address(operand, insn.address, insn.bytes.len()) {
                        // Check if the referenced address contains a string
                        if let Some(s) = program.strings_at.get(&addr) {
                            features.strings.insert(s.clone());
                        }
                    }
                }
                // Also check immediate values that might be string pointers
                if operand.starts_with("0x") && !operand.contains('[') {
                    if let Ok(addr) = u64::from_str_radix(&operand[2..], 16) {
                        if let Some(s) = program.strings_at.get(&addr) {
                            features.strings.insert(s.clone());
                        }
                    }
                }
            }
            // Check operand_values for string pointers too
            for val in insn.operand_values.iter().flatten() {
                let addr = *val as u64;
                if let Some(s) = program.strings_at.get(&addr) {
                    features.strings.insert(s.clone());
                }
            }
        }

        // Check for indirect calls
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: None, is_call: true } = op {
                        features.characteristics.insert(CharacteristicType::IndirectCall);
                    }
                }
            }
        }

        // Check for FS/GS segment access (anti-debug, PEB access on Windows)
        // On Windows x86: FS points to TEB, FS:[0x30] is PEB
        // On Windows x64: GS points to TEB, GS:[0x60] is PEB
        // On Linux: FS/GS are used for TLS, not PEB (no PEB exists)
        for insn in &bb.instructions {
            let op_str = insn.operands.join(", ").to_lowercase();
            if op_str.contains("fs:") {
                features.characteristics.insert(CharacteristicType::FsAccess);
                // Only mark as PEB access on Windows
                if info.os == OsType::Windows {
                    features.characteristics.insert(CharacteristicType::Peb);
                }
            }
            if op_str.contains("gs:") {
                features.characteristics.insert(CharacteristicType::GsAccess);
                // On Windows x64, GS access could be TEB/PEB access
                if info.os == OsType::Windows && info.arch == ArchType::Amd64 {
                    features.characteristics.insert(CharacteristicType::Peb);
                }
            }
        }

        // Extract offset values from memory references
        for insn in &bb.instructions {
            for offset in self.extract_offsets(insn) {
                features.offsets.insert(offset);
            }
        }

        // Check for call-next pattern (shellcode/position-independent code)
        if self.detect_call_next(bb) {
            features.characteristics.insert(CharacteristicType::CallsFromShellcode);
        }

        // Check for call $+5 pattern (get EIP/RIP)
        if self.detect_call_plus_5(bb) {
            features.characteristics.insert(CharacteristicType::CallPlus5);
        }

        // Check for unmangled API calls
        if self.detect_unmangled_call(bb, info) {
            features.characteristics.insert(CharacteristicType::UnmangledCall);
        }

        // Check for cross-section flow
        if self.detect_cross_section_flow(bb, info) {
            features.characteristics.insert(CharacteristicType::CrossSectionFlow);
        }

        features
    }

    /// Extract features from a single instruction
    fn extract_instruction_features(&self, insn: &crate::lifter::LiftedInstruction, _info: &BinaryInfo) -> FeatureSet {
        let mut features = FeatureSet::new();

        // Mnemonic
        *features.mnemonics.entry(insn.mnemonic.clone()).or_insert(0) += 1;

        // Operand values
        for (idx, val) in insn.operand_values.iter().enumerate() {
            if let Some(v) = val {
                features.numbers.insert(*v);
                features.operands.push((idx, Some(*v), None));
            }
        }

        // Bytes
        if !insn.bytes.is_empty() {
            features.bytes_sequences.push(insn.bytes.clone());
        }

        features
    }

    /// Check if instruction is a non-zero XOR
    fn is_nzxor(&self, insn: &crate::lifter::LiftedInstruction) -> bool {
        if insn.mnemonic != "xor" {
            return false;
        }

        // XOR with different operands is nzxor
        if insn.operands.len() >= 2 {
            let op1 = insn.operands[0].trim().to_lowercase();
            let op2 = insn.operands[1].trim().to_lowercase();

            // Same register XOR (zeroing) is NOT nzxor
            if op1 == op2 {
                return false;
            }

            // XOR with 0 is NOT nzxor
            if op2 == "0" || op2 == "0x0" {
                return false;
            }

            return true;
        }

        false
    }

    /// Issue 9: Detect COM class/interface features from imports and strings
    fn detect_com_features(&self, info: &BinaryInfo, features: &mut FeatureSet) {
        // COM-related API imports that indicate COM usage
        let com_apis = [
            "CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject",
            "CLSIDFromProgID", "CLSIDFromString", "CoInitialize",
            "CoInitializeEx", "OleInitialize", "CoRegisterClassObject",
            "CoGetInterfaceAndReleaseStream",
        ];

        for import in &info.imports {
            for com_api in &com_apis {
                if import.name.eq_ignore_ascii_case(com_api) {
                    features.characteristics.insert(CharacteristicType::CallsFrom);
                    // Add the COM API as an API feature too
                    insert_api(&mut features.apis, &import.module, &import.name);
                }
            }
        }

        // Look for CLSID patterns in strings (GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
        let guid_re = regex::Regex::new(
            r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
        ).ok();

        if let Some(re) = guid_re {
            for si in &info.strings {
                if re.is_match(&si.value) {
                    features.classes.insert(si.value.clone());
                }
            }
        }
    }

    /// Issue 8: Check for embedded PE by looking for MZ header in raw bytes.
    /// Validates the PE signature to avoid false positives.
    fn has_embedded_pe_bytes(&self, bytes: &[u8]) -> bool {
        // Skip the first MZ header (the file itself), look for embedded ones
        if bytes.len() < 1024 {
            return false;
        }

        let finder = memmem::Finder::new(b"MZ");
        let mut iter = finder.find_iter(&bytes[512..]); // Skip first 512 bytes

        // Check if any MZ found is followed by PE signature
        while let Some(pos) = iter.next() {
            let abs_pos = pos + 512;
            // Check for "This program" or PE header offset
            if abs_pos + 64 < bytes.len() {
                // Get PE header offset from e_lfanew (offset 0x3C)
                let pe_offset_pos = abs_pos + 0x3C;
                if pe_offset_pos + 4 < bytes.len() {
                    let pe_offset = u32::from_le_bytes([
                        bytes[pe_offset_pos],
                        bytes[pe_offset_pos + 1],
                        bytes[pe_offset_pos + 2],
                        bytes[pe_offset_pos + 3],
                    ]) as usize;

                    // Check for "PE\0\0" at that offset
                    if abs_pos + pe_offset + 4 < bytes.len() {
                        let pe_sig = &bytes[abs_pos + pe_offset..abs_pos + pe_offset + 4];
                        if pe_sig == b"PE\0\0" {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Detect stack string construction patterns
    fn detect_stack_strings(&self, func: &LiftedFunction) -> bool {
        // Look for patterns like: mov [esp+X], imm32 repeated multiple times
        // This is a common pattern for building strings on the stack
        let mut stack_moves = 0;

        for bb in &func.basic_blocks {
            for insn in &bb.instructions {
                // Check for mov to stack with immediate value
                if insn.mnemonic == "mov" && insn.operands.len() >= 2 {
                    let dst = insn.operands[0].to_lowercase();

                    // Check if destination is stack-relative
                    let is_stack_dst = dst.contains("esp")
                        || dst.contains("ebp")
                        || dst.contains("rsp")
                        || dst.contains("rbp");

                    // Check if source is a small immediate (likely character)
                    let is_char_imm = insn.operand_values.get(1).and_then(|v| *v).map_or(false, |v| {
                        (v >= 0x20 && v <= 0x7E) || // Printable ASCII
                        (v >= 0x20202020 && v <= 0x7E7E7E7E) // 4 chars packed
                    });

                    if is_stack_dst && is_char_imm {
                        stack_moves += 1;
                    }
                }
            }
        }

        // If we see 4+ stack moves with character immediates, likely stack string
        stack_moves >= 4
    }

    /// Detect call to next instruction (shellcode pattern)
    fn detect_call_next(&self, bb: &LiftedBasicBlock) -> bool {
        for (i, insn) in bb.instructions.iter().enumerate() {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Check if call target is the next instruction
                        if let Some(next_insn) = bb.instructions.get(i + 1) {
                            if *target == next_insn.address {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Detect unmangled API calls (direct calls to API functions)
    fn detect_unmangled_call(&self, bb: &LiftedBasicBlock, info: &BinaryInfo) -> bool {
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Check if target is in import table
                        if info.imports.iter().any(|imp| imp.address == *target) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Search for byte pattern in binary
    pub fn find_bytes(&self, bytes: &[u8], pattern: &[u8]) -> Vec<u64> {
        let finder = memmem::Finder::new(pattern);
        finder.find_iter(bytes).map(|pos| pos as u64).collect()
    }

    /// Extract offset values from operands (memory references)
    fn extract_offsets(&self, insn: &crate::lifter::LiftedInstruction) -> Vec<i64> {
        let mut offsets = Vec::new();

        for op in &insn.operands {
            let op_lower = op.to_lowercase();

            // Look for memory offset patterns like [reg+offset] or [offset]
            if op_lower.contains('[') {
                // Extract numbers from memory references
                if let Some(start) = op_lower.find('+') {
                    let after_plus = &op_lower[start + 1..];
                    if let Some(end) = after_plus.find(']') {
                        let offset_str = after_plus[..end].trim();
                        if let Some(offset) = parse_number(offset_str) {
                            offsets.push(offset);
                        }
                    }
                } else if let Some(start) = op_lower.find('-') {
                    let after_minus = &op_lower[start + 1..];
                    if let Some(end) = after_minus.find(']') {
                        let offset_str = after_minus[..end].trim();
                        if let Some(offset) = parse_number(offset_str) {
                            offsets.push(-offset);
                        }
                    }
                }
            }
        }

        offsets
    }

    /// Detect call $+5 pattern (common in shellcode to get EIP/RIP)
    /// Pattern: call instruction where target is exactly 5 bytes after the call itself
    fn detect_call_plus_5(&self, bb: &LiftedBasicBlock) -> bool {
        for insn in &bb.instructions {
            if insn.mnemonic == "call" {
                for op in &insn.operations {
                    if let ILOperation::Branch { target: Some(target), is_call: true } = op {
                        // Call instruction is typically 5 bytes on x86
                        // call $+5 means target = address + 5
                        if *target == insn.address + 5 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Parse memory address from operand string for IAT resolution
    /// Handles formats like "[0x1234]" or "[rip+0x1234]"
    fn parse_memory_address(&self, operand: &str, _insn_addr: u64, _insn_len: usize) -> Option<u64> {
        let op_lower = operand.to_lowercase();

        // Extract hex value from memory operand
        // Note: iced-x86's memory_displacement64() returns the resolved absolute address
        // for RIP-relative addressing, so [rip+0xABCD] means the target IS 0xABCD,
        // not rip + 0xABCD.
        if let Some(start) = op_lower.find("0x") {
            let hex_part = &op_lower[start + 2..];
            let end = hex_part.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex_part.len());
            let hex_str = &hex_part[..end];

            if let Ok(addr) = u64::from_str_radix(hex_str, 16) {
                return Some(addr);
            }
        }

        None
    }

    /// Detect cross-section control flow (jump/call to different section)
    fn detect_cross_section_flow(&self, bb: &LiftedBasicBlock, info: &BinaryInfo) -> bool {
        // Find which section the basic block is in
        let bb_section = info.sections.iter().find(|s| {
            bb.address >= s.address && bb.address < s.address + s.size
        });

        let bb_section = match bb_section {
            Some(s) => s,
            None => return false,
        };

        // Check if any branch target is in a different section
        for insn in &bb.instructions {
            for op in &insn.operations {
                if let ILOperation::Branch { target: Some(target), .. } = op {
                    // Find section of target
                    let target_section = info.sections.iter().find(|s| {
                        *target >= s.address && *target < s.address + s.size
                    });

                    if let Some(ts) = target_section {
                        if ts.name != bb_section.name {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Parse a number from string (hex or decimal)
fn parse_number(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).ok()
    } else if s.ends_with('h') || s.ends_with('H') {
        i64::from_str_radix(&s[..s.len() - 1], 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 1 {
        i64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

impl BinaryExtractor {
    /// Extract features with explicit format specification
    /// Used for shellcode or when auto-detection should be bypassed
    pub fn extract_with_format(&self, binary: &[u8], format: capa_core::rule::FormatType) -> Result<ExtractedFeatures> {
        // Load binary info with explicit format
        let info = crate::loader::load_binary_with_format(binary, format).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        // Then lift to IL
        let program = lift_binary(binary, &info).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.extract_from_lifted(&program, binary);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features via dotscope");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                merge_dotnet_features(&dotnet_features, &mut features.file);
                merge_dotnet_method_features(&dotnet_features, &mut features.functions);
            }
        }

        Ok(features)
    }
}

impl FeatureExtractor for BinaryExtractor {
    fn extract(&self, binary: &[u8]) -> Result<ExtractedFeatures> {
        // First load basic binary info
        let info = load_binary(binary).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        // Then lift to IL
        let program = lift_binary(binary, &info).map_err(|e| {
            capa_core::error::CapaError::ExtractionError(e.to_string())
        })?;

        let mut features = self.extract_from_lifted(&program, binary);

        // Extract .NET-specific features if this is a .NET assembly
        if info.is_dotnet {
            debug!("Detected .NET assembly, extracting .NET-specific features via dotscope");
            if let Some(dotnet_features) = extract_dotnet_features(binary) {
                // Merge file-level features
                merge_dotnet_features(&dotnet_features, &mut features.file);

                // Merge method-level features for function-scope matching
                merge_dotnet_method_features(&dotnet_features, &mut features.functions);

                debug!(
                    ".NET extraction complete: {} user strings, {} types, {} API calls, {} methods",
                    dotnet_features.user_strings.len(),
                    dotnet_features.types.len(),
                    dotnet_features.api_calls.len(),
                    dotnet_features.method_features.len()
                );
            }
        }

        Ok(features)
    }

    fn extract_file_features(&self, binary: &[u8]) -> Result<FeatureSet> {
        let features = self.extract(binary)?;
        Ok(features.file)
    }

    fn extract_function_features(&self, binary: &[u8], addr: Address) -> Result<FunctionFeatures> {
        let features = self.extract(binary)?;
        features
            .functions
            .get(&addr)
            .cloned()
            .ok_or_else(|| capa_core::error::CapaError::ExtractionError(
                format!("Function at {} not found", addr)
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::SectionInfo;

    #[test]
    fn test_goblin_extractor() {
        let extractor = GoblinExtractor::new();
        assert!(extractor.extract(&[]).is_err());
    }

    #[test]
    fn test_binary_extractor() {
        let extractor = BinaryExtractor::new();
        assert!(extractor.extract(&[]).is_err());
    }

    #[test]
    fn test_byte_pattern_matcher() {
        let patterns = vec![
            b"MZ".to_vec(),
            b"PE\x00\x00".to_vec(),
            b"kernel32.dll".to_vec(),
        ];
        let matcher = BytePatternMatcher::new(patterns);

        let data = b"This is a test MZ header followed by PE\x00\x00 signature";
        let matches = matcher.find_all(data);

        assert!(matches.contains_key(&0)); // MZ found
        assert!(matches.contains_key(&1)); // PE\0\0 found
        assert!(!matches.contains_key(&2)); // kernel32.dll not found
    }

    #[test]
    fn test_byte_pattern_matcher_empty() {
        let matcher = BytePatternMatcher::new(vec![]);
        let data = b"test data";
        assert!(!matcher.has_any_match(data));
    }

    #[test]
    fn test_parse_number() {
        assert_eq!(parse_number("0x40"), Some(0x40));
        assert_eq!(parse_number("40h"), Some(0x40));
        assert_eq!(parse_number("64"), Some(100)); // "64" is all hex digits, parsed as hex
        assert_eq!(parse_number("abc"), Some(0xabc)); // All hex digits, parsed as hex
        assert_eq!(parse_number("xyz"), None); // Not valid hex or decimal
    }

    #[test]
    fn test_nzxor_detection() {
        let extractor = BinaryExtractor::new();

        // XOR with same register (zeroing) - NOT nzxor
        let insn_zero = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "eax".to_string()],
            operand_values: vec![None, None],
            bytes: vec![0x33, 0xc0],
            operations: vec![],
        };
        assert!(!extractor.is_nzxor(&insn_zero));

        // XOR with different registers - IS nzxor
        let insn_nzxor = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "ebx".to_string()],
            operand_values: vec![None, None],
            bytes: vec![0x33, 0xc3],
            operations: vec![],
        };
        assert!(extractor.is_nzxor(&insn_nzxor));

        // XOR with immediate 0 - NOT nzxor
        let insn_zero_imm = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "xor".to_string(),
            operands: vec!["eax".to_string(), "0".to_string()],
            operand_values: vec![None, Some(0)],
            bytes: vec![0x83, 0xf0, 0x00],
            operations: vec![],
        };
        assert!(!extractor.is_nzxor(&insn_zero_imm));
    }

    #[test]
    fn test_call_plus_5_detection() {
        let extractor = BinaryExtractor::new();

        // Create a call instruction that targets address + 5
        let call_plus_5 = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "call".to_string(),
            operands: vec!["0x1005".to_string()],
            operand_values: vec![Some(0x1005)],
            bytes: vec![0xE8, 0x00, 0x00, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x1005), is_call: true }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1004,
            instructions: vec![call_plus_5],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(extractor.detect_call_plus_5(&bb));
    }

    #[test]
    fn test_call_plus_5_not_detected() {
        let extractor = BinaryExtractor::new();

        // Call to a different address (not $+5)
        let call_other = crate::lifter::LiftedInstruction {
            address: 0x1000,
            mnemonic: "call".to_string(),
            operands: vec!["0x2000".to_string()],
            operand_values: vec![Some(0x2000)],
            bytes: vec![0xE8, 0x00, 0x10, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x2000), is_call: true }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1000,
            end_address: 0x1004,
            instructions: vec![call_other],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(!extractor.detect_call_plus_5(&bb));
    }

    #[test]
    fn test_cross_section_flow() {
        let extractor = BinaryExtractor::new();

        // Create sections
        let info = BinaryInfo {
            os: capa_core::rule::OsType::Windows,
            arch: capa_core::rule::ArchType::I386,
            format: capa_core::rule::FormatType::Pe,
            imports: vec![],
            exports: vec![],
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    address: 0x1000,
                    size: 0x1000,
                    is_executable: true,
                },
                SectionInfo {
                    name: ".data".to_string(),
                    address: 0x2000,
                    size: 0x1000,
                    is_executable: false,
                },
            ],
            strings: vec![],
            is_dotnet: false,
            has_forwarded_exports: false,
            is_mixed_mode: false,
            entry_point: 0x1000,
        };

        // Jump from .text to .data
        let jmp_cross = crate::lifter::LiftedInstruction {
            address: 0x1100,
            mnemonic: "jmp".to_string(),
            operands: vec!["0x2100".to_string()],
            operand_values: vec![Some(0x2100)],
            bytes: vec![0xE9, 0x00, 0x10, 0x00, 0x00],
            operations: vec![ILOperation::Branch { target: Some(0x2100), is_call: false }],
        };

        let bb = crate::lifter::LiftedBasicBlock {
            index: 0,
            address: 0x1100,
            end_address: 0x1104,
            instructions: vec![jmp_cross],
            successors: vec![],
            predecessors: vec![],
            is_loop_header: false,
        };

        assert!(extractor.detect_cross_section_flow(&bb, &info));
    }
}
