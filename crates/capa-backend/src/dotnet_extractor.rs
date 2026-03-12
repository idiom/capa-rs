//! .NET feature extraction using dotscope
//!
//! Extracts CAPA features from .NET assemblies using dotscope for
//! proper metadata parsing, user string extraction, and API resolution.

use capa_core::feature::{Address, FeatureSet, FunctionFeatures};
use crate::loader::StringInfo;
use log::debug;
use std::collections::HashMap;

/// Features for a single .NET method
#[derive(Debug, Clone, Default)]
pub struct DotNetMethodFeatures {
    /// Method RVA (address for matching)
    pub rva: u64,
    /// Method name
    pub name: String,
    /// IL mnemonics in this method
    pub mnemonics: HashMap<String, u32>,
    /// Numeric constants in this method
    pub numbers: std::collections::HashSet<i64>,
    /// Strings loaded by this method (ldstr targets)
    pub strings: Vec<String>,
}

/// .NET-specific features extracted from an assembly
#[derive(Debug, Clone, Default)]
pub struct DotNetExtractedFeatures {
    /// User strings from the #US heap (actual string literals in code)
    pub user_strings: Vec<StringInfo>,
    /// Type names (Namespace.ClassName format)
    pub types: Vec<String>,
    /// Method names
    pub methods: Vec<String>,
    /// API calls (member references to external assemblies)
    pub api_calls: Vec<String>,
    /// Namespaces used
    pub namespaces: Vec<String>,
    /// Module name
    pub module_name: String,
    /// IL opcodes/mnemonics used in methods (ldstr, call, newobj, etc.)
    pub il_mnemonics: std::collections::HashMap<String, u32>,
    /// Numeric constants from IL operands
    pub il_numbers: std::collections::HashSet<i64>,
    /// Per-method features with RVAs for function-scope matching
    pub method_features: Vec<DotNetMethodFeatures>,
}

/// Extract .NET-specific features using dotscope
#[cfg(feature = "dotnet")]
pub fn extract_dotnet_features(bytes: &[u8]) -> Option<DotNetExtractedFeatures> {
    use dotscope::CilObject;
    use dotscope::ValidationConfig;
    use dotscope::assembly::Operand;
    use std::collections::{HashSet, HashMap};

    // Try to parse as .NET assembly with disabled validation (most lenient for malware)
    let assembly = match CilObject::from_mem_with_validation(bytes.to_vec(), ValidationConfig::disabled()) {
        Ok(asm) => asm,
        Err(e) => {
            debug!("Failed to parse .NET assembly with dotscope: {:?}", e);
            return None;
        }
    };

    let mut features = DotNetExtractedFeatures::default();

    // Get module name
    if let Some(module) = assembly.module() {
        features.module_name = module.name.clone();
    }

    // Get user strings heap for resolving ldstr tokens
    let user_strings_heap = assembly.userstrings();

    // Extract user strings from #US heap
    // These are the actual string literals used in IL code
    if let Some(ref user_strings) = user_strings_heap {
        let mut addr = 0u64;
        for (_, s) in user_strings.iter() {
            let s_string = s.to_string_lossy();
            if !s_string.is_empty() && s_string.len() >= 4 {
                features.user_strings.push(StringInfo {
                    value: s_string,
                    address: addr,
                });
                addr += 1;
            }
        }
    }

    // Extract type names
    let types = assembly.types();
    let mut namespaces_set: HashSet<String> = HashSet::new();

    for entry in types.iter() {
        let type_info = entry.value();
        let name = type_info.name.clone();
        let namespace = type_info.namespace.clone();

        let full_name = if namespace.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", namespace, name)
        };

        features.types.push(full_name);

        if !namespace.is_empty() {
            namespaces_set.insert(namespace);
        }
    }

    features.namespaces = namespaces_set.into_iter().collect();

    // Extract method names and IL mnemonics/numbers
    let methods = assembly.methods();
    let file = assembly.file();
    let file_data = file.data();
    let mut il_mnemonics: HashMap<String, u32> = HashMap::new();
    let mut il_numbers: HashSet<i64> = HashSet::new();
    let mut methods_with_rva = 0u32;
    let mut methods_decoded = 0u32;
    let mut total_instructions = 0u32;
    let mut strings_resolved = 0u32;

    for entry in methods.iter() {
        let method = entry.value();
        features.methods.push(method.name.clone());

        // Decode IL instructions from method body
        if let Some(rva) = method.rva {
            if rva > 0 {
                methods_with_rva += 1;

                // Track per-method features
                let mut method_features = DotNetMethodFeatures {
                    rva: rva as u64,
                    name: method.name.clone(),
                    ..Default::default()
                };

                // Convert RVA to file offset
                if let Ok(offset) = file.rva_to_offset(rva as usize) {
                    if offset > 0 && offset < file_data.len() {
                        // Try to decode instructions from this method body
                        let method_bytes = &file_data[offset..];

                        // Parse method header to get code size
                        if let Some((header_size, code_size)) = parse_method_header(method_bytes) {
                            let code_start = offset + header_size;
                            let code_end = code_start + code_size;

                            if code_end <= file_data.len() && code_size > 0 {
                                let il_bytes = &file_data[code_start..code_end];

                                // Decode IL instructions
                                if let Ok(blocks) = dotscope::assembly::decode_blocks(
                                    il_bytes,
                                    0,
                                    rva as usize + header_size,
                                    None
                                ) {
                                    methods_decoded += 1;
                                    for block in &blocks {
                                        for instruction in &block.instructions {
                                            total_instructions += 1;
                                            // Count mnemonic usage (global and per-method)
                                            let mnemonic = instruction.mnemonic.to_string();
                                            *il_mnemonics.entry(mnemonic.clone()).or_insert(0) += 1;
                                            *method_features.mnemonics.entry(mnemonic.clone()).or_insert(0) += 1;

                                            // Extract operands based on type
                                            match &instruction.operand {
                                                Operand::Immediate(imm) => {
                                                    let val: u64 = (*imm).into();
                                                    il_numbers.insert(val as i64);
                                                    method_features.numbers.insert(val as i64);
                                                }
                                                Operand::Token(token) => {
                                                    // Check if this is a ldstr instruction (table 0x70 = User String)
                                                    // ldstr uses tokens where:
                                                    // - Table ID = 0x70 (User String pseudo-table)
                                                    // - Row = byte offset into #US heap
                                                    if mnemonic == "ldstr" && token.table() == 0x70 {
                                                        if let Some(ref user_strings) = user_strings_heap {
                                                            let string_offset = token.row() as usize;
                                                            if let Ok(s) = user_strings.get(string_offset) {
                                                                let s_string = s.to_string_lossy();
                                                                if !s_string.is_empty() {
                                                                    method_features.strings.push(s_string);
                                                                    strings_resolved += 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Add method features to the list
                features.method_features.push(method_features);
            }
        }
    }

    debug!(
        ".NET IL decode: {} methods with RVA, {} decoded, {} instructions, {} unique mnemonics, {} strings resolved to methods",
        methods_with_rva, methods_decoded, total_instructions, il_mnemonics.len(), strings_resolved
    );

    features.il_mnemonics = il_mnemonics;
    features.il_numbers = il_numbers;

    // Extract imports as API calls
    let imports = assembly.imports();

    // CIL imports (managed references to external types/methods)
    for entry in imports.cil().iter() {
        let import = entry.value();
        // Add both short name and full name for matching
        features.api_calls.push(import.name.clone());
        let fullname = import.fullname();
        if fullname != import.name {
            features.api_calls.push(fullname);
        }
    }

    // Native imports (P/Invoke)
    for descriptor in imports.native().descriptors() {
        let dll_name = descriptor.dll_name.trim_end_matches(".dll")
            .trim_end_matches(".DLL");
        for func in &descriptor.functions {
            if let Some(ref name) = func.name {
                // Format: module.function (e.g., kernel32.CreateFile)
                let api_name = format!("{}.{}", dll_name, name);
                features.api_calls.push(api_name);
                features.api_calls.push(name.clone());
            }
        }
    }

    // Log the top IL mnemonics for debugging
    let mut top_mnemonics: Vec<_> = features.il_mnemonics.iter().collect();
    top_mnemonics.sort_by(|a, b| b.1.cmp(a.1));
    let top_5: Vec<_> = top_mnemonics.iter().take(5).map(|(k, v)| format!("{}:{}", k, v)).collect();

    debug!(
        ".NET features: {} user strings, {} types, {} methods, {} API calls, {} IL mnemonics (top: {}), {} IL numbers",
        features.user_strings.len(),
        features.types.len(),
        features.methods.len(),
        features.api_calls.len(),
        features.il_mnemonics.len(),
        top_5.join(", "),
        features.il_numbers.len()
    );

    Some(features)
}

/// Parse .NET method header to get header size and code size
/// Returns (header_size, code_size) or None if invalid
#[cfg(feature = "dotnet")]
fn parse_method_header(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];

    // Check for tiny header (bit 0-1 = 0b10)
    if (first_byte & 0x03) == 0x02 {
        // Tiny header: 1 byte, code size in upper 6 bits
        let code_size = (first_byte >> 2) as usize;
        return Some((1, code_size));
    }

    // Check for fat header (bit 0-1 = 0b11)
    if (first_byte & 0x03) == 0x03 {
        if data.len() < 12 {
            return None;
        }

        // Fat header is 12 bytes
        // Bytes 0-1: flags and header size (in 4-byte units)
        // Bytes 2-3: max stack
        // Bytes 4-7: code size (little-endian u32)
        // Bytes 8-11: local var sig token

        let header_size = ((data[1] >> 4) as usize) * 4;
        let code_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        return Some((header_size, code_size));
    }

    None
}

/// Stub when dotnet feature is not enabled
#[cfg(not(feature = "dotnet"))]
pub fn extract_dotnet_features(_bytes: &[u8]) -> Option<DotNetExtractedFeatures> {
    None
}

/// Merge .NET features into a FeatureSet (file-level)
pub fn merge_dotnet_features(features: &DotNetExtractedFeatures, feature_set: &mut FeatureSet) {
    // Add user strings
    for string_info in &features.user_strings {
        feature_set.strings.insert(string_info.value.clone());
    }

    // Add type names as strings (for class: matching)
    for type_name in &features.types {
        feature_set.strings.insert(type_name.clone());
    }

    // Add API calls
    for api in &features.api_calls {
        feature_set.apis.insert(api.clone());
        feature_set.strings.insert(api.clone());
    }

    // Add namespaces as strings
    for ns in &features.namespaces {
        feature_set.strings.insert(ns.clone());
    }

    // Add method names as strings
    for method in &features.methods {
        feature_set.strings.insert(method.clone());
    }

    // Add IL mnemonics
    for (mnemonic, count) in &features.il_mnemonics {
        *feature_set.mnemonics.entry(mnemonic.clone()).or_insert(0) += *count as usize;
    }

    // Add IL numeric constants
    for num in &features.il_numbers {
        feature_set.numbers.insert(*num);
    }
}

/// Merge .NET method features into the functions map (for function-scope matching)
/// Returns a HashMap of method RVA -> FunctionFeatures
pub fn merge_dotnet_method_features(
    dotnet_features: &DotNetExtractedFeatures,
    functions: &mut HashMap<Address, FunctionFeatures>,
) {
    for method in &dotnet_features.method_features {
        let addr = Address(method.rva);
        let mut func_features = FunctionFeatures::new(addr);

        // Add method name as function name
        func_features.features.function_names.insert(method.name.clone());

        // Add per-method IL mnemonics
        for (mnemonic, count) in &method.mnemonics {
            *func_features.features.mnemonics.entry(mnemonic.clone()).or_insert(0) += *count as usize;
        }

        // Add per-method numeric constants
        for num in &method.numbers {
            func_features.features.numbers.insert(*num);
        }

        // Add per-method strings
        for s in &method.strings {
            func_features.features.strings.insert(s.clone());
        }

        functions.insert(addr, func_features);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dotnet_features_default() {
        let features = DotNetExtractedFeatures::default();
        assert!(features.user_strings.is_empty());
        assert!(features.types.is_empty());
        assert!(features.api_calls.is_empty());
    }
}
