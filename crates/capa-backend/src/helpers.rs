//! Helper utilities
//!
//! Porting Python capa's `capa.features.extractors.helpers` module.

/// Returns true if all bytes in the buffer are zero. Empty buffer returns false.
pub fn all_zeros(buf: &[u8]) -> bool {
    !buf.is_empty() && buf.iter().all(|&b| b == 0)
}

/// Generate symbol name variants for an import.
///
/// If `include_dll` is true, generates qualified names like `module.api`.
/// Strips `.dll` extension from module name.
/// For names ending in A or W (where preceding char is lowercase), also generates base name.
/// For ordinal imports (starting with `#`), always uses qualified `module.#N` form.
pub fn generate_symbols(module: &str, api: &str, include_dll: bool) -> Vec<String> {
    let mut symbols = Vec::new();

    // Normalize module name: strip .dll extension
    let module = if module.to_lowercase().ends_with(".dll") {
        &module[..module.len() - 4]
    } else {
        module
    };

    // Ordinal imports
    if api.starts_with('#') {
        symbols.push(format!("{}.{}", module, api));
        return symbols;
    }

    if include_dll {
        // Qualified name: module.api
        symbols.push(format!("{}.{}", module, api));
    }

    // Unqualified name
    symbols.push(api.to_string());

    // A/W suffix stripping
    if api.len() > 1 && (api.ends_with('A') || api.ends_with('W')) {
        let base = &api[..api.len() - 1];
        if base.chars().last().map_or(false, |c| c.is_ascii_lowercase()) {
            if include_dll {
                symbols.push(format!("{}.{}", module, base));
            }
            symbols.push(base.to_string());
        }
    }

    symbols
}
