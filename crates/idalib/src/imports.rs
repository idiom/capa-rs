//! Import enumeration — wraps IDA's `get_import_module_qty` / `enum_import_names`.

/// A single import entry: module name, address, and function name.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// DLL/module name (e.g., "kernel32.dll", "ntdll.dll").
    pub module: String,
    /// Address in the IDB where this import is referenced.
    pub address: u64,
    /// Function name (e.g., "CreateFileA").
    pub name: String,
}

/// Enumerate all imports across all modules.
///
/// Uses IDA's `get_import_module_qty()` + `enum_import_names()` to get
/// proper module→function mappings (e.g., kernel32.dll → CreateFileA).
pub fn enum_all_imports() -> Vec<ImportEntry> {
    let raw = unsafe { idalib_sys::nalt::idalib_enum_all_imports() };
    let mut entries = Vec::new();

    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let module = parts[0].to_string();
        let address = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap_or(0);
        let name = parts[2].to_string();

        if name.is_empty() {
            continue; // skip ordinal-only imports with no name
        }

        entries.push(ImportEntry {
            module,
            address,
            name,
        });
    }

    entries
}
