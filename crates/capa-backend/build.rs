fn main() {
    // When the IDA backend is enabled, the test binaries need to link against
    // idalib.dll / ida.dll which are loaded at runtime. On Windows, the SDK
    // stub libs don't define all symbols, so we force-allow unresolved symbols
    // at link time (they will be resolved at runtime by the IDA installation).
    if std::env::var("CARGO_FEATURE_IDA_BACKEND").is_ok() {
        #[cfg(target_os = "windows")]
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }
}
