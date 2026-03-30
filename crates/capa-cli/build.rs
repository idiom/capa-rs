fn main() {
    // When linking against IDA SDK stubs on Windows, some symbols are resolved
    // at runtime from ida.dll/idalib.dll rather than at link time.
    // /FORCE:UNRESOLVED tells MSVC's linker to produce the binary anyway.
    //
    // NOTE: cargo ignores `rustc-link-arg` from library crate build scripts,
    // so this MUST be emitted from the binary crate (capa-cli), not from idalib.
    #[cfg(all(feature = "ida-backend", target_os = "windows"))]
    println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
}
