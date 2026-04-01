# Changelog

All notable changes to capa-rs will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] — 2026-04-01

### Added

- **Core rule engine** (`capa-core`): YAML rule parser supporting all CAPA feature types — API, string, bytes, number, offset, mnemonic, operand, characteristic, namespace, class, property, OS, arch, format.
- **Boolean operators**: `and`, `or`, `not`, `optional`, `N or more`, `count()`, `match` (cross-rule references), subscope operators (`instruction:`, `basic block:`, `function:`).
- **Wildcard byte patterns**: `??` in `bytes:` rules matches any byte.
- **Binary backend** (`capa-backend`): PE/ELF loading via goblin; x86/x64 disassembly via iced-x86; ARM/MIPS/PPC via capstone.
- **Characteristic detection**: `nzxor`, `loop`, `tight loop`, `recursive call`, `stack string`, `indirect call`, `embedded pe`, `cross section flow`, `peb access`, `call $+5`, `forwarded export`, `mixed mode`.
- **.NET support** (optional `--features dotnet`): CIL disassembly and metadata analysis via [dotscope](https://github.com/BinFlip/dotscope).
- **IDA Pro backend** (optional `--features ida-backend`): disassembly and analysis via [idalib-rs](https://github.com/binarly-io/idalib) (requires IDA Pro 9.x).
- **CLI** (`capa-rs`): JSON and table output, namespace filtering, pre-extracted feature import/export, shellcode format flags.
- **1051 bundled CAPA rules** from [mandiant/capa-rules](https://github.com/mandiant/capa-rules).
- **7 enhanced .NET rules** covering crypto detection, reflection, process injection, and registry persistence.
- **FLIRT signatures** (14.7 MB) for common MSVC and library function identification.
- **Cross-platform**: builds on Windows, Linux, and macOS.
- **Parallel rule matching** via rayon with lock-free result collection via DashMap.

### Performance

- 10–50x faster than Python CAPA with the vivisect backend (iced-x86 vs. Python disassembly).
- 2.4x faster than Python CAPA with the IDA Pro backend.

[0.1.0]: https://github.com/yeti-sec/capa-rs/releases/tag/v0.1.0
