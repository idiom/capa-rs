# Writing CAPA Rules for Shellcode Analysis

This guide covers how to write YAML-based CAPA rules that detect capabilities in raw shellcode using capa-rs.

## What is Shellcode?

Shellcode is position-independent machine code that executes directly without the usual PE/ELF headers. It's commonly used in:

- **Exploits**: Code injected via buffer overflows, format string bugs, etc.
- **Malware**: Stagers, loaders, and payloads delivered by droppers
- **Red Team Tools**: Cobalt Strike beacons, Metasploit payloads
- **In-Memory Attacks**: Fileless malware, reflective injection

## Build Requirements

```bash
cargo build --release -p capa-cli
```

---

## Analyzing Shellcode with capa-rs

### Command Line Usage

Shellcode requires explicit format specification since there are no headers to auto-detect:

```bash
# 64-bit shellcode (x64)
capa-rs -f sc64 -r rules shellcode.bin

# 32-bit shellcode (x86)
capa-rs -f sc32 -r rules shellcode.bin

# Verbose output with match details
capa-rs -f sc64 -v -r rules shellcode.bin

# JSON output for integration
capa-rs -f sc64 -j -r rules shellcode.bin
```

### File Extensions

For convenience, files with these extensions are recognized as shellcode:
- `.sc32`, `.raw32` - 32-bit x86 shellcode
- `.sc64`, `.raw64` - 64-bit x64 shellcode

---

## Feature Extraction Overview

Shellcode analysis differs significantly from PE/ELF analysis:

| Feature | PE/ELF | Shellcode |
|---------|--------|-----------|
| **Import Table** | Yes | No (resolved at runtime) |
| **Export Table** | Yes | No |
| **Sections** | .text, .data, etc. | Single `.shellcode` section |
| **Entry Point** | From header | Offset 0 |
| **API Calls** | Resolved from IAT | Must be resolved via PEB walking |
| **OS Detection** | From header | Unknown (defaults to Windows) |

### Features Available in Shellcode

| Source | Feature Type | Description |
|--------|-------------|-------------|
| String Scan | `string:` | ASCII and UTF-16LE strings |
| Disassembly | `mnemonic:`, `number:`, `offset:` | Instruction-level features |
| Control Flow | `characteristic:` | Loops, calls, patterns |
| Format | `format:` | `sc32` or `sc64` |
| Architecture | `arch:` | `i386` or `amd64` |

### Features NOT Available in Shellcode

| Feature | Reason |
|---------|--------|
| `api:` | No import table to resolve |
| `import:` | No import table |
| `export:` | No export table |
| `section:` | No real sections (only synthetic `.shellcode`) |
| `os:` | Cannot detect from raw bytes (defaults to Windows) |

---

## Shellcode-Specific Characteristics

Shellcode often uses unique patterns that can be detected:

### Position-Independent Code Patterns

```yaml
# Get EIP/RIP via call $+5
- characteristic: call $+5

# Position-independent code marker
- characteristic: calls from shellcode

# Cross-section flow (unusual in normal code)
- characteristic: cross section flow
```

### API Resolution Patterns

```yaml
# Accesses PEB to find loaded modules
- characteristic: peb access

# Uses FS segment (x86 TEB access)
- characteristic: fs access

# Uses GS segment (x64 TEB access)
- characteristic: gs access
```

### Encoding/Decryption Patterns

```yaml
# Non-zero XOR (encryption/decoding)
- characteristic: nzxor

# Small loop (decoder stub)
- characteristic: tight loop

# Combination: XOR decoder
- and:
  - characteristic: tight loop
  - characteristic: nzxor
```

---

## Rule Examples for Shellcode

### Example 1: Basic Shellcode Detection

```yaml
rule:
  meta:
    name: shellcode with PEB walking
    namespace: load-code/shellcode
    authors:
      - your-name
    description: >
      Detects shellcode that accesses the PEB to resolve API addresses.
      This is the most common technique for position-independent API resolution.
    scopes:
      static: function
      dynamic: unsupported
    mbc:
      - Execution::Dynamic API Resolution [B0009]
  features:
    - and:
      - characteristic: peb access
      - or:
        - characteristic: fs access    # x86
        - characteristic: gs access    # x64
```

### Example 2: Shellcode Decoder Stub

```yaml
rule:
  meta:
    name: XOR decoder stub
    namespace: load-code/shellcode/decoder
    authors:
      - your-name
    description: >
      Detects XOR-based decoder stub commonly found in encoded shellcode.
      The tight loop with XOR is a signature of self-decrypting shellcode.
    scopes:
      static: basic block
      dynamic: unsupported
    mbc:
      - Defense Evasion::Obfuscated Files or Information::Encoding-XOR [E1027.m02]
  features:
    - and:
      - characteristic: tight loop
      - characteristic: nzxor
```

### Example 3: Call $+5 Pattern (Get EIP)

```yaml
rule:
  meta:
    name: get program counter via call
    namespace: load-code/shellcode
    authors:
      - your-name
    description: >
      Uses call $+5 to get the current instruction pointer.
      This is a classic shellcode technique for position-independent code.
    scopes:
      static: basic block
      dynamic: unsupported
    mbc:
      - Execution::Install Additional Program [E1105]
  features:
    - characteristic: call $+5
```

### Example 4: Embedded PE in Shellcode

```yaml
rule:
  meta:
    name: shellcode with embedded PE
    namespace: load-code/shellcode/loader
    authors:
      - your-name
    description: >
      Shellcode that contains an embedded PE file.
      Common in stagers that reflectively load a PE payload.
    scopes:
      static: file
      dynamic: unsupported
    att&ck:
      - Defense Evasion::Reflective Code Loading [T1620]
  features:
    - and:
      - characteristic: embedded pe
      - or:
        - characteristic: peb access
        - characteristic: call $+5
```

### Example 5: API Hash Resolution

```yaml
rule:
  meta:
    name: resolve API by hash
    namespace: load-code/shellcode
    authors:
      - your-name
    description: >
      Uses API hashing to resolve function addresses at runtime.
      Common hashing algorithms: ROR13, DJB2, CRC32.
    scopes:
      static: function
      dynamic: unsupported
    mbc:
      - Execution::Dynamic API Resolution::API Hashing [B0009.001]
  features:
    - and:
      - characteristic: peb access
      - characteristic: loop
      - or:
        # Common API hash values
        - number: 0x7C0DFCAA    # kernel32.LoadLibraryA (ROR13)
        - number: 0xEC0E4E8E    # kernel32.GetProcAddress (ROR13)
        - number: 0x73E2D87E    # kernel32.ExitProcess (ROR13)
        - number: 0x9DBD95A6    # kernel32.VirtualAlloc (ROR13)
        - number: 0xE553A458    # kernel32.VirtualFree (ROR13)
```

### Example 6: Shellcode with Stack Strings

```yaml
rule:
  meta:
    name: build strings on stack
    namespace: anti-analysis/obfuscation/string
    authors:
      - your-name
    description: >
      Builds strings on the stack to avoid static string detection.
      Common in shellcode and obfuscated malware.
    scopes:
      static: function
      dynamic: unsupported
    mbc:
      - Anti-Static Analysis::Disassembler Evasion::Argument Obfuscation [B0012.001]
  features:
    - characteristic: stack string
```

### Example 7: Anti-Debug in Shellcode

```yaml
rule:
  meta:
    name: check PEB BeingDebugged flag
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - your-name
    description: >
      Accesses PEB.BeingDebugged flag to detect debuggers.
      Common anti-debugging technique in shellcode.
    scopes:
      static: function
      dynamic: unsupported
    att&ck:
      - Defense Evasion::Debugger Evasion [T1622]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection::PEB BeingDebugged [B0001.001]
  features:
    - and:
      - characteristic: peb access
      - or:
        - offset: 0x02    # PEB.BeingDebugged (x86 & x64)
        - and:
          - or:
            - offset: 0x30    # TEB->PEB (x86)
            - offset: 0x60    # TEB->PEB (x64)
          - number: 0x02
```

### Example 8: Metasploit/Cobalt Strike Patterns

```yaml
rule:
  meta:
    name: Metasploit-style API resolution
    namespace: load-code/shellcode/framework
    authors:
      - your-name
    description: >
      Detects shellcode using Metasploit/Cobalt Strike-style
      block_api for API resolution.
    scopes:
      static: function
      dynamic: unsupported
    mbc:
      - Execution::Dynamic API Resolution [B0009]
  features:
    - and:
      - characteristic: peb access
      - characteristic: fs access
      - characteristic: loop
      # Metasploit ROR13 constants
      - or:
        - number: 0x0D       # ROR by 13
        - mnemonic: ror
```

---

## Common Shellcode Offsets

### PEB/TEB Offsets (x86)

```yaml
# TEB.ProcessEnvironmentBlock
- offset: 0x30

# PEB.Ldr
- offset: 0x0C

# PEB_LDR_DATA.InLoadOrderModuleList
- offset: 0x0C

# PEB_LDR_DATA.InMemoryOrderModuleList
- offset: 0x14

# PEB_LDR_DATA.InInitializationOrderModuleList
- offset: 0x1C

# LDR_DATA_TABLE_ENTRY.DllBase
- offset: 0x18

# PEB.BeingDebugged
- offset: 0x02
```

### PEB/TEB Offsets (x64)

```yaml
# TEB.ProcessEnvironmentBlock
- offset: 0x60

# PEB.Ldr
- offset: 0x18

# PEB_LDR_DATA.InLoadOrderModuleList
- offset: 0x10

# PEB_LDR_DATA.InMemoryOrderModuleList
- offset: 0x20

# PEB_LDR_DATA.InInitializationOrderModuleList
- offset: 0x30

# LDR_DATA_TABLE_ENTRY.DllBase
- offset: 0x30

# PEB.BeingDebugged
- offset: 0x02
```

---

## Common API Hash Values

These are ROR13 hash values commonly used in shellcode:

### kernel32.dll Functions

| Function | ROR13 Hash |
|----------|------------|
| LoadLibraryA | 0x7C0DFCAA |
| GetProcAddress | 0xEC0E4E8E |
| VirtualAlloc | 0x9DBD95A6 |
| VirtualFree | 0xE553A458 |
| VirtualProtect | 0x7946C61B |
| CreateThread | 0x160D6838 |
| ExitProcess | 0x73E2D87E |
| ExitThread | 0x60E0CEEF |
| WaitForSingleObject | 0x601D8708 |
| CloseHandle | 0x528796C6 |

### ws2_32.dll Functions

| Function | ROR13 Hash |
|----------|------------|
| WSAStartup | 0x3BFCEDCB |
| WSASocketA | 0xADF509D9 |
| connect | 0x6174A599 |
| send | 0x5F38EBC2 |
| recv | 0x5FC8D902 |
| closesocket | 0x614D6E75 |

### ntdll.dll Functions

| Function | ROR13 Hash |
|----------|------------|
| NtAllocateVirtualMemory | 0x6E0F1510 |
| NtProtectVirtualMemory | 0x9FA82AC0 |
| NtWriteVirtualMemory | 0x68A3C2BA |

---

## Architecture-Specific Rules

### x86-Only Shellcode

```yaml
rule:
  meta:
    name: x86 shellcode with FS segment
    namespace: load-code/shellcode
    scopes:
      static: function
      dynamic: unsupported
  features:
    - and:
      - arch: i386
      - characteristic: fs access
      - offset: 0x30    # TEB->PEB (x86)
```

### x64-Only Shellcode

```yaml
rule:
  meta:
    name: x64 shellcode with GS segment
    namespace: load-code/shellcode
    scopes:
      static: function
      dynamic: unsupported
  features:
    - and:
      - arch: amd64
      - characteristic: gs access
      - offset: 0x60    # TEB->PEB (x64)
```

### Architecture-Agnostic

```yaml
rule:
  meta:
    name: PEB-based API resolution
    namespace: load-code/shellcode
    scopes:
      static: function
      dynamic: unsupported
  features:
    - and:
      - characteristic: peb access
      - or:
        - and:
          - arch: i386
          - characteristic: fs access
        - and:
          - arch: amd64
          - characteristic: gs access
```

---

## Testing Shellcode Rules

### 1. Analyze Shellcode Sample

```bash
# 64-bit shellcode with verbose output
capa-rs -f sc64 -v -r rules/ shellcode.bin

# Dump features for debugging
capa-rs -f sc64 --dump-features features.json --extract-only shellcode.bin
```

### 2. Inspect Extracted Features

```bash
# View characteristics
jq '.file.characteristics' features.json

# View strings
jq '.file.strings | length' features.json

# View function count
jq '.functions | length' features.json
```

### 3. Test Specific Rule

```bash
# Test single rule file
capa-rs -f sc64 -r my-rule.yml shellcode.bin

# Filter by namespace
capa-rs -f sc64 -n "load-code/shellcode" -r rules/ shellcode.bin
```

---

## Limitations

### What Shellcode Analysis Cannot Detect

1. **API Calls**: Without IAT, `api:` features don't work
2. **Imports/Exports**: No tables to parse
3. **OS Detection**: Cannot determine target OS from raw bytes
4. **Sections**: Only synthetic `.shellcode` section exists

### Workarounds

| Missing Feature | Alternative |
|-----------------|-------------|
| `api: VirtualAlloc` | Use `number:` with API hash value |
| `import: ws2_32.dll` | Use `string: "ws2_32"` if present |
| `os: windows` | Assume Windows (most shellcode targets Windows) |
| `section: .text` | Not applicable, use `characteristic:` |

---

## Best Practices

### 1. Use Characteristics Over APIs

```yaml
# Good: Works with shellcode
- characteristic: peb access

# Won't work: No import table
# - api: GetProcAddress
```

### 2. Match on Behavior Patterns

```yaml
# Good: Detects decoder stub pattern
- and:
  - characteristic: tight loop
  - characteristic: nzxor

# Good: Detects PEB walking
- and:
  - characteristic: peb access
  - characteristic: loop
```

### 3. Use API Hash Constants

```yaml
# Match known API hashes
- or:
  - number: 0x7C0DFCAA    # LoadLibraryA
  - number: 0xEC0E4E8E    # GetProcAddress
```

### 4. Consider Both Architectures

```yaml
# Support both x86 and x64
- or:
  - and:
    - arch: i386
    - offset: 0x30    # x86 TEB->PEB
  - and:
    - arch: amd64
    - offset: 0x60    # x64 TEB->PEB
```

### 5. Set Dynamic Scope to Unsupported

```yaml
scopes:
  static: function
  dynamic: unsupported    # Shellcode is static analysis only
```

---

## Namespace Conventions for Shellcode Rules

| Namespace | Purpose |
|-----------|---------|
| `load-code/shellcode` | General shellcode detection |
| `load-code/shellcode/decoder` | Decoder stubs |
| `load-code/shellcode/loader` | PE/DLL loaders |
| `load-code/shellcode/framework` | Framework-specific (MSF, CS) |
| `anti-analysis/anti-debugging` | Anti-debug techniques |
| `anti-analysis/obfuscation` | Obfuscation patterns |

---

## Reference: Shellcode Feature Summary

| Feature | Available | Example |
|---------|-----------|---------|
| `string:` | Yes | `"kernel32.dll"` |
| `mnemonic:` | Yes | `ror`, `xor`, `call` |
| `number:` | Yes | `0x7C0DFCAA` (API hash) |
| `offset:` | Yes | `0x30`, `0x60` |
| `characteristic:` | Yes | `peb access`, `nzxor` |
| `arch:` | Yes | `i386`, `amd64` |
| `format:` | Yes | `sc32`, `sc64` |
| `api:` | No | Use `number:` with hash |
| `import:` | No | Use `string:` if embedded |
| `export:` | No | N/A |
| `section:` | Limited | Only `.shellcode` |
| `os:` | No | Defaults to Windows |
