# Writing CAPA Rules for PE Binaries

This guide covers how to write YAML-based CAPA rules that detect capabilities in Windows PE (Portable Executable) binaries using capa-rs.

## Build Requirements

```bash
cargo build --release -p capa-cli
```

---

## Feature Extraction Overview

When capa-rs processes a PE binary, it extracts features from multiple sources:

| Source | Feature Type | Description |
|--------|-------------|-------------|
| Import Address Table | `api:`, `import:` | Imported functions from DLLs |
| Export Table | `export:` | Exported functions |
| Section Headers | `section:` | Section names (.text, .data, etc.) |
| String Scan | `string:` | ASCII and UTF-16LE strings (4+ chars) |
| Disassembly | `mnemonic:`, `number:`, `offset:` | Instruction-level features |
| Control Flow | `characteristic:` | Loops, calls, patterns |
| PE Header | `format:`, `os:`, `arch:` | Binary metadata |

---

## Feature Types and Examples

### 1. Format and OS Constraints

**Constrain rules to Windows PE binaries:**

```yaml
# Match only PE files
- format: pe

# Match only Windows binaries
- os: windows

# Architecture constraints
- arch: i386      # 32-bit x86
- arch: amd64     # 64-bit x64
```

---

### 2. API Features

API calls resolved from disassembly (call instructions to IAT entries).

```yaml
# Short form (function name only)
- api: VirtualAlloc
- api: CreateProcessW
- api: RegSetValueExW

# Full form (module.function)
- api: kernel32.VirtualAlloc
- api: ntdll.NtCreateThreadEx
- api: advapi32.RegSetValueExW

# Regex patterns
- api: /Virtual(Alloc|AllocEx|Protect)/
- api: /Nt(Create|Open)(Process|Thread)/
```

#### Common API Categories

**Process Manipulation:**
```yaml
- api: CreateProcessW
- api: CreateProcessA
- api: OpenProcess
- api: TerminateProcess
- api: NtCreateProcess
- api: NtOpenProcess
```

**Memory Operations:**
```yaml
- api: VirtualAlloc
- api: VirtualAllocEx
- api: VirtualProtect
- api: VirtualProtectEx
- api: WriteProcessMemory
- api: ReadProcessMemory
- api: NtAllocateVirtualMemory
- api: NtProtectVirtualMemory
```

**Thread Operations:**
```yaml
- api: CreateThread
- api: CreateRemoteThread
- api: CreateRemoteThreadEx
- api: NtCreateThreadEx
- api: ResumeThread
- api: SuspendThread
- api: SetThreadContext
- api: GetThreadContext
```

**Registry Operations:**
```yaml
- api: RegOpenKeyExW
- api: RegSetValueExW
- api: RegCreateKeyExW
- api: RegDeleteKeyW
- api: NtSetValueKey
```

**File Operations:**
```yaml
- api: CreateFileW
- api: WriteFile
- api: ReadFile
- api: DeleteFileW
- api: CopyFileW
- api: MoveFileW
- api: NtCreateFile
```

**Network Operations:**
```yaml
- api: socket
- api: connect
- api: send
- api: recv
- api: WSAStartup
- api: InternetOpenW
- api: InternetConnectW
- api: HttpOpenRequestW
- api: WinHttpOpen
```

**Cryptography:**
```yaml
- api: CryptAcquireContextW
- api: CryptEncrypt
- api: CryptDecrypt
- api: CryptGenKey
- api: BCryptOpenAlgorithmProvider
- api: BCryptEncrypt
```

**Anti-Debug/Anti-Analysis:**
```yaml
- api: IsDebuggerPresent
- api: CheckRemoteDebuggerPresent
- api: NtQueryInformationProcess
- api: GetTickCount
- api: QueryPerformanceCounter
- api: OutputDebugStringW
```

---

### 3. Import Features

Raw imports from IAT (without requiring call instruction).

```yaml
# Function imports
- import: VirtualAlloc
- import: kernel32.VirtualAlloc

# DLL imports
- import: ws2_32.dll
- import: winhttp.dll
```

---

### 4. Export Features

Exported functions (for DLLs and some EXEs).

```yaml
- export: DllMain
- export: ServiceMain
- export: PluginInit

# Regex for export patterns
- export: /^Dll(Register|Unregister)Server$/
```

---

### 5. Section Features

Section names from PE section headers.

```yaml
# Standard sections
- section: .text
- section: .data
- section: .rdata
- section: .rsrc

# Packer/Protector indicators
- section: .upx0      # UPX
- section: .upx1
- section: .aspack    # ASPack
- section: .adata     # ASProtect
- section: .vmp0      # VMProtect
- section: .themida   # Themida
```

---

### 6. String Features

ASCII and UTF-16LE strings extracted from the binary.

```yaml
# File paths
- string: "C:\\Windows\\System32\\cmd.exe"
- string: "%APPDATA%\\malware.exe"

# URLs and IPs
- string: "http://c2.malware.com"
- string: /https?:\/\/[^\s]+/
- string: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

# Registry paths
- string: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
- string: /CurrentVersion\\Run/i

# Commands
- string: "cmd.exe /c"
- string: "powershell -enc"
- string: "schtasks /create"

# Mutex names (anti-reinfection)
- string: /^Global\\/
- string: /Mutex/i
```

---

### 7. Mnemonic Features

Assembly instruction mnemonics.

```yaml
# Specific instructions
- mnemonic: cpuid        # CPU detection
- mnemonic: rdtsc        # Timing (anti-debug)
- mnemonic: int 2d       # Debug interrupt
- mnemonic: sidt         # IDT access
- mnemonic: sgdt         # GDT access
- mnemonic: sldt         # LDT access

# Crypto-related
- mnemonic: aesenc
- mnemonic: aesdec
- mnemonic: pclmulqdq

# SIMD operations
- mnemonic: movdqa
- mnemonic: pxor
```

---

### 8. Number Features

Numeric constants from instruction operands.

```yaml
# Magic numbers
- number: 0x5A4D         # MZ header
- number: 0x4550         # PE signature
- number: 0xDEADBEEF     # Common marker

# Page protection constants
- number: 0x40           # PAGE_EXECUTE_READWRITE
- number: 0x20           # PAGE_EXECUTE_READ

# Process access rights
- number: 0x1F0FFF       # PROCESS_ALL_ACCESS
- number: 0x001F03FF     # THREAD_ALL_ACCESS

# Crypto constants
- number: 0x67452301     # MD5 init
- number: 0xEFCDAB89
- number: 0x98BADCFE
- number: 0x10325476
```

---

### 9. Offset Features

Memory offsets from addressing modes.

```yaml
# PEB offsets (x86)
- offset: 0x30           # TEB->PEB
- offset: 0x0C           # PEB->Ldr
- offset: 0x14           # PEB_LDR_DATA->InMemoryOrderModuleList

# PEB offsets (x64)
- offset: 0x60           # TEB->PEB (x64)
- offset: 0x18           # PEB->Ldr (x64)
```

---

### 10. Characteristic Features

Code patterns and behaviors detected during analysis.

#### File Scope Characteristics

```yaml
# Has embedded PE file
- characteristic: embedded pe

# Mixed-mode assembly (native + .NET)
- characteristic: mixed mode

# Has forwarded exports
- characteristic: forwarded export
```

#### Function Scope Characteristics

```yaml
# Contains a loop
- characteristic: loop

# Calls itself recursively
- characteristic: recursive call

# Non-zero XOR (potential encryption)
- characteristic: nzxor

# Accesses PEB (anti-debug, shellcode)
- characteristic: peb access

# Uses FS segment (x86 TEB access)
- characteristic: fs access

# Uses GS segment (x64 TEB access)
- characteristic: gs access

# Jump/call across sections
- characteristic: cross section flow
```

#### Basic Block Scope Characteristics

```yaml
# Small loop (shellcode decoder)
- characteristic: tight loop

# Builds string on stack (obfuscation)
- characteristic: stack string

# Position-independent code pattern
- characteristic: calls from shellcode
```

#### Instruction Scope Characteristics

```yaml
# Indirect call (call eax, call [ebx])
- characteristic: indirect call

# Call $+5 (get EIP, common in shellcode)
- characteristic: call $+5

# Direct call to API
- characteristic: unmangled call
```

---

## Boolean Logic

### AND - All conditions must match
```yaml
- and:
  - format: pe
  - api: VirtualAllocEx
  - api: WriteProcessMemory
  - api: CreateRemoteThread
```

### OR - Any condition matches
```yaml
- or:
  - api: CreateProcessW
  - api: CreateProcessA
  - api: ShellExecuteW
```

### N-of-M - At least N conditions match
```yaml
- 2 or more:
  - api: VirtualAllocEx
  - api: WriteProcessMemory
  - api: CreateRemoteThread
  - api: NtCreateThreadEx
```

### NOT - Exclude matches
```yaml
- and:
  - api: CreateRemoteThread
  - not:
    - section: .rsrc    # Exclude resource-only DLLs
```

### Nested Logic
```yaml
- and:
  - format: pe
  - or:
    - api: VirtualAlloc
    - api: VirtualAllocEx
  - or:
    - characteristic: nzxor
    - characteristic: tight loop
```

---

## Scope Specification

Scopes define where features are evaluated.

```yaml
scopes:
  static: file           # File-level features
  dynamic: file

scopes:
  static: function       # Function-level features
  dynamic: process

scopes:
  static: basic block    # Basic block features
  dynamic: thread

scopes:
  static: instruction    # Instruction-level features
  dynamic: call
```

---

## Complete Rule Examples

### Example 1: Process Injection

```yaml
rule:
  meta:
    name: inject code into remote process
    namespace: host-interaction/process/inject
    authors:
      - your-name
    description: >
      Allocates memory in a remote process, writes code, and creates
      a remote thread to execute it. Classic process injection technique.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    mbc:
      - Process::Inject Code [E1055]
  features:
    - and:
      - or:
        - api: VirtualAllocEx
        - api: NtAllocateVirtualMemory
      - or:
        - api: WriteProcessMemory
        - api: NtWriteVirtualMemory
      - or:
        - api: CreateRemoteThread
        - api: CreateRemoteThreadEx
        - api: NtCreateThreadEx
        - api: RtlCreateUserThread
```

### Example 2: Anti-Debug Techniques

```yaml
rule:
  meta:
    name: detect debugger via API
    namespace: anti-analysis/anti-debugging
    authors:
      - your-name
    description: >
      Uses Windows APIs to detect if a debugger is attached.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Defense Evasion::Debugger Evasion [T1622]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
  features:
    - and:
      - format: pe
      - or:
        - api: IsDebuggerPresent
        - api: CheckRemoteDebuggerPresent
        - and:
          - api: NtQueryInformationProcess
          - or:
            - number: 0x07    # ProcessDebugPort
            - number: 0x1F    # ProcessDebugFlags
```

### Example 3: PEB Walking Shellcode

```yaml
rule:
  meta:
    name: resolve API via PEB walking
    namespace: load-code/shellcode
    authors:
      - your-name
    description: >
      Walks the PEB to find loaded modules and resolve API addresses.
      Common technique in shellcode and position-independent code.
    scopes:
      static: function
      dynamic: thread
    mbc:
      - Execution::Dynamic API Resolution [B0009]
  features:
    - and:
      - format: pe
      - characteristic: peb access
      - or:
        - characteristic: fs access
        - characteristic: gs access
      - or:
        - offset: 0x30    # TEB->PEB (x86)
        - offset: 0x60    # TEB->PEB (x64)
```

### Example 4: XOR Encryption Loop

```yaml
rule:
  meta:
    name: encrypt data using XOR loop
    namespace: data-manipulation/encryption/xor
    authors:
      - your-name
    description: >
      Uses XOR in a tight loop, common pattern for simple encryption
      or string decoding in malware.
    scopes:
      static: basic block
      dynamic: thread
    mbc:
      - Cryptography::Encrypt Data::XOR [C0027.003]
  features:
    - and:
      - format: pe
      - characteristic: tight loop
      - characteristic: nzxor
```

### Example 5: Registry Persistence

```yaml
rule:
  meta:
    name: persist via Run registry key
    namespace: persistence/registry
    authors:
      - your-name
    description: >
      Creates registry value in Run key for persistence.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys [T1547.001]
    mbc:
      - Persistence::Registry [F0012]
  features:
    - and:
      - format: pe
      - or:
        - api: RegSetValueExW
        - api: RegSetValueExA
        - api: NtSetValueKey
      - or:
        - string: /CurrentVersion\\Run/i
        - string: /CurrentVersion\\RunOnce/i
```

### Example 6: Packed/Encrypted Binary

```yaml
rule:
  meta:
    name: packed with UPX
    namespace: executable/packed/upx
    authors:
      - your-name
    description: >
      Binary packed with UPX packer.
    scopes:
      static: file
      dynamic: file
  features:
    - and:
      - format: pe
      - section: UPX0
      - section: UPX1
```

---

## Testing Rules

### 1. Extract Features for Debugging

```bash
# Dump features to JSON
capa-rs.exe --dump-features features.json --extract-only sample.exe

# Check feature counts
jq '.file | {apis: .apis | length, strings: .strings | length, imports: .imports | length}' features.json

# Search for specific APIs
jq '.file.apis[]' features.json | grep -i "virtual"
```

### 2. Test Rules Against Sample

```bash
# Test single rule
capa-rs.exe -r path/to/rule.yml sample.exe

# Test rule directory
capa-rs.exe -r path/to/rules/ sample.exe

# Verbose output
capa-rs.exe -v -r path/to/rules/ sample.exe
```

---

## Best Practices

### 1. Constrain by Format
```yaml
- format: pe
```

### 2. Use Multiple Indicators
```yaml
# Good: Multiple related APIs
- and:
  - api: VirtualAllocEx
  - api: WriteProcessMemory
  - api: CreateRemoteThread

# Avoid: Single common API
- api: VirtualAlloc    # Too generic
```

### 3. Use Both Short and Full API Names
```yaml
- or:
  - api: VirtualAlloc
  - api: kernel32.VirtualAlloc
```

### 4. Consider API Variants
```yaml
- or:
  - api: CreateProcessW
  - api: CreateProcessA
  - api: CreateProcessAsUserW
  - api: CreateProcessWithLogonW
```

### 5. Use Regex for Patterns
```yaml
- api: /Virtual(Alloc|AllocEx|Protect|ProtectEx)/
- api: /Nt(Create|Open)(Process|Thread)/
```

---

## Namespace Conventions

| Namespace | Purpose |
|-----------|---------|
| `anti-analysis/anti-debugging` | Debugger detection |
| `anti-analysis/anti-vm` | VM detection |
| `data-manipulation/encryption/*` | Encryption operations |
| `executable/packed/*` | Packer detection |
| `host-interaction/process/inject` | Process injection |
| `host-interaction/registry` | Registry operations |
| `load-code/shellcode` | Shellcode patterns |
| `persistence/registry` | Registry persistence |
| `persistence/scheduled-task` | Task scheduler |
| `communication/*` | Network communication |

---

## Extracted Feature Reference

| Feature | CAPA Matcher | Source | Example |
|---------|-------------|--------|---------|
| API call | `api:` | Disasm + IAT | `kernel32.VirtualAlloc` |
| Import | `import:` | IAT | `VirtualAlloc` |
| Export | `export:` | Export table | `DllMain` |
| Section | `section:` | Section headers | `.text` |
| String | `string:` | String scan | `"cmd.exe"` |
| Mnemonic | `mnemonic:` | Disassembly | `cpuid` |
| Number | `number:` | Operands | `0x40` |
| Offset | `offset:` | Memory refs | `0x30` |
| Characteristic | `characteristic:` | Analysis | `nzxor` |
| Format | `format:` | PE header | `pe` |
| OS | `os:` | PE header | `windows` |
| Arch | `arch:` | PE header | `i386`, `amd64` |
