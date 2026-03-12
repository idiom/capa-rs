# Writing CAPA Rules for .NET Binaries

This guide covers how to write YAML-based CAPA rules that detect capabilities in .NET assemblies using capa-rs with the `dotnet` feature enabled.

## Build Requirements

```bash
cargo build --release -p capa-cli --features dotnet
```

---

## Feature Extraction Overview

When capa-rs processes a .NET binary, it extracts features from multiple sources:

| Source | Feature Type | Scope | Description |
|--------|-------------|-------|-------------|
| #US Heap | `string:` | file, function | User strings - string literals used in IL code |
| TypeDef Table | `string:` | file | Type names (Namespace.ClassName format) |
| MethodDef Table | `string:`, `function-name:` | file, function | Method names defined in the assembly |
| MemberRef Table | `string:`, `api:` | file | External method/type references (API calls) |
| ImplMap Table | `string:`, `api:` | file | P/Invoke declarations (native imports) |
| ModuleRef Table | `string:` | file | Native DLL names referenced |
| Namespace | `string:` | file | All namespaces in the assembly |
| IL Disassembly | `mnemonic:` | file, function | CIL opcodes (ldstr, call, newobj, etc.) |
| IL Operands | `number:` | file, function | Numeric constants from IL instructions |
| PE Header | `format:`, `characteristic:` | file | Format detection, embedded PE |

### Function-Scope Feature Tracking

capa-rs tracks features per .NET method, enabling function-scope rules to match at specific method RVAs. This is achieved by:

1. **IL Instruction Decoding** - Each method body is decoded to extract IL opcodes
2. **ldstr Token Resolution** - `ldstr` instructions reference the #US heap via metadata tokens; capa-rs resolves these to actual strings
3. **Per-Method Feature Maps** - Strings, mnemonics, and numbers are tracked per method RVA

When a rule matches, the output shows the method RVA and name (e.g., `0x4814 (Install)`) for precise RE targeting.

### Critical: File-Level vs Per-Method Features

**This distinction is essential for writing effective .NET rules.**

| Feature Source | Tracked Per-Method? | Example |
|----------------|:-------------------:|---------|
| User strings (`ldstr` targets) | **Yes** | `"http://c2.evil.com"`, `"cmd.exe"` |
| Type names (TypeDef/TypeRef) | No | `"System.Security.Cryptography.AesManaged"` |
| API calls (MemberRef) | No | `"Process.Start"`, `"WebClient.DownloadString"` |
| P/Invoke declarations | No | `"VirtualAlloc"`, `"kernel32.CreateRemoteThread"` |
| IL mnemonics | **Yes** | `call`, `newobj`, `xor`, `ldstr` |
| IL numeric constants | **Yes** | `0x40`, `13`, `256` |
| Function names | **Yes** | `"Encrypt"`, `"Install"`, `"SendData"` |

**Implications for Rule Writing:**

```yaml
# WORKS at function-scope: user strings loaded via ldstr
- and:
  - string: "CurrentVersion\\Run"    # User string in method
  - mnemonic: call                    # IL opcode in method

# DOES NOT WORK at function-scope: type references are file-level
- and:
  - string: "AesCryptoServiceProvider"  # Type name (file-level only!)
  - mnemonic: newobj                     # IL opcode (per-method)
  # These will never be in the same function's features
```

**Best Practices for Function-Scope .NET Rules:**
1. Use `function-name:` patterns to identify methods by name
2. Use IL mnemonics that are tracked per-method
3. Use numeric constants from IL operands
4. Only use `string:` for actual string literals (ldstr targets), not type/API names
5. For type references like `"AesCryptoServiceProvider"`, use file-scope rules

---

## Feature Types and Examples

### 1. Format Constraint

**Always include for .NET-specific rules.**

```yaml
- format: dotnet
```

This ensures the rule only matches .NET assemblies (detected via CLR header or mscoree.dll import).

---

### 2. String Features

Strings are the primary matching mechanism for .NET rules. The following are merged into the `strings` set:

#### 2.1 User Strings (#US Heap)

Actual string literals used in code (ldstr instruction targets).

```yaml
# C2 URLs
- string: "http://malicious-c2.com/beacon"
- string: "ws://192.168.1.100:4444"

# File paths
- string: "C:\\Windows\\System32\\cmd.exe"
- string: "%APPDATA%\\payload.exe"

# Registry paths
- string: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Commands
- string: "/c ping localhost"
- string: "schtasks /create"

# Hardcoded credentials
- string: "password123"
- string: "admin:admin"
```

#### 2.2 Type Names

Full qualified type names from TypeDef and TypeRef tables.

```yaml
# Cryptography types
- string: "System.Security.Cryptography.AesManaged"
- string: "System.Security.Cryptography.RSACryptoServiceProvider"
- string: "System.Security.Cryptography.SHA256Managed"

# Network types
- string: "System.Net.Sockets.TcpClient"
- string: "System.Net.WebClient"
- string: "System.Net.Http.HttpClient"
- string: "System.Net.Security.SslStream"

# Process types
- string: "System.Diagnostics.Process"
- string: "System.Diagnostics.ProcessStartInfo"

# Registry types
- string: "Microsoft.Win32.Registry"
- string: "Microsoft.Win32.RegistryKey"

# Reflection types
- string: "System.Reflection.Assembly"
- string: "System.Reflection.MethodInfo"
- string: "System.Activator"
```

#### 2.3 Method Names

All method names defined in the assembly.

```yaml
# Common malware method patterns
- string: "DecryptConfig"
- string: "SendData"
- string: "DownloadPayload"
- string: "ExecuteCommand"
- string: "GrabPasswords"
- string: "KeyLogger"

# .NET Framework method names
- string: "CreateEncryptor"
- string: "TransformFinalBlock"
- string: "GetBytes"
- string: "FromBase64String"
```

#### 2.4 API Calls (MemberRef)

External method references to other assemblies.

```yaml
# Process execution
- string: "Process.Start"
- string: "ProcessStartInfo"

# File operations
- string: "File.WriteAllBytes"
- string: "File.ReadAllBytes"
- string: "Directory.CreateDirectory"

# Registry operations
- string: "Registry.SetValue"
- string: "RegistryKey.CreateSubKey"

# Network operations
- string: "WebClient.DownloadString"
- string: "WebClient.DownloadData"
- string: "TcpClient.Connect"
- string: "SslStream.AuthenticateAsClient"

# Cryptography
- string: "AesManaged.CreateEncryptor"
- string: "RijndaelManaged.CreateDecryptor"

# Reflection/Dynamic loading
- string: "Assembly.Load"
- string: "Assembly.LoadFrom"
- string: "Activator.CreateInstance"
- string: "MethodInfo.Invoke"
- string: "GetManifestResourceStream"
```

#### 2.5 P/Invoke Calls (Native Imports)

Native API calls via DllImport. Extracted in both short and full formats.

```yaml
# Short form (function name only)
- string: "VirtualAlloc"
- string: "VirtualAllocEx"
- string: "VirtualProtect"
- string: "WriteProcessMemory"
- string: "CreateRemoteThread"
- string: "NtCreateThreadEx"
- string: "SetWindowsHookEx"
- string: "GetAsyncKeyState"
- string: "OpenProcess"
- string: "ReadProcessMemory"

# Full form (module.function)
- string: "kernel32.VirtualAlloc"
- string: "kernel32.CreateRemoteThread"
- string: "ntdll.NtCreateThreadEx"
- string: "user32.SetWindowsHookEx"
- string: "user32.GetAsyncKeyState"
- string: "advapi32.RegSetValueEx"
```

#### 2.6 Namespace Names

All namespaces used in the assembly.

```yaml
- string: "System.Security.Cryptography"
- string: "System.Net.Sockets"
- string: "System.Diagnostics"
- string: "Microsoft.Win32"
- string: "System.Runtime.InteropServices"
```

---

### 3. Regex Patterns

Use regular expressions for flexible matching.

```yaml
# URL patterns
- string: /https?:\/\/[^\s"']+/

# IP addresses
- string: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

# Port patterns
- string: /:\d{2,5}/

# Base64 encoded data (50+ chars)
- string: /[A-Za-z0-9+\/]{50,}={0,2}/

# Hex strings (potential keys/hashes)
- string: /[0-9A-Fa-f]{32,}/

# Registry Run keys
- string: /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i

# File extensions
- string: /\.(exe|dll|bat|ps1|vbs)$/i

# P/Invoke patterns
- string: /Virtual(Alloc|AllocEx|Protect|ProtectEx)/
- string: /(Create|Open)(Process|Thread|File)/
```

---

### 4. Characteristic Features

Binary-level characteristics.

```yaml
# Has embedded PE (dropper detection)
- characteristic: embedded pe

# Mixed-mode assembly (native + managed code)
- characteristic: mixed mode
```

---

### 5. Import Features

Native PE imports (from IAT).

```yaml
# CLR runtime import (all .NET binaries have this)
- import: "_CorExeMain"
- import: "mscoree.dll._CorExeMain"
```

---

### 6. IL Mnemonic Features

CIL (Common Intermediate Language) opcodes extracted from method bodies.

```yaml
# String loading
- mnemonic: ldstr          # Load string literal

# Method calls
- mnemonic: call           # Direct method call
- mnemonic: callvirt       # Virtual method call
- mnemonic: newobj         # Object instantiation

# Control flow
- mnemonic: ret            # Return from method
- mnemonic: br             # Unconditional branch
- mnemonic: brfalse        # Branch if false/null
- mnemonic: brtrue         # Branch if true/non-null
- mnemonic: switch         # Switch statement
- mnemonic: throw          # Throw exception

# Local variables
- mnemonic: ldloc.0        # Load local variable 0
- mnemonic: stloc.0        # Store to local variable 0
- mnemonic: ldloc.s        # Load local (short form)
- mnemonic: stloc.s        # Store local (short form)

# Arguments
- mnemonic: ldarg.0        # Load argument 0 (this)
- mnemonic: ldarg.1        # Load argument 1
- mnemonic: starg.s        # Store argument

# Fields
- mnemonic: ldfld          # Load instance field
- mnemonic: stfld          # Store instance field
- mnemonic: ldsfld         # Load static field
- mnemonic: stsfld         # Store static field

# Arrays
- mnemonic: newarr         # Create array
- mnemonic: ldlen          # Get array length
- mnemonic: ldelem         # Load array element
- mnemonic: stelem.ref     # Store reference in array

# Constants
- mnemonic: ldc.i4         # Load 32-bit integer constant
- mnemonic: ldc.i4.0       # Load integer 0
- mnemonic: ldc.i4.1       # Load integer 1
- mnemonic: ldc.i8         # Load 64-bit integer
- mnemonic: ldnull         # Load null reference

# Type operations
- mnemonic: castclass      # Cast to class
- mnemonic: isinst         # Type check (as operator)
- mnemonic: box            # Box value type
- mnemonic: unbox.any      # Unbox to value type

# Arithmetic
- mnemonic: add            # Addition
- mnemonic: sub            # Subtraction
- mnemonic: mul            # Multiplication
- mnemonic: div            # Division
- mnemonic: xor            # XOR (encryption indicator)
- mnemonic: and            # Bitwise AND
- mnemonic: or             # Bitwise OR

# Function pointers (delegates)
- mnemonic: ldftn          # Load method pointer
- mnemonic: ldvirtftn      # Load virtual method pointer

# Exception handling
- mnemonic: leave          # Exit try/catch block
- mnemonic: endfinally     # End finally block

# Misc
- mnemonic: dup            # Duplicate top of stack
- mnemonic: pop            # Pop from stack
- mnemonic: nop            # No operation
- mnemonic: ldtoken        # Load metadata token
```

#### Common IL Patterns for Malware Detection

```yaml
# XOR encryption loop indicator
- and:
  - mnemonic: xor
  - or:
    - mnemonic: ldelem
    - mnemonic: ldelem.u1

# Dynamic method invocation (reflection)
- and:
  - mnemonic: callvirt
  - string: "MethodInfo.Invoke"

# String decryption pattern
- and:
  - mnemonic: ldstr
  - mnemonic: call
  - string: "FromBase64String"
```

#### IL Pattern Recipes for Function-Scope Detection

These patterns work well at function-scope because they use per-method features:

```yaml
# Detect crypto methods by name + IL
- and:
  - function-name: /[Ee]ncrypt|[Dd]ecrypt/
  - mnemonic: call

# Detect XOR decryption loops
- and:
  - mnemonic: xor
  - mnemonic: ldelem.u1
  - mnemonic: stelem.i1

# Detect process injection setup
- and:
  - number: 0x40              # PAGE_EXECUTE_READWRITE
  - mnemonic: call

# Detect keyboard hook installation
- and:
  - number: 13                # WH_KEYBOARD_LL
  - mnemonic: call

# Detect persistence methods by name
- and:
  - or:
    - function-name: /[Ii]nstall/
    - function-name: /[Pp]ersist/
    - function-name: /[Ss]tartup/
  - mnemonic: call

# Detect methods with suspicious string patterns
- and:
  - or:
    - string: /cmd\.exe/i
    - string: /powershell/i
    - string: /CurrentVersion\\Run/i
  - mnemonic: call
```

---

### 7. IL Number Features

Numeric constants from IL instruction operands.

```yaml
# Common constants
- number: 0                # False, null checks
- number: 1                # True, flags
- number: 4096             # Common buffer size (0x1000)
- number: 65535            # Max port number

# Memory protection (for P/Invoke)
- number: 0x40             # PAGE_EXECUTE_READWRITE
- number: 0x3000           # MEM_COMMIT | MEM_RESERVE

# Crypto constants
- number: 256              # Common key/block size
- number: 128              # AES block size in bits
```

---

## Boolean Logic

### AND - All conditions must match
```yaml
- and:
  - format: dotnet
  - string: "CreateEncryptor"
  - string: "TransformFinalBlock"
```

### OR - Any condition matches
```yaml
- or:
  - string: "AesManaged"
  - string: "AesCryptoServiceProvider"
  - string: "RijndaelManaged"
```

### N-of-M - At least N conditions match
```yaml
# At least 2 of these indicators
- 2 or more:
  - string: "VirtualAlloc"
  - string: "WriteProcessMemory"
  - string: "CreateRemoteThread"
  - string: "NtCreateThreadEx"
```

### NOT - Exclude matches
```yaml
- and:
  - format: dotnet
  - string: "CreateRemoteThread"
  - not:
    - string: "DebuggerTests"  # Exclude test assemblies
```

### Nested Logic
```yaml
- and:
  - format: dotnet
  - or:
    - string: "AesManaged"
    - string: "RijndaelManaged"
  - or:
    - string: "CreateEncryptor"
    - string: "CreateDecryptor"
```

---

## Function-Scope Rules

Function-scope rules match features within individual .NET methods. When matched, they report the method's RVA address and name (e.g., `0x4814 (Install)`).

### Match Location Output

capa-rs now shows method locations for all matches when possible:

```
# Function-scope rule - shows exact method
persist via registry Run key (function-scope)
  matches:   0x4814 (Install)

# File-scope rule - shows contributing methods when identifiable
bypass ETW via memory patching in .NET
  matches:   0x24c3 (PatchETW)

# File-scope rule - shows "file" only when features span multiple methods
communicate via SSL stream in .NET
  matches:   file
```

### Scope Configuration

```yaml
scopes:
  static: function    # Match at method level
  dynamic: call       # For dynamic analysis compatibility
```

### Function-Scope Example: Detect Registry Persistence (with IL)

```yaml
rule:
  meta:
    name: persist via registry run key (function-scope)
    namespace: persistence/registry
    scopes:
      static: function
      dynamic: call
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys [T1547.001]
  features:
    - and:
      - format: dotnet
      - string: /CurrentVersion\\Run/i   # User string (ldstr target)
      - or:
        - mnemonic: call                  # Confirms API call present
        - mnemonic: callvirt
```

**Example Output:**
```
persist via registry run key (function-scope)
  namespace: persistence/registry
  matches:   0x4814 (Install)    ← Method RVA and name
```

### Function-Scope Example: Detect Crypto Methods by Name

```yaml
rule:
  meta:
    name: crypto method detected by name and IL
    namespace: data-manipulation/encryption
    scopes:
      static: function
      dynamic: call
  features:
    - and:
      - format: dotnet
      - or:
        - function-name: /[Ee]ncrypt/    # Method name pattern
        - function-name: /[Dd]ecrypt/
        - function-name: /[Cc]rypto/
      - mnemonic: call                    # Confirms method has calls
```

**Example Output:**
```
crypto method detected by name and IL (3 matches)
  matches:   0x62ac (Decrypt)
             0x2556 (Encrypt)
             0x256e
```

### Features Available at Function Scope

| Feature | Available | Notes |
|---------|-----------|-------|
| `string:` | **Partial** | Only user strings loaded via `ldstr` (not type/API names) |
| `mnemonic:` | **Yes** | IL opcodes used in the method |
| `number:` | **Yes** | Numeric constants from IL operands |
| `function-name:` | **Yes** | The method's own name (powerful for pattern matching) |
| `format:` | Yes | Inherited from file |
| `api:` | No | API references are file-scope only |
| `import:` | No | PE imports are file-scope only |
| `characteristic:` | No | File-scope only |

**Warning:** Type names like `"AesCryptoServiceProvider"` and API names like `"Process.Start"` are file-scope only. They will never match at function scope even though they appear in `string:` features.

### Effective Function-Scope Patterns

**DO use these (tracked per-method):**
```yaml
- function-name: /Encrypt/           # Method name pattern
- mnemonic: newobj                   # Object instantiation
- mnemonic: call                     # Method calls
- mnemonic: xor                      # XOR operations
- number: 13                         # WH_KEYBOARD_LL constant
- number: 0x40                       # PAGE_EXECUTE_READWRITE
- string: "http://evil.com"          # User string literal
```

**DON'T use these at function-scope (file-level only):**
```yaml
- string: "AesCryptoServiceProvider"  # Type name, not user string
- string: "VirtualAlloc"              # P/Invoke name, not user string
- api: "Process.Start"                # API reference
```

### When to Use Function Scope

- **Pinpoint malicious methods** - Identify exactly which method contains suspicious behavior
- **Reduce false positives** - Require features to co-occur within a single method
- **Target RE analysis** - Jump directly to the method implementing the capability
- **Use `function-name:` patterns** - Match methods by naming conventions (Encrypt, Decrypt, Install, etc.)

### File vs Function Scope Decision

```yaml
# Use FILE scope when:
# - Matching type names (AesCryptoServiceProvider)
# - Matching API references (Process.Start)
# - Features naturally span multiple methods
scopes:
  static: file

# Use FUNCTION scope when:
# - Matching user string literals (URLs, paths, commands)
# - Matching IL patterns (xor + ldelem for decryption)
# - Matching method names (function-name: /Encrypt/)
# - You need the exact method RVA for RE
scopes:
  static: function
```

---

## Complete Rule Examples

### Example 1: Process Injection Detection

```yaml
rule:
  meta:
    name: inject code via P/Invoke in .NET
    namespace: host-interaction/process/inject
    authors:
      - your-name
    description: >
      Uses P/Invoke to call native APIs commonly used for process injection.
      This includes VirtualAlloc(Ex) for memory allocation, WriteProcessMemory
      for shellcode writing, and CreateRemoteThread for execution.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Process Injection [T1055]
      - Defense Evasion::Process Injection::Process Hollowing [T1055.012]
    mbc:
      - Process::Inject Code [E1055]
  features:
    - and:
      - format: dotnet
      - or:
        - string: "VirtualAllocEx"
        - string: "kernel32.VirtualAllocEx"
      - or:
        - string: "WriteProcessMemory"
        - string: "kernel32.WriteProcessMemory"
      - or:
        - string: "CreateRemoteThread"
        - string: "kernel32.CreateRemoteThread"
        - string: "NtCreateThreadEx"
        - string: "ntdll.NtCreateThreadEx"
```

### Example 2: Keylogger Detection

```yaml
rule:
  meta:
    name: log keystrokes via hook in .NET
    namespace: collection/keylog
    authors:
      - your-name
    description: >
      Uses Windows hooks or GetAsyncKeyState to capture keystrokes.
      Common technique in info-stealers and RATs.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Collection::Input Capture::Keylogging [T1056.001]
    mbc:
      - Collection::Keylogging [F0002]
  features:
    - and:
      - format: dotnet
      - or:
        - and:
          - string: "SetWindowsHookEx"
          - or:
            - string: "WH_KEYBOARD"
            - string: "WH_KEYBOARD_LL"
            - string: /WH_KEYBOARD/i
        - and:
          - string: "GetAsyncKeyState"
          - or:
            - string: "Keys"
            - string: "VirtualKey"
```

### Example 3: C2 Communication Detection

```yaml
rule:
  meta:
    name: communicate via encrypted channel in .NET
    namespace: communication/encrypted
    authors:
      - your-name
    description: >
      Establishes encrypted network communication using TLS/SSL.
      Combined with TCP socket usage indicates potential C2 channel.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Command and Control::Encrypted Channel [T1573]
      - Command and Control::Encrypted Channel::Asymmetric Cryptography [T1573.002]
    mbc:
      - Communication::Encrypted Communication [C0030]
  features:
    - and:
      - format: dotnet
      - or:
        - string: "TcpClient"
        - string: "System.Net.Sockets.TcpClient"
      - or:
        - string: "SslStream"
        - string: "System.Net.Security.SslStream"
      - or:
        - string: "AuthenticateAsClient"
        - string: "GetStream"
```

### Example 4: Malware Family Detection

```yaml
rule:
  meta:
    name: reference VenomRAT malware family
    namespace: malware-family/rat
    authors:
      - your-name
    description: >
      References strings specific to VenomRAT and related variants
      (AsyncRAT, QuasarRAT). These strings indicate the malware family.
    scopes:
      static: file
      dynamic: file
    references:
      - https://malpedia.caad.fkie.fraunhofer.de/details/win.venomrat
  features:
    - and:
      - format: dotnet
      - or:
        - string: "VenomRAT"
        - string: "Venom RAT"
        - string: "HVNC"
        - string: "AsyncClient"
        - and:
          - string: "Client.Algorithm"
          - string: "Client.Connection"
          - string: "Client.Handle"
```

### Example 5: Anti-Analysis Detection

```yaml
rule:
  meta:
    name: detect virtual machine in .NET
    namespace: anti-analysis/anti-vm
    authors:
      - your-name
    description: >
      Detects VM environment by checking for VM-specific artifacts
      using WMI queries or checking hardware characteristics.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]
    mbc:
      - Anti-Behavioral Analysis::Virtual Machine Detection [B0009]
  features:
    - and:
      - format: dotnet
      - or:
        - string: "Win32_CacheMemory"
        - string: "SELECT * FROM Win32_CacheMemory"
        - string: "Win32_BIOS"
        - string: "VMware"
        - string: "VirtualBox"
        - string: "VBOX"
        - string: "Virtual Machine"
```

### Example 6: Persistence Detection

```yaml
rule:
  meta:
    name: persist via scheduled task in .NET
    namespace: persistence/scheduled-task
    authors:
      - your-name
    description: >
      Creates scheduled tasks for persistence using schtasks.exe
      or the Task Scheduler COM interface.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Scheduled Task/Job::Scheduled Task [T1053.005]
    mbc:
      - Persistence::Scheduled Task [F0003]
  features:
    - and:
      - format: dotnet
      - or:
        - and:
          - string: "schtasks"
          - or:
            - string: "/create"
            - string: "/Create"
        - and:
          - string: "TaskScheduler"
          - or:
            - string: "RegisterTask"
            - string: "NewTask"
```

---

## Testing Rules

### 1. Extract Features for Debugging

```bash
# Dump features to JSON
capa-rs.exe --dump-features features.json --extract-only sample.exe

# View file-level feature counts
jq '.file.strings | length' features.json
jq '.file.apis | length' features.json

# Search for specific patterns at file level
jq '.file.strings[]' features.json | grep -i "pattern"
```

### 2. Inspect Function-Level Features

```bash
# Count functions with features
jq '.functions | length' features.json

# Find functions with strings (for function-scope rules)
jq '.functions | to_entries[] | select(.value.features.strings | length > 0) | {rva: .key, name: .value.features.function_names, string_count: (.value.features.strings | length)}' features.json

# List strings in a specific function (by RVA)
jq '.functions["20624"].features.strings' features.json

# Find functions with specific mnemonics
jq '.functions | to_entries[] | select(.value.features.mnemonics.ldstr > 0) | .key' features.json
```

### 3. Test Rules Against Sample

```bash
# Test single rule file
capa-rs.exe -r path/to/rule.yml sample.exe

# Test rule directory
capa-rs.exe -r path/to/rules/ sample.exe

# Verbose output with match details (shows RVAs for function-scope rules)
capa-rs.exe -v -r path/to/rules/ sample.exe
```

**Example verbose output for function-scope rules:**
```
persist via registry run key in method
  namespace: persistence/registry
  ATT&CK:    T1547.001
  matches:   0x4814        ← Method RVA

reference WMI statements
  namespace: collection/database/wmi
  matches:   0x4cac        ← Method RVA
```

### 4. Validate Rule Syntax

Rules must have:
- `rule:` root key
- `meta:` section with `name` and `scopes`
- `features:` section with at least one feature

For function-scope rules:
```yaml
scopes:
  static: function    # Required for method-level matching
  dynamic: call       # Use 'call' for dynamic scope (not 'function')
```

---

## Best Practices

### 1. Always Constrain by Format
```yaml
- format: dotnet
```

### 2. Use Multiple Indicators
Avoid false positives with multiple indicators:
```yaml
# Good: Multiple related indicators
- and:
  - format: dotnet
  - 2 or more:
    - string: "VirtualAlloc"
    - string: "WriteProcessMemory"
    - string: "CreateRemoteThread"

# Avoid: Single common string
- string: "GetBytes"  # Too generic
```

### 3. Consider Both Short and Full API Names
```yaml
- or:
  - string: "VirtualAlloc"
  - string: "kernel32.VirtualAlloc"
```

### 4. Use Regex for Variations
```yaml
# Case insensitive
- string: /VirtualAlloc/i

# Multiple related functions
- string: /Virtual(Alloc|AllocEx|Protect)/
```

### 5. Document Well
Include description, ATT&CK mappings, and references.

### 6. Use IL Patterns for Better Precision
Add IL mnemonics to reduce false positives:
```yaml
# Better: String + IL confirms actual usage
- and:
  - string: /CurrentVersion\\Run/i
  - mnemonic: call         # Confirms method call present

# Even better: Function name + IL
- and:
  - function-name: /[Ii]nstall/
  - mnemonic: call
  - string: /Run/
```

---

## Filtered Rules

capa-rs automatically filters certain rules from output to reduce noise:

| Filtered | Reason |
|----------|--------|
| Library rules (`lib: true`) | Helper rules for other rules, not standalone detections |
| `internal/*` namespace | Meta/limitation rules, not capability detections |
| `"compiled to the .NET platform"` | Generic format detection, matches everything |

These rules still match and can be referenced by other rules, but are hidden from the final output to focus on actionable capability detections.

---

## Namespace Conventions

| Namespace | Purpose |
|-----------|---------|
| `anti-analysis/anti-debugging` | Debugger detection |
| `anti-analysis/anti-vm` | VM detection |
| `anti-analysis/anti-av` | AV evasion |
| `collection/keylog` | Keylogging |
| `collection/screenshot` | Screenshot capture |
| `communication/http` | HTTP communication |
| `communication/encrypted` | Encrypted channels |
| `data-manipulation/encryption/aes` | AES encryption |
| `host-interaction/process/inject` | Process injection |
| `host-interaction/registry` | Registry operations |
| `load-code/dotnet` | Dynamic assembly loading |
| `persistence/registry` | Registry persistence |
| `persistence/scheduled-task` | Scheduled task persistence |
| `malware-family/*` | Malware family detection |

---

## Extracted Feature Reference

| Feature | CAPA Matcher | Source | Scope | Example Match |
|---------|-------------|--------|-------|---------------|
| User string | `string:` | #US Heap (ldstr) | file, function | `"http://c2.evil.com"` |
| Type name | `string:` | TypeDef | file | `"System.Net.Sockets.TcpClient"` |
| Method name | `string:`, `function-name:` | MethodDef | file, function | `"DecryptConfig"` |
| API call | `string:`, `api:` | MemberRef | file | `"Process.Start"` |
| P/Invoke | `string:`, `api:` | ImplMap | file | `"VirtualAlloc"`, `"kernel32.VirtualAlloc"` |
| Namespace | `string:` | Types | file | `"System.Security.Cryptography"` |
| IL Mnemonic | `mnemonic:` | IL Disassembly | file, function | `ldstr`, `call`, `newobj` |
| IL Number | `number:` | IL Operands | file, function | `256`, `0x40` |
| Format | `format:` | PE Header | file | `dotnet` |
| Embedded PE | `characteristic:` | Byte scan | file | `embedded pe` |
| PE Import | `import:` | IAT | file | `"mscoree.dll._CorExeMain"` |

### Function-Scope Feature Resolution

For function-scope matching, the following features are tracked per .NET method:

| Feature | How Resolved | Notes |
|---------|--------------|-------|
| Strings | `ldstr` token → #US heap lookup | Token table 0x70 references user string heap |
| Mnemonics | IL instruction decode | All opcodes in method body counted |
| Numbers | IL operand extraction | Immediate values from instructions |
| Function Name | MethodDef table | Method's own name for `function-name:` matching |

**Technical Details:**
- Method bodies are located via RVA from MethodDef table
- Tiny headers (1 byte) and Fat headers (12 bytes) are parsed to find IL code
- `ldstr` tokens use table ID 0x70 with the row being a byte offset into the #US heap
- Each method's features are stored at its RVA address in the functions map
