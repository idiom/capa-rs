# Writing CAPA Rules for ELF Binaries

This guide covers how to write YAML-based CAPA rules that detect capabilities in Linux ELF (Executable and Linkable Format) binaries using capa-rs.

## Build Requirements

```bash
cargo build --release -p capa-cli
```

---

## Feature Extraction Overview

When capa-rs processes an ELF binary, it extracts features from multiple sources:

| Source | Feature Type | Description |
|--------|-------------|-------------|
| Dynamic Symbol Table | `api:`, `import:` | Imported library functions |
| Symbol Table | `export:` | Exported symbols |
| Section Headers | `section:` | Section names |
| String Scan | `string:` | ASCII strings (4+ chars) |
| Disassembly | `mnemonic:`, `number:`, `offset:` | Instruction-level features |
| Control Flow | `characteristic:` | Loops, calls, patterns |
| ELF Header | `format:`, `os:`, `arch:` | Binary metadata |

---

## Feature Types and Examples

### 1. Format and OS Constraints

**Constrain rules to Linux ELF binaries:**

```yaml
# Match only ELF files
- format: elf

# Match only Linux binaries
- os: linux

# Architecture constraints
- arch: i386      # 32-bit x86
- arch: amd64     # 64-bit x64
- arch: arm       # 32-bit ARM
- arch: arm64     # 64-bit ARM (AArch64)
- arch: mips      # MIPS
- arch: ppc       # PowerPC 32-bit
- arch: ppc64     # PowerPC 64-bit
```

---

### 2. API Features

API calls resolved from disassembly (calls to PLT/GOT entries).

```yaml
# Standard C library
- api: system
- api: execve
- api: fork
- api: popen

# Network functions
- api: socket
- api: connect
- api: bind
- api: listen
- api: accept
- api: send
- api: recv

# File operations
- api: open
- api: read
- api: write
- api: unlink
- api: chmod

# Memory operations
- api: mmap
- api: mprotect
- api: memcpy
- api: malloc

# Regex patterns
- api: /exec(ve|l|le|lp|v|vp)?$/
- api: /^(send|recv)(msg|from|to)?$/
```

#### Common API Categories

**Process Execution:**
```yaml
- api: system
- api: execve
- api: execl
- api: execle
- api: execlp
- api: execv
- api: execvp
- api: fork
- api: vfork
- api: clone
- api: popen
- api: pclose
```

**Process Control:**
```yaml
- api: kill
- api: ptrace
- api: wait
- api: waitpid
- api: exit
- api: _exit
- api: abort
```

**Memory Operations:**
```yaml
- api: mmap
- api: munmap
- api: mprotect
- api: mremap
- api: brk
- api: sbrk
- api: malloc
- api: calloc
- api: realloc
- api: free
- api: memcpy
- api: memmove
- api: memset
```

**File Operations:**
```yaml
- api: open
- api: openat
- api: creat
- api: close
- api: read
- api: write
- api: lseek
- api: stat
- api: fstat
- api: lstat
- api: unlink
- api: rename
- api: chmod
- api: chown
- api: readdir
- api: opendir
```

**Network Operations:**
```yaml
- api: socket
- api: socketpair
- api: bind
- api: listen
- api: accept
- api: connect
- api: send
- api: sendto
- api: sendmsg
- api: recv
- api: recvfrom
- api: recvmsg
- api: shutdown
- api: gethostbyname
- api: getaddrinfo
- api: inet_addr
- api: inet_ntoa
```

**Cryptography (OpenSSL/libcrypto):**
```yaml
- api: EVP_EncryptInit
- api: EVP_EncryptUpdate
- api: EVP_EncryptFinal
- api: EVP_DecryptInit
- api: AES_encrypt
- api: AES_decrypt
- api: RSA_public_encrypt
- api: RSA_private_decrypt
- api: SHA256_Init
- api: SHA256_Update
- api: SHA256_Final
```

**Dynamic Loading:**
```yaml
- api: dlopen
- api: dlsym
- api: dlclose
- api: dlerror
```

**Anti-Debug:**
```yaml
- api: ptrace
- api: getppid
- api: prctl
```

---

### 3. Import Features

Raw imports from dynamic symbol table.

```yaml
# Library function imports
- import: system
- import: execve
- import: socket

# Library dependencies
- import: libssl.so
- import: libcrypto.so
- import: libpthread.so
```

---

### 4. Export Features

Exported symbols from symbol table.

```yaml
- export: main
- export: init
- export: fini

# Shared library exports
- export: plugin_init
- export: module_entry
```

---

### 5. Section Features

Section names from ELF section headers.

```yaml
# Standard sections
- section: .text
- section: .data
- section: .rodata
- section: .bss
- section: .plt
- section: .got
- section: .got.plt
- section: .dynamic
- section: .symtab
- section: .dynsym

# Packer indicators
- section: .upx
- section: UPX!
```

---

### 6. String Features

ASCII strings extracted from the binary.

```yaml
# Shell commands
- string: "/bin/sh"
- string: "/bin/bash"
- string: "sh -c"
- string: "bash -c"

# Common paths
- string: "/etc/passwd"
- string: "/etc/shadow"
- string: "/proc/self"
- string: "/dev/null"
- string: "/tmp/"

# URLs and network
- string: /https?:\/\/[^\s]+/
- string: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

# Cron persistence
- string: "/etc/crontab"
- string: "/etc/cron.d"
- string: "/var/spool/cron"

# SSH-related
- string: "/.ssh/authorized_keys"
- string: "/.ssh/id_rsa"

# Systemd persistence
- string: "/etc/systemd/system"
- string: ".service"
```

---

### 7. Mnemonic Features

Assembly instruction mnemonics.

```yaml
# System calls (x86/x64)
- mnemonic: syscall    # x64 syscall
- mnemonic: int 0x80   # x86 syscall
- mnemonic: sysenter   # Fast syscall

# CPU detection
- mnemonic: cpuid

# Anti-debug timing
- mnemonic: rdtsc
- mnemonic: rdtscp
```

---

### 8. Number Features

Numeric constants from instruction operands.

```yaml
# Syscall numbers (x64)
- number: 59           # execve
- number: 41           # socket
- number: 42           # connect
- number: 0            # read
- number: 1            # write
- number: 2            # open
- number: 57           # fork
- number: 56           # clone

# Memory protection flags
- number: 0x7          # PROT_READ | PROT_WRITE | PROT_EXEC

# Socket constants
- number: 2            # AF_INET
- number: 1            # SOCK_STREAM
- number: 6            # IPPROTO_TCP

# ptrace constants
- number: 0            # PTRACE_TRACEME
```

---

### 9. Characteristic Features

Code patterns and behaviors.

```yaml
# File scope
- characteristic: embedded pe    # Embedded Windows PE

# Function scope
- characteristic: loop
- characteristic: recursive call
- characteristic: nzxor
- characteristic: cross section flow

# Basic block scope
- characteristic: tight loop
- characteristic: stack string

# Instruction scope
- characteristic: indirect call
```

---

## Complete Rule Examples

### Example 1: Reverse Shell

```yaml
rule:
  meta:
    name: create reverse shell
    namespace: communication/shell
    authors:
      - your-name
    description: >
      Creates a socket connection and redirects stdin/stdout/stderr
      to execute a shell. Classic reverse shell technique.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Execution::Command and Scripting Interpreter::Unix Shell [T1059.004]
    mbc:
      - Communication::Reverse Shell [B0022]
  features:
    - and:
      - format: elf
      - api: socket
      - api: connect
      - or:
        - api: dup2
        - api: dup
      - or:
        - api: execve
        - api: system
      - or:
        - string: "/bin/sh"
        - string: "/bin/bash"
```

### Example 2: Anti-Debug via ptrace

```yaml
rule:
  meta:
    name: detect debugger via ptrace
    namespace: anti-analysis/anti-debugging
    authors:
      - your-name
    description: >
      Uses ptrace(PTRACE_TRACEME) to detect debuggers.
      A process can only be traced once, so this fails under debugger.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Defense Evasion::Debugger Evasion [T1622]
    mbc:
      - Anti-Behavioral Analysis::Debugger Detection [B0001]
  features:
    - and:
      - format: elf
      - api: ptrace
      - or:
        - number: 0    # PTRACE_TRACEME
        - string: "PTRACE_TRACEME"
```

### Example 3: Cron Persistence

```yaml
rule:
  meta:
    name: persist via cron
    namespace: persistence/cron
    authors:
      - your-name
    description: >
      Modifies cron configuration for persistence.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Persistence::Scheduled Task/Job::Cron [T1053.003]
    mbc:
      - Persistence::Scheduled Task [F0003]
  features:
    - and:
      - format: elf
      - or:
        - string: "/etc/crontab"
        - string: "/etc/cron.d"
        - string: "/var/spool/cron"
        - string: "crontab"
      - or:
        - api: open
        - api: fopen
        - api: write
        - api: fwrite
```

### Example 4: SSH Key Theft

```yaml
rule:
  meta:
    name: access SSH keys
    namespace: credential-access/ssh
    authors:
      - your-name
    description: >
      Accesses SSH private keys or authorized_keys file.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Credential Access::Unsecured Credentials::Private Keys [T1552.004]
    mbc:
      - Credential Access::Steal Credentials [E1552]
  features:
    - and:
      - format: elf
      - or:
        - string: "/.ssh/id_rsa"
        - string: "/.ssh/id_dsa"
        - string: "/.ssh/id_ecdsa"
        - string: "/.ssh/id_ed25519"
        - string: "/.ssh/authorized_keys"
```

### Example 5: Memory-Only Execution

```yaml
rule:
  meta:
    name: execute code from memory
    namespace: defense-evasion/memexec
    authors:
      - your-name
    description: >
      Uses mmap/mprotect to create executable memory and execute code
      without touching disk. Common in fileless malware.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Defense Evasion::Reflective Code Loading [T1620]
    mbc:
      - Defense Evasion::Fileless Execution [B0037]
  features:
    - and:
      - format: elf
      - or:
        - api: mmap
        - api: mmap64
      - or:
        - api: mprotect
        - number: 0x7    # PROT_READ|WRITE|EXEC
```

### Example 6: Credential Harvesting

```yaml
rule:
  meta:
    name: read password file
    namespace: credential-access/files
    authors:
      - your-name
    description: >
      Reads /etc/passwd or /etc/shadow for credential harvesting.
    scopes:
      static: file
      dynamic: file
    att&ck:
      - Credential Access::Unsecured Credentials::Credentials in Files [T1552.001]
    mbc:
      - Credential Access::Steal Credentials [E1552]
  features:
    - and:
      - format: elf
      - or:
        - string: "/etc/passwd"
        - string: "/etc/shadow"
      - or:
        - api: open
        - api: fopen
        - api: read
        - api: fread
```

### Example 7: Process Injection via ptrace

```yaml
rule:
  meta:
    name: inject code via ptrace
    namespace: host-interaction/process/inject
    authors:
      - your-name
    description: >
      Uses ptrace to inject code into another process.
    scopes:
      static: function
      dynamic: process
    att&ck:
      - Defense Evasion::Process Injection::Ptrace System Calls [T1055.008]
    mbc:
      - Process::Inject Code [E1055]
  features:
    - and:
      - format: elf
      - api: ptrace
      - or:
        - number: 4     # PTRACE_POKETEXT
        - number: 5     # PTRACE_POKEDATA
        - number: 6     # PTRACE_POKEUSER
        - string: "PTRACE_POKE"
```

---

## Syscall-Based Detection

For statically linked binaries or direct syscall usage:

```yaml
rule:
  meta:
    name: execute via direct syscall
    namespace: execution/syscall
    authors:
      - your-name
    description: >
      Uses direct syscall instruction for execution,
      bypassing library function hooks.
    scopes:
      static: basic block
      dynamic: thread
  features:
    - and:
      - format: elf
      - or:
        - mnemonic: syscall
        - mnemonic: int 0x80
      - or:
        - number: 59    # execve (x64)
        - number: 11    # execve (x86)
```

---

## Testing Rules

### 1. Extract Features for Debugging

```bash
# Dump features to JSON
capa-rs --dump-features features.json --extract-only sample

# Check feature counts
jq '.file | {apis: .apis | length, strings: .strings | length}' features.json

# Search for specific APIs
jq '.file.apis[]' features.json | grep -i "exec"
```

### 2. Test Rules Against Sample

```bash
# Test single rule
capa-rs -r path/to/rule.yml sample

# Test rule directory
capa-rs -r path/to/rules/ sample

# Verbose output
capa-rs -v -r path/to/rules/ sample
```

---

## Best Practices

### 1. Constrain by Format
```yaml
- format: elf
```

### 2. Use Multiple Indicators
```yaml
# Good: Multiple related APIs
- and:
  - api: socket
  - api: connect
  - api: execve

# Avoid: Single common API
- api: read    # Too generic
```

### 3. Consider Library Variants
```yaml
# File operations have multiple interfaces
- or:
  - api: open
  - api: fopen
  - api: openat
```

### 4. Use Regex for Patterns
```yaml
- api: /exec(ve|l|le|lp|v|vp)?$/
- api: /^f?(read|write)$/
```

### 5. Consider Syscall Numbers
For stripped/statically linked binaries:
```yaml
- and:
  - mnemonic: syscall
  - number: 59    # execve syscall number
```

---

## Namespace Conventions

| Namespace | Purpose |
|-----------|---------|
| `anti-analysis/anti-debugging` | Debugger detection |
| `communication/shell` | Shell/backdoor communication |
| `credential-access/files` | Credential file access |
| `credential-access/ssh` | SSH key access |
| `defense-evasion/memexec` | Memory-only execution |
| `execution/syscall` | Direct syscall usage |
| `host-interaction/process/inject` | Process injection |
| `persistence/cron` | Cron persistence |
| `persistence/systemd` | Systemd persistence |
| `persistence/init` | Init script persistence |

---

## Extracted Feature Reference

| Feature | CAPA Matcher | Source | Example |
|---------|-------------|--------|---------|
| API call | `api:` | Disasm + PLT/GOT | `execve` |
| Import | `import:` | .dynsym | `socket` |
| Export | `export:` | .symtab | `main` |
| Section | `section:` | Section headers | `.text` |
| String | `string:` | String scan | `"/bin/sh"` |
| Mnemonic | `mnemonic:` | Disassembly | `syscall` |
| Number | `number:` | Operands | `59` |
| Characteristic | `characteristic:` | Analysis | `nzxor` |
| Format | `format:` | ELF header | `elf` |
| OS | `os:` | ELF header | `linux` |
| Arch | `arch:` | ELF header | `amd64` |

---

## Common Syscall Numbers (x86_64)

| Syscall | Number | Purpose |
|---------|--------|---------|
| read | 0 | Read from file descriptor |
| write | 1 | Write to file descriptor |
| open | 2 | Open file |
| close | 3 | Close file descriptor |
| stat | 4 | Get file status |
| mmap | 9 | Map memory |
| mprotect | 10 | Set memory protection |
| brk | 12 | Change data segment size |
| socket | 41 | Create socket |
| connect | 42 | Connect socket |
| accept | 43 | Accept connection |
| sendto | 44 | Send message |
| recvfrom | 45 | Receive message |
| bind | 49 | Bind socket |
| listen | 50 | Listen on socket |
| clone | 56 | Create child process |
| fork | 57 | Create child process |
| execve | 59 | Execute program |
| exit | 60 | Terminate process |
| kill | 62 | Send signal |
| ptrace | 101 | Process trace |
