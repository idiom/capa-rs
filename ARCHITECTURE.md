# Vivisect-rs Architecture

This document describes the architecture of vivisect-rs, a Rust library for static binary analysis.

## High-Level Architecture

```mermaid
graph TB
    subgraph Input["Input Layer"]
        PE[PE Parser]
        ELF[ELF Parser]
        MACH[Mach-O Parser]
        SREC[S-Record Parser]
    end

    subgraph Core["Core Analysis"]
        WS[VivWorkspace]
        MEM[Memory Manager]
        LOC[Location Manager]
    end

    subgraph Disasm["Disassembly Layer"]
        ICED[iced-x86<br/>x86/x64]
        CAP[capstone-rs<br/>ARM/PPC/MIPS]
    end

    subgraph Analysis["Analysis Passes"]
        CFG[CFG Builder]
        CG[Call Graph]
        SW[Switch Analyzer]
        NR[NoReturn Analyzer]
        TH[Thunk Analyzer]
    end

    subgraph Advanced["Advanced Analysis"]
        UNI[Unicorn Emulator]
        ICE[Icicle Emulator]
        SYM[Symbolic Engine<br/>Z3]
    end

    subgraph Output["Output"]
        FUNC[Functions]
        XREF[Cross-References]
        GRAPH[Call Graph]
        EMU[Emulation Results]
    end

    PE --> WS
    ELF --> WS
    MACH --> WS
    SREC --> WS

    WS --> MEM
    WS --> LOC
    MEM --> ICED
    MEM --> CAP

    ICED --> CFG
    CAP --> CFG

    CFG --> CG
    CFG --> SW
    CFG --> NR
    CFG --> TH

    MEM --> UNI
    MEM --> ICE
    CFG --> SYM

    CG --> GRAPH
    CFG --> FUNC
    CFG --> XREF
    UNI --> EMU
    ICE --> EMU
    SYM --> EMU
```

## Component Overview

### Input Layer

The input layer handles parsing of various binary formats:

```mermaid
graph LR
    subgraph Formats["Binary Formats"]
        FILE[Binary File]
        FILE --> DETECT{Format Detection}
        DETECT -->|MZ Header| PE[PE Parser]
        DETECT -->|ELF Magic| ELF[ELF Parser]
        DETECT -->|Mach-O Magic| MACH[Mach-O Parser]
        DETECT -->|S0 Record| SREC[S-Record Parser]
    end

    PE --> SEGMENTS[Memory Segments]
    ELF --> SEGMENTS
    MACH --> SEGMENTS
    SREC --> SEGMENTS
```

| Parser | Module | Formats |
|--------|--------|---------|
| PE | `src/pe/` | `.exe`, `.dll`, `.sys` |
| ELF | `src/elf/` | Linux executables, `.so` |
| Mach-O | `src/mach/` | macOS executables, `.dylib` |
| S-Record | `src/srec_parser.rs` | Motorola SREC firmware |

### Disassembly Layer

Architecture-specific disassembly is handled by two backends:

```mermaid
graph TB
    subgraph Disassemblers["Disassembly Backends"]
        BYTES[Raw Bytes]

        subgraph ICED["iced-x86 (Default)"]
            X86[x86 32-bit]
            X64[x86-64]
        end

        subgraph CAPSTONE["capstone-rs (Optional)"]
            ARM32[ARM 32-bit]
            THUMB[ARM Thumb]
            ARM64[ARM64/AArch64]
            PPC32[PowerPC 32]
            PPC64[PowerPC 64]
            MIPS[MIPS]
        end

        BYTES --> ICED
        BYTES --> CAPSTONE
    end

    ICED --> OPCODE[OpCode Struct]
    CAPSTONE --> OPCODE
```

### Analysis Pipeline

```mermaid
sequenceDiagram
    participant User
    participant Workspace
    participant Memory
    participant Disasm
    participant Analyzer

    User->>Workspace: load_from_file()
    Workspace->>Memory: Map segments
    User->>Workspace: analyze()

    loop For each entry point
        Workspace->>Disasm: disassemble(va)
        Disasm-->>Workspace: OpCode
        Workspace->>Workspace: Build CFG
    end

    Workspace->>Analyzer: SwitchCaseAnalyzer
    Analyzer-->>Workspace: Jump tables

    Workspace->>Analyzer: NoReturnAnalyzer
    Analyzer-->>Workspace: Non-returning functions

    Workspace->>Analyzer: ThunkAnalyzer
    Analyzer-->>Workspace: Import thunks

    Workspace-->>User: Analysis complete
```

### Call Graph Structure

```mermaid
graph TB
    subgraph CallGraph["Call Graph (petgraph)"]
        MAIN[main<br/>0x401000]
        INIT[_init<br/>0x400800]
        PARSE[parse_args<br/>0x401100]
        PROC[process<br/>0x401200]
        EXIT[exit<br/>0x400600]

        INIT --> MAIN
        MAIN --> PARSE
        MAIN --> PROC
        PROC --> EXIT
        PARSE --> EXIT
    end
```

The call graph is built using `petgraph::DiGraph`:

```rust
pub struct CallGraph {
    graph: DiGraph<i32, ()>,      // Node = function VA
    va_to_node: HashMap<i32, NodeIndex>,
    node_to_va: HashMap<NodeIndex, i32>,
}
```

## Memory Model

```mermaid
graph TB
    subgraph VirtualMemory["Virtual Address Space"]
        subgraph Text[".text (RX)"]
            CODE[Executable Code]
        end

        subgraph Data[".data (RW)"]
            GLOBALS[Global Variables]
        end

        subgraph Rodata[".rodata (R)"]
            STRINGS[String Literals]
        end

        subgraph Import[".idata"]
            IAT[Import Address Table]
        end
    end

    subgraph MemoryManager["Memory Manager"]
        READ[read_memory]
        WRITE[write_memory]
        PROBE[probe_memory]
    end

    CODE --> READ
    GLOBALS --> READ
    GLOBALS --> WRITE
    STRINGS --> READ
```

## Emulation Architecture

```mermaid
graph TB
    subgraph Emulation["Icicle Emulator (Pure Rust)"]
        SLEIGH[SLEIGH Specs]

        subgraph Architectures["Supported Architectures"]
            IC_X86[x86/x64]
            IC_ARM[ARM/ARM64]
            IC_MIPS[MIPS]
            IC_PPC[PowerPC]
            IC_RISCV[RISC-V]
            IC_MSP[MSP430]
        end

        SLEIGH --> Architectures
    end

    MEM[Memory State] --> Emulation
    Emulation --> RESULT[Emulation Result]
```

| Engine | Type | License | Architectures |
|--------|------|---------|---------------|
| Icicle | Pure Rust | MIT | x86, ARM, MIPS, PowerPC, RISC-V, MSP430 |

## Symbolic Execution

```mermaid
graph LR
    subgraph Symbolic["Symbolic Engine (Z3)"]
        EXPR[Symbolic Expression]
        CONST[Constraints]
        SOLVE[SAT Solver]

        EXPR --> CONST
        CONST --> SOLVE
        SOLVE --> SAT{Satisfiable?}
        SAT -->|Yes| MODEL[Concrete Values]
        SAT -->|No| UNSAT[Unsatisfiable]
    end
```

## Feature Flag Dependencies

```mermaid
graph TB
    subgraph Features["Feature Flags"]
        DEFAULT[default]
        MULTI[multi_arch]
        FULL[full_analysis]

        DEFAULT --> STD[std]
        DEFAULT --> ELF32[elf32]
        DEFAULT --> ELF64[elf64]
        DEFAULT --> PE32[pe32]
        DEFAULT --> PE64[pe64]
        DEFAULT --> MACH32[mach32]
        DEFAULT --> MACH64[mach64]

        MULTI --> ARM[arch_arm]
        MULTI --> ARM64[arch_arm64]
        MULTI --> PPC[arch_ppc]
        MULTI --> CALLGRAPH[callgraph]

        ARM --> CAPSTONE[capstone]
        ARM64 --> CAPSTONE
        PPC --> CAPSTONE

        CALLGRAPH --> PETGRAPH[petgraph]

        FULL --> MULTI
        FULL --> UNICORN[unicorn_emu]
        FULL --> SREC[srec_format]

        UNICORN --> UNICORN_ENGINE[unicorn-engine]
        SREC --> SREC_CRATE[srec]
    end
```

## Module Structure

```
src/
├── lib.rs                 # Library entry point, Object enum
├── workspace.rs           # VivWorkspace - main analysis container
├── analysis.rs            # Analysis passes
├── emulator.rs            # OpCode, Operand types
├── memory.rs              # Memory trait and implementations
├── constants.rs           # Architecture and flag constants
├── codegraph.rs           # Call graph (petgraph-based)
├── srec_parser.rs         # S-Record file parser
├── icicle_emu.rs          # Pure Rust CPU emulation (icicle)
├── symboliks.rs           # Symbolic execution (Z3)
│
├── pe/                    # PE format parsing
│   ├── mod.rs
│   ├── header.rs
│   ├── optional_header.rs
│   ├── section_table.rs
│   ├── export.rs
│   └── exception.rs
│
├── elf/                   # ELF format parsing
│   ├── mod.rs
│   ├── header.rs
│   ├── program_header.rs
│   ├── section_header.rs
│   ├── sym.rs
│   ├── dynamic.rs
│   └── note.rs
│
├── mach/                  # Mach-O format parsing
│   ├── mod.rs
│   ├── header.rs
│   ├── constants.rs
│   ├── exports.rs
│   └── imports.rs
│
└── envi/                  # Architecture modules
    └── archs/
        ├── mod.rs
        ├── i386/          # x86 32-bit (iced-x86)
        ├── amd64/         # x86-64 (iced-x86)
        ├── arm/           # ARM/Thumb/ARM64 (capstone)
        └── ppc/           # PowerPC 32/64 (capstone)
```

## Data Flow

```mermaid
flowchart LR
    subgraph Input
        BIN[Binary File]
    end

    subgraph Parse
        FMT[Format Parser]
    end

    subgraph Load
        SEG[Segments]
        SYM[Symbols]
        IMP[Imports]
    end

    subgraph Analyze
        DIS[Disassembly]
        CFG[CFG]
        CG[Call Graph]
    end

    subgraph Query
        FUNC[Functions]
        XREF[XRefs]
        STR[Strings]
    end

    BIN --> FMT
    FMT --> SEG
    FMT --> SYM
    FMT --> IMP

    SEG --> DIS
    SYM --> DIS
    IMP --> DIS

    DIS --> CFG
    CFG --> CG

    CFG --> FUNC
    CFG --> XREF
    SEG --> STR
```
