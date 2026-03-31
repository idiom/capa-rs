# capa-rs Benchmark Commands

Quick benchmarking of capa-rs vs Python capa using the built-in `just` commands.

## Prerequisites

- capa-rs compiled in release mode: `just build-release`
- Python capa installed: `pip install flare-capa`
- IDA Pro 9.2 (for IDA backend benchmarks)
- `just` command runner installed

## Quick Start

```bash
# Compare IDA backends (6-7 seconds)
just bench-ida test_samples/floss_conti

# Compare fast backends (52+ seconds - vivisect is slow)
just bench-fast test_samples/floss_conti

# Run complete benchmark suite (90 seconds total)
just bench-all test_samples/floss_conti
```

## Benchmark Commands

### `bench-ida [SAMPLE]`

Compare capa-rs IDA backend vs Python capa IDA backend.

**What it does:**
1. Cleans up any IDA temporary files from previous runs
2. Runs Python capa with `-b ida` on the sample
3. Cleans up IDA temporary files again
4. Runs capa-rs with `--backend ida` on the sample
5. Reports timing and rule match counts

**Expected results:**
- Python capa + IDA: ~16 seconds, 10 rules
- capa-rs + IDA: ~6.7 seconds, 20 rules
- **Speedup: 2.4x faster**, detects 2x more rules

**Example:**
```bash
just bench-ida test_samples/floss_conti
```

### `bench-fast [SAMPLE]`

Compare capa-rs goblin backend vs Python capa vivisect backend.

**What it does:**
1. Runs Python capa with `-b vivisect` on the sample
2. Runs capa-rs with default goblin backend
3. Reports timing and rule match counts

**Expected results:**
- Python capa + vivisect: ~52 seconds, ~9 rules
- capa-rs + goblin: ~0.8 seconds, 18 rules
- **Speedup: 65x faster**, detects 2x more rules

**Note:** vivisect is significantly slower than IDA due to comprehensive flow analysis. This benchmark shows capa-rs's speed advantage even without IDA.

**Example:**
```bash
just bench-fast test_samples/floss_conti
```

### `bench-all [SAMPLE]`

Run complete benchmark suite comparing all 4 backends.

**What it does:**
1. Runs `bench-fast` (52+ seconds for vivisect)
2. Runs `bench-ida` (6-7 seconds)
3. Prints summary table with all 4 tools

**Total time:** ~90 seconds

**Expected output:**
```
Tool                      | Time    | Rules | vs goblin
========================+=========+=======+==========
capa-rs + goblin         | 0.80s   |  18   | 1.0x
capa-rs + IDA            | 6.74s   |  20   | 8.4x
capa (IDA)               | 16.06s  |  10   | 20x
capa (vivisect)          | 51.86s  |  ~9   | 65x

Key Findings:
  ✓ capa-rs + goblin:   65x faster than vivisect
  ✓ capa-rs + IDA:      2.4x faster than Python IDA
  ✓ capa-rs (IDA):      Detects 20 rules vs Python's 10
```

**Example:**
```bash
just bench-all test_samples/floss_conti
```

## Custom Sample

All benchmark commands accept a custom sample path:

```bash
just bench-ida my_sample.exe
just bench-fast another_binary.bin
just bench-all /path/to/malware.bin
```

## Understanding the Results

### Rule Counts

**Why capa-rs detects more rules:**

1. **Operand-indexed offsets**: capa-rs extracts offsets from specific operand positions (e.g., `operand[1].offset`), enabling rules like "enumerate PE sections" that Python capa misses

2. **Segment register fix**: Corrected IDA SDK register ID mapping (R_fs=33, R_gs=34) enables proper PEB access detection

3. **Architecture awareness**: 32-bit binaries generate `esp`/`ebp` names (not `rsp`/`rbp`), fixing stack detection

4. **BB-scope stack strings**: Stack string detection at basic-block scope vs function-only scope

5. **More comprehensive function analysis**: IDA backend analyzes 334 functions in test sample vs ~160-170 for other methods

### Performance Factors

**Why capa-rs is faster:**

1. **FFI optimization**: 1 FFI call per instruction (mnemonic only) vs 7 (Python capa with `print_operand()`)

2. **Pure Rust operand formatting**: From `op_t` POD fields, zero copies

3. **Zero-allocation fast path**: No intermediate string allocations in hot path

4. **Rust compilation**: Release mode optimizations (LTO, codegen-units=1)

**Why vivisect is slow:**

1. Comprehensive function/block/instruction analysis
2. Python interpreter overhead
3. Full CFG reconstruction and instruction emulation
4. No binary caching between runs

## Troubleshooting

### "ModuleNotFoundError: No module named 'capa'"

Make sure Python capa is installed:
```bash
pip install flare-capa
```

### "IDA initialization failed"

Make sure:
1. IDA Pro 9.2 is installed at `C:\Program Files\IDA Professional 9.2`
2. Environment variable `IDADIR` is set correctly
3. idalib-rs is properly built with `cargo build --release --features ida-backend`

### "command not found: just"

Install `just` command runner:
```bash
cargo install just
```

Or use `cargo install --path /path/to/just`

### IDB files not cleaning up

If temporary `.id0`, `.id1`, `.id2`, `.nam`, `.til`, `.idb` files persist, delete them manually:
```bash
rm test_samples/floss_conti.id*
rm test_samples/floss_conti.nam
rm test_samples/floss_conti.til
```

## Detailed Results

See `BENCHMARK_REPORT.md` for:
- Comprehensive performance analysis
- Rule-by-rule comparison
- Technical improvements in capa-rs
- JSON output from each benchmark
- Feature extraction metrics

## Using Benchmarks in CI/CD

For automated performance tracking:

```bash
#!/bin/bash
# Run benchmarks and save results
just bench-ida test_samples/floss_conti > results.txt
just bench-fast test_samples/floss_conti >> results.txt

# Parse timing results
echo "Performance: $(grep 'Speedup:' results.txt | head -1)"
```

## Next Steps

After running benchmarks:

1. **Review detailed report**: `cat BENCHMARK_REPORT.md`
2. **Analyze rule differences**: Compare matched rules between tools
3. **Profile specific rules**: Use `-v` (verbose) flag for detailed match info:
   ```bash
   just run-verbose test_samples/floss_conti
   cargo run --release -- --backend ida -r capa-rules -v test_samples/floss_conti
   ```
4. **Benchmark other samples**: Replace `test_samples/floss_conti` with any other binary
