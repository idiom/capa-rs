# capa-rs Justfile
# Run `just --list` to see available commands

# Use PowerShell on Windows, bash elsewhere
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Default recipe - show help
default:
    @just --list

# ============================================================================
# BUILD COMMANDS
# ============================================================================

# Build capa-rs with default features
build:
    cargo build

# Build capa-rs release
build-release:
    cargo build --release

# Build with .NET analysis (dotscope)
build-dotnet:
    cargo build --features dotnet

# Build release with .NET analysis
build-release-dotnet:
    cargo build --release --features dotnet

# ============================================================================
# TEST COMMANDS
# ============================================================================

# Run all tests
test:
    cargo test

# Run tests with verbose output
test-verbose:
    cargo test -- --nocapture

# Run a specific test
test-one NAME:
    cargo test {{NAME}} -- --nocapture

# ============================================================================
# RUN COMMANDS
# ============================================================================

# Run capa-rs on a file
run FILE:
    cargo run --release -- -r capa-rules {{FILE}}

# Run capa-rs with JSON output
run-json FILE:
    cargo run --release -- -r capa-rules -j {{FILE}}

# Run capa-rs with verbose output
run-verbose FILE:
    cargo run --release -- -r capa-rules -v {{FILE}}

# Run capa-rs on a .NET sample
run-dotnet FILE:
    cargo run --release --features dotnet -- -r capa-rules -f dotnet {{FILE}}

# ============================================================================
# DOCUMENTATION
# ============================================================================

# Generate documentation
doc:
    cargo doc --no-deps

# Generate and open documentation
doc-open:
    cargo doc --no-deps --open

# ============================================================================
# CODE QUALITY
# ============================================================================

# Run clippy linter
lint:
    cargo clippy

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Run all checks (format, lint, test)
check-all: fmt-check lint test

# ============================================================================
# CLEANING
# ============================================================================

# Clean build artifacts
clean:
    cargo clean

# Clean and rebuild
rebuild: clean build

# ============================================================================
# UTILITIES
# ============================================================================

# Show feature flags
features:
    @echo "Available feature flags for capa-rs:"
    @echo ""
    @echo "  default    - x86/x64 analysis via iced-x86 (pure Rust)"
    @echo "  dotnet     - .NET CIL analysis via dotscope (pure Rust)"
    @echo ""
    @echo "Input formats: auto, pe, elf, dotnet, sc32, sc64"

# Show dependency versions
deps:
    cargo tree --depth 1

# Update dependencies
update:
    cargo update
