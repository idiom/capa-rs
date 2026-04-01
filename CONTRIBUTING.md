# Contributing to capa-rs

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/yeti-sec/capa-rs.git
cd capa-rs
cargo build
cargo test --workspace
```

## Development Workflow

1. Fork the repository and create a feature branch.
2. Make your changes and add tests where appropriate.
3. Run the quality gate before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo test --workspace --features dotnet   # if touching .NET code
```

4. Open a pull request against `main` with a clear description of the change and the motivation behind it.

## Code Style

- Follow standard Rust idioms (`rustfmt` enforces formatting).
- Clippy warnings are treated as errors in CI — run `cargo clippy` locally first.
- Error handling: use `thiserror` in library crates, `anyhow` in `capa-cli`.
- No `.unwrap()` outside `#[cfg(test)]` blocks.

## Adding Rules

Rule contributions should go to the upstream [capa-rules](https://github.com/mandiant/capa-rules) repository. If you have capa-rs-specific rules (e.g., additional .NET rules), open a PR adding them to `enhanced-dotnet-rules/`.

## Reporting Issues

Please use [GitHub Issues](https://github.com/yeti-sec/capa-rs/issues) for bug reports and feature requests. Include the capa-rs version, OS, and a minimal reproducer where possible.
