# Dagger Rust SDK for SBOM Tools

This module provides a Rust SDK entrypoint for Dagger-based CI/CD activities focused on the Go/Swift bindings MVP.

Supported commands:

- `build-staticlib`: build debug static library artifact
- `release-staticlib`: build release static library artifact
- `test-abi`: run ABI contract tests
- `ci-all`: run the full MVP CI bundle (default)

Usage:

```sh
cargo run --manifest-path dagger/rust-sdk/Cargo.toml -- ci-all
```