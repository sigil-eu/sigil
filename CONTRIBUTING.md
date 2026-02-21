# Contributing to SIGIL

Thank you for your interest in contributing to the SIGIL protocol!

## Ways to Contribute

### 🔧 Rust Crate

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Ensure all checks pass:

   ```bash
   cargo fmt --all
   cargo clippy --all-features -- -D warnings
   cargo test --all-features
   ```

4. Submit a pull request with a clear description

### 📝 Specification

- Open an issue to propose changes to the spec
- Submit PRs against `spec/` documents with clear rationale
- Reference real-world use cases or security concerns

### 🌍 Language SDKs

We welcome SIGIL implementations in other languages:

- **Python** (`sigil-py`) — Protocol classes for LangChain, LlamaIndex, etc.
- **TypeScript** (`sigil-js`) — Interfaces for Node.js MCP servers
- **Go** (`sigil-go`) — For cloud-native agent systems

If you're building an SDK, open an issue first so we can coordinate.

### 🐛 Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, please email <security@mymolt.org>

## Development

```bash
# Run all tests
cargo test --all-features

# Run the example
cargo run --example basic_mcp_server

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-features -- -D warnings

# Build docs
cargo doc --no-deps --open
```

## Code of Conduct

Be respectful, inclusive, and constructive. We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
