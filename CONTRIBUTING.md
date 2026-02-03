# Contributing to MCP Gateway

Thank you for your interest in contributing to MCP Gateway!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/mcp-gateway`
3. Create a feature branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
# Install Rust (1.85+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Run tests
cargo test

# Run with example config
cargo run -- --config examples/servers.yaml
```

## Code Standards

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- Add tests for new functionality
- Update documentation for API changes

## Pull Request Process

1. Ensure CI passes (fmt, clippy, test, build)
2. Update README.md if adding features
3. Add entry to CHANGELOG.md
4. Request review

## Architecture Overview

```
src/
├── backend/       # Backend process management
├── config.rs      # Configuration parsing
├── failsafe/      # Circuit breaker, retry, rate limiting
├── gateway/       # Core gateway logic + Meta-MCP
├── protocol/      # MCP message types
└── transport/     # stdio, HTTP, SSE transports
```

## Adding a New Backend Transport

1. Implement `Transport` trait in `src/transport/`
2. Add configuration variant in `src/config.rs`
3. Register in `src/backend/mod.rs`
4. Add tests in `tests/`

## Adding a Failsafe

1. Add module in `src/failsafe/`
2. Integrate with `BackendManager`
3. Add configuration options
4. Document in README.md

## Adding Capabilities

The easiest way to contribute is adding new API capabilities:

1. Copy an existing YAML from `capabilities/`
2. Modify for your API
3. Test it works
4. Submit PR

### Zero-Config Capabilities Welcome

APIs that work without authentication are especially valuable. Good candidates:
- Government open data
- Public datasets
- Free utility APIs

### Capability Guidelines

- Keep YAML clean and readable
- Include realistic examples
- Document rate limits
- Add appropriate tags

## Questions?

Open an issue for discussion before large changes.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
