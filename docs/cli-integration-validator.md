# CLI Integration Guide for Agent-UX Validator

## Overview

The Agent-UX Validator (`src/validator/`) is complete and ready for CLI integration. This document describes the CLI commands that should be added after the Auto-Discovery feature (#45) is complete.

## Integration Point

**File**: `src/cli.rs`

**Module**: Already exposed in `src/lib.rs` as `pub mod validator`

## Proposed CLI Commands

### Option 1: New `validate` subcommand

```rust
#[derive(Debug, clap::Subcommand)]
pub enum Commands {
    // ... existing commands ...

    /// Validate MCP tools against agent-UX design best practices
    Validate {
        /// Path to capability YAML file or directory
        #[arg(short, long)]
        path: Option<String>,

        /// Server name (validate live server via tools/list)
        #[arg(short, long)]
        server: Option<String>,

        /// Output format: text, json, yaml
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Show only failures and warnings
        #[arg(long)]
        only_issues: bool,
    },
}
```

### Option 2: Extend `cap` subcommand

```rust
#[derive(Debug, clap::Subcommand)]
pub enum CapCommands {
    // ... existing cap commands ...

    /// Lint/validate capability definitions
    Lint {
        /// Path to capability YAML file or directory
        path: String,

        /// Output format: text, json, yaml
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Show only failures and warnings
        #[arg(long)]
        only_issues: bool,
    },
}
```

## Implementation

### 1. Add validator handler function

```rust
use mcp_gateway::validator::{AgentUxValidator, ValidationReport};
use mcp_gateway::capability::{CapabilityLoader, CapabilityDefinition};
use mcp_gateway::protocol::Tool;

async fn handle_validate(
    path: Option<String>,
    server: Option<String>,
    format: String,
    only_issues: bool,
) -> Result<()> {
    let validator = AgentUxValidator::new();

    let tools: Vec<Tool> = if let Some(path) = path {
        // Load from YAML files
        let capabilities = if std::path::Path::new(&path).is_dir() {
            CapabilityLoader::load_directory(&path).await?
        } else {
            vec![parse_capability_file(std::path::Path::new(&path)).await?]
        };

        capabilities.iter().map(|cap| cap.to_mcp_tool()).collect()
    } else if let Some(server_name) = server {
        // Connect to live server and call tools/list
        // TODO: Implement after Auto-Discovery integration
        unimplemented!("Live server validation requires Auto-Discovery (#45)")
    } else {
        return Err(Error::Config("Either --path or --server must be specified".to_string()));
    };

    let report = validator.validate_tools(&tools)?;

    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(&report)?);
        }
        _ => {
            println!("{}", report.format_text());
        }
    }

    // Exit with non-zero if there are failures
    std::process::exit(if report.summary.failed > 0 { 1 } else { 0 });
}
```

### 2. Wire into main CLI handler

```rust
match cli.command {
    Commands::Validate { path, server, format, only_issues } => {
        handle_validate(path, server, format, only_issues).await?;
    }
    // ... other commands ...
}
```

## Usage Examples

```bash
# Validate a single capability file
mcp-gateway validate --path capabilities/search/brave_search.yaml

# Validate all capabilities in a directory
mcp-gateway validate --path capabilities/

# Get JSON output for CI/CD integration
mcp-gateway validate --path capabilities/ --format json

# Show only issues (failures and warnings)
mcp-gateway validate --path capabilities/ --only-issues

# Validate a live MCP server (after #45)
mcp-gateway validate --server fulcrum

# Alternative: using cap subcommand
mcp-gateway cap lint capabilities/
```

## Integration Tests

Add integration tests in `tests/validator_cli_tests.rs`:

```rust
#[tokio::test]
async fn test_validate_good_capability() {
    // Test that well-designed capabilities pass validation
}

#[tokio::test]
async fn test_validate_bad_capability() {
    // Test that poorly-designed capabilities fail validation
}

#[tokio::test]
async fn test_validate_directory() {
    // Test validating multiple capabilities at once
}

#[tokio::test]
async fn test_validate_json_output() {
    // Test JSON output format
}
```

## Documentation Updates

Update `README.md` to include:

1. New "Tool Validation" section
2. Examples of running the validator
3. Explanation of the 6 design principles
4. Link to Phil Schmid's article: https://www.philschmid.de/mcp-best-practices

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
- name: Validate MCP Capabilities
  run: |
    mcp-gateway validate --path capabilities/ --format json > validation_report.json
    cat validation_report.json

    # Fail if validation score is below 80%
    SCORE=$(jq -r '.overall_score' validation_report.json)
    if (( $(echo "$SCORE < 0.8" | bc -l) )); then
      echo "Validation failed: score $SCORE < 0.8"
      exit 1
    fi
```

## Dependencies

The validator module is self-contained and has no external dependencies beyond what's already in `Cargo.toml`.

## Related Issues

- #36 - MCP Server Design Validator - Agent-UX Compliance (this feature)
- #45 - Auto-Discovery for Local MCP Servers (needed for `--server` option)

## Testing

All unit tests pass:

```bash
cargo test --lib validator
# Result: 17 passed; 0 failed
```

Run the example:

```bash
cargo run --example validator_demo
```
