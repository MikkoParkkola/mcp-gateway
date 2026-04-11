# MCP Gateway Built-in Capabilities

This branch currently ships **72 built-in capability YAMLs** under `capabilities/`, excluding `capabilities/examples/`.

## Current category inventory

| Category | Count |
|----------|-------|
| **automation/** | 1 |
| **communication/** | 2 |
| **developer/** | 1 |
| **entertainment/** | 4 |
| **finance/** | 6 |
| **food/** | 1 |
| **infrastructure/** | 1 |
| **knowledge/** | 7 |
| **linear/** | 13 |
| **media/** | 4 |
| **productivity/** | 25 |
| **security/** | 2 |
| **utility/** | 3 |
| **verification/** | 2 |

## Working with the registry

```bash
# List built-in capabilities
mcp-gateway cap registry-list

# Search the built-in registry
mcp-gateway cap search github

# Install a capability from GitHub
mcp-gateway cap install stock_quote --from-github
```

## Notes

`capabilities/examples/` contains starter examples and templates, not the built-in capability inventory counted above.
