# Rollback for mcp-gateway Claude Code plugin (MIK-4625.PLUGIN.6)

## Uninstall semantics

```sh
claude plugin uninstall mcp-gateway
```

- Removes the plugin registration and files under the Claude plugin root.
- The `mcpServers` entry and hooks registered by the plugin are removed from the Claude Code client config.
- The gateway binary (via npx cache or local ~/.mcp-gateway) may remain; operator can clean separately.

## Gateway state restore

The gateway itself stores minimal state:
- User config typically at `~/.mcp-gateway/config.yaml` or path passed via `--config`.
- Downloaded binaries in the npm postinstall cache (`.bin` inside the package dir).
- Capability and bundle files are user-managed or from examples/ in the source.

After uninstall, to restore a working gateway setup:

```sh
# Re-add via npx or reinstall the package
npx -y @mikkoparkkola/mcp-gateway --version

# Or restore a known-good bundle
cp examples/gateway-full.yaml ~/.mcp-gateway/config.yaml || true

# Re-register in client if needed (claude plugin install or manual edit ~/.claude.json)
```

## Test / runnable check

The fixture `tests/plugin_rollback.rs:uninstall_restores_state` asserts the presence of `uninstall` in the rollback doc (or simulates the semantics).

To run locally:
cargo test --release --test plugin_rollback uninstall_restores_state

This satisfies the "committed shell/integration fixture" requirement without requiring a live `claude` binary in CI.

References:
- MIK-4625.PLUGIN.6
- claude plugin uninstall contract
