# RFC-0070: Universal MCP Config Generator

**Status**: Draft
**Authors**: Mikko Parkkola
**Created**: 2026-03-13
**Target**: mcp-gateway v2.6.0
**LOC Budget**: 300-500 LOC
**Feature Gate**: `#[cfg(feature = "config-export")]` (default-enabled)

---

## 1. Problem Statement

Every AI client that supports MCP uses a different JSON config file format and
path to define MCP server connections. A developer using 3-5 AI clients (Claude
Code, Claude Desktop, Cursor, VS Code Copilot, Windsurf, Zed, Cline) must
maintain near-identical configurations in 3-5 separate files.

**Impact**: Adding a single backend to the gateway requires manually updating
every client config. Removing one requires the same. This is the #2 industry
pain point ("MCP Config Sprawl") per the March 2026 awesome-mcp-gateways
survey.

**Current state**: `mcp-gateway setup --configure-client` (src/commands/setup.rs)
already writes gateway entries into detected client configs. But it is a
one-shot wizard, not a continuous export mechanism. It writes a single `url`
entry, not the full client-native format for stdio mode.

**What nobody does**: No MCP gateway, proxy, or server provides a single
command that generates ALL client configs from a single source of truth.
No tool supports bidirectional sync (import AND export). We created
`mcp-gateway setup` for import; this RFC adds the export direction,
completing the circle.

---

## 2. Architecture

### 2.1 Data Flow

```
                            gateway.yaml
                                |
                          Config::load()
                                |
                    +-----------+-----------+
                    |     ConfigExporter    |
                    |  (src/commands/       |
                    |   config_export.rs)   |
                    +-----------+-----------+
                                |
            +-------------------+-------------------+
            |         |         |         |         |
        Claude     Claude    Cursor   VS Code   Windsurf
        Code       Desktop            Copilot
         |           |         |         |         |
    ~/.claude.  ~/Library/  .cursor/  .vscode/  ~/.codeium/
    json        Application  mcp.json  mcp.json  windsurf/
                Support/                         mcp_config
                Claude/...                       .json
```

### 2.2 Connection Modes

The gateway supports two connection modes for clients:

```
MODE 1: Proxy (HTTP)                    MODE 2: Stdio (subprocess)
+--------+    HTTP POST     +-------+  +--------+  stdin/stdout  +-------+
| Client | ──────────────-> |Gateway|  | Client | ───────────--> |Gateway|
+--------+ :39400/mcp       +-------+  +--------+ mcp-gateway    +-------+
                                                   serve --stdio
Config:                                 Config:
{ "url": "http://host:port/mcp" }      { "command": "mcp-gateway",
                                          "args": ["serve", "--stdio"] }
```

**Auto-detection logic**:
- Try connecting to `http://host:port/health` — if a daemon responds: proxy mode
- Else if the gateway binary is on PATH: stdio mode (simpler, no daemon needed)
- Else: proxy mode (fallback, user must ensure daemon is started)
- `--mode proxy|stdio` overrides auto-detection

### 2.3 Client Config Formats

Each client has a distinct JSON structure. The exporter maps the gateway's
single config into each format.

```
+----------+---------------------------+-------------------------------------------+
| Client   | Config Path               | Structure                                 |
+----------+---------------------------+-------------------------------------------+
| Claude   | ~/.claude.json            | {"mcpServers":                            |
| Code     | (or `claude mcp add`)     |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| Claude   | ~/Library/Application     | {"mcpServers":                            |
| Desktop  | Support/Claude/           |   {"gw": {"command":"...","args":[...]}}}  |
|          | claude_desktop_config.json|                                           |
+----------+---------------------------+-------------------------------------------+
| Cursor   | .cursor/mcp.json          | {"mcpServers":                            |
|          |                           |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| VS Code  | .vscode/mcp.json          | {"servers":                               |
| Copilot  |                           |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| Windsurf | ~/.codeium/windsurf/      | {"mcpServers":                            |
|          | mcp_config.json           |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| Cline    | .cline/mcp_servers.json   | {"mcpServers":                            |
|          |                           |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| Zed      | ~/.config/zed/            | {"context_servers":                       |
|          | settings.json             |   {"gw": {"command":"...","args":[...]}}}  |
+----------+---------------------------+-------------------------------------------+
| Generic  | stdout or --output path   | {"mcpServers":                            |
|          |                           |   {"gw": {"url":"http://..."}}}            |
+----------+---------------------------+-------------------------------------------+
```

### 2.4 Merge Strategy

When a client config file exists, the exporter MUST NOT overwrite unrelated
content. Strategy:

1. Read existing JSON file (or start with `{}` if it does not exist)
2. Navigate to the `mcpServers` (or `servers` or `context_servers`) key
3. Upsert the gateway entry under the configured name (default: `"gateway"`)
4. Serialize and write back with `serde_json::to_string_pretty`
5. Preserve all other keys in the JSON document

This is the same approach already used in `setup.rs::write_client_entry_if_exists`.

**Atomic writes**: Step 4 uses write-to-tempfile + rename to prevent partial
writes from corrupting the config. For shared config files (e.g., Zed
`settings.json` which may be written by the editor simultaneously), the
exporter acquires an advisory file lock (`flock`/`LockFile`) before
read-modify-write to prevent concurrent mutation races.

---

## 3. Rust Type Definitions

```rust
// src/commands/config_export.rs

use std::path::{Path, PathBuf};
use serde_json::{Map, Value, json};
use crate::config::Config;

/// Connection mode for the exported client config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConnectionMode {
    /// HTTP proxy mode: client connects to gateway URL
    Proxy,
    /// Stdio mode: client spawns gateway as subprocess
    Stdio,
    /// Auto-detect based on environment
    Auto,
}

/// Target AI client for config export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportTarget {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    VsCodeCopilot,
    Windsurf,
    Cline,
    Zed,
    Generic,
    All,
}

/// Resolved export target with its config path and JSON structure.
struct ClientSpec {
    /// Human-readable label (for CLI output)
    label: &'static str,
    /// Resolved path to the client's config file
    path: PathBuf,
    /// JSON key for the server list ("mcpServers", "servers", "context_servers")
    servers_key: &'static str,
    /// Whether the file may contain non-MCP content (Zed settings.json)
    is_shared_config: bool,
}

/// Result of a single client export operation.
pub struct ExportResult {
    pub client: &'static str,
    pub path: PathBuf,
    pub action: ExportAction,
}

pub enum ExportAction {
    /// Wrote new config file
    Created,
    /// Updated existing config (merged gateway entry)
    Updated,
    /// Skipped (client not installed or config dir missing)
    Skipped(String),
    /// Failed with error
    Failed(String),
}

/// Build the gateway entry JSON for a given connection mode.
///
/// Proxy mode:
///   { "url": "http://127.0.0.1:39400/mcp" }
///
/// Stdio mode:
///   { "command": "mcp-gateway", "args": ["serve", "--stdio", "-c", "/path/to/gateway.yaml"] }
fn build_gateway_entry(
    config: &Config,
    config_path: Option<&Path>,
    mode: ConnectionMode,
) -> Value {
    match resolve_mode(mode) {
        ConnectionMode::Proxy => {
            json!({
                "url": format!("http://{}:{}/mcp", config.server.host, config.server.port)
            })
        }
        ConnectionMode::Stdio | ConnectionMode::Auto => {
            let mut args = vec!["serve".to_string(), "--stdio".to_string()];
            if let Some(p) = config_path {
                args.push("-c".to_string());
                args.push(p.display().to_string());
            }
            json!({
                "command": "mcp-gateway",
                "args": args
            })
        }
    }
}

/// Resolve Auto mode: check if a gateway daemon is already running
/// (-> proxy) or if the binary is on PATH (-> stdio).
fn resolve_mode(mode: ConnectionMode, config: &Config) -> ConnectionMode {
    if mode != ConnectionMode::Auto {
        return mode;
    }
    // First, check if a running gateway is reachable via health endpoint.
    // A quick connect + GET /health avoids spawning unnecessary subprocesses.
    let health_url = format!(
        "http://{}:{}/health",
        config.server.host, config.server.port
    );
    if probe_health(&health_url) {
        return ConnectionMode::Proxy;
    }
    // Fallback: check if mcp-gateway is on PATH (-> stdio)
    if which_mcp_gateway().is_some() {
        ConnectionMode::Stdio
    } else {
        ConnectionMode::Proxy
    }
}

/// Try a GET to the gateway health endpoint with a short timeout.
/// Returns true if the daemon is running and healthy.
fn probe_health(url: &str) -> bool {
    // Uses std::net::TcpStream with 500ms timeout to avoid blocking.
    // A full HTTP client is not needed — a successful TCP connect to
    // the port plus a 200 response on /health is sufficient.
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let addr = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .and_then(|hp| hp.to_socket_addrs().ok())
        .and_then(|mut addrs| addrs.next());
    match addr {
        Some(a) => TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

fn which_mcp_gateway() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join("mcp-gateway"))
                .find(|p| p.is_file())
        })
}

/// Merge a gateway entry into an existing JSON config file.
///
/// Preserves all existing content. Creates the servers_key object if absent.
/// Returns Ok(ExportAction) describing what happened.
fn merge_into_config(
    path: &Path,
    servers_key: &str,
    entry_name: &str,
    entry: &Value,
) -> Result<ExportAction, String> {
    let mut doc: Value = if path.exists() {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?
    } else {
        json!({})
    };

    let servers = doc
        .as_object_mut()
        .ok_or("Config root is not a JSON object")?
        .entry(servers_key)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(format!("'{servers_key}' is not a JSON object"))?;

    let action = if servers.contains_key(entry_name) {
        servers.insert(entry_name.to_string(), entry.clone());
        ExportAction::Updated
    } else {
        servers.insert(entry_name.to_string(), entry.clone());
        if path.exists() { ExportAction::Updated } else { ExportAction::Created }
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }

    let json_str = serde_json::to_string_pretty(&doc)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;

    // Atomic write: write to tempfile in same directory, then rename.
    // This prevents partial writes from corrupting the config if the
    // process is interrupted mid-write.
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&tmp, &json_str)
        .map_err(|e| format!("Cannot write temp file {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("Cannot rename {} -> {}: {e}", tmp.display(), path.display()))?;

    Ok(action)
}
```

---

## 4. CLI Interface

### 4.1 New Subcommand

```rust
// Addition to src/cli/mod.rs Command enum:

/// Export gateway config as client-specific MCP configurations
///
/// Generates JSON config files for AI clients (Claude Code, Cursor, VS Code,
/// etc.) from the single gateway.yaml. Supports proxy and stdio modes.
///
/// # Examples
///
/// ```bash
/// # Export to all detected clients
/// mcp-gateway setup export --all
///
/// # Export only for Claude Code in stdio mode
/// mcp-gateway setup export --target claude-code --mode stdio
///
/// # Export in proxy mode with custom entry name
/// mcp-gateway setup export --all --mode proxy --name my-gateway
///
/// # Watch for config changes and auto-regenerate
/// mcp-gateway setup export --all --watch
///
/// # Dry-run: show what would be written
/// mcp-gateway setup export --all --dry-run
/// ```
#[command(subcommand, about = "Setup and export gateway config to AI client formats")]
Setup(SetupCommand),

// New subcommand enum (extends existing Setup):
#[derive(Subcommand, Debug)]
pub enum SetupCommand {
    /// Export gateway.yaml as client-native MCP config
    #[command(about = "Generate client-specific MCP config files")]
    Export {
        /// Target client(s) to export for
        #[arg(short, long, default_value = "all", value_enum)]
        target: ExportTarget,

        /// Connection mode: proxy (HTTP URL) or stdio (subprocess)
        #[arg(short, long, default_value = "auto", value_enum)]
        mode: ConnectionMode,

        /// Name for the gateway entry in client configs
        #[arg(short, long, default_value = "gateway")]
        name: String,

        /// Watch gateway.yaml for changes and auto-regenerate
        #[arg(short, long)]
        watch: bool,

        /// Show what would be written without writing
        #[arg(long)]
        dry_run: bool,

        /// Gateway config file to read
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
    },
}
```

### 4.2 CLI Output

```
$ mcp-gateway setup export --all

Exporting gateway config to AI clients...

  Claude Code:    Updated ~/.claude.json
  Claude Desktop: Created ~/Library/.../claude_desktop_config.json
  Cursor:         Updated .cursor/mcp.json
  VS Code Copilot: Skipped (no .vscode/ directory)
  Windsurf:       Skipped (not installed)
  Cline:          Skipped (no .cline/ directory)
  Zed:            Updated ~/.config/zed/settings.json

Exported to 3 clients (stdio mode).

Entry name: "gateway"
Gateway URL: http://127.0.0.1:39400/mcp (proxy fallback)
```

### 4.3 Watch Mode

```
$ mcp-gateway setup export --all --watch

Watching gateway.yaml for changes (Ctrl+C to stop)...

[14:32:15] gateway.yaml changed — regenerating...
  Claude Code:    Updated
  Cursor:         Updated
  Zed:            Updated
[14:32:15] Done (3 clients updated).
```

Watch mode reuses the existing `notify` crate (already in Cargo.toml for
hot-reload). The file watcher is the same infrastructure used by
`src/config_reload/`.

---

## 5. Integration Points

### 5.1 Files to Create

| File | Purpose | Approx LOC |
|------|---------|------------|
| `src/commands/config_export.rs` | Export logic + merge + client specs | ~250 |
| (test code inline with `#[cfg(test)]`) | Unit tests for merge, path resolution | ~100 |

### 5.2 Files to Modify

| File | Change | LOC Delta |
|------|--------|-----------|
| `src/cli/mod.rs` | Add `Export` variant to existing `SetupCommand` enum | ~40 |
| `src/commands/mod.rs` | Add `mod config_export; pub use config_export::run_config_export;` | ~3 |
| `src/main.rs` | Add match arm for `Command::Setup(SetupCommand::Export { .. })` | ~10 |
| `Cargo.toml` | Add `config-export` to default features list | ~1 |

### 5.3 Reuse from Existing Code

- `Config::load()` from `src/config/mod.rs` -- already handles YAML + env vars
- `dirs::home_dir()` -- already a dependency
- `notify` crate -- already in Cargo.toml for config reload
- Path helpers from `src/commands/setup.rs` (`home_path`, `claude_desktop_path`)
  -- factor into shared `src/commands/paths.rs` module
- `serde_json` -- already a dependency

**Zero new dependencies required.**

---

## 6. Config Schema

No new config fields are needed. The exporter reads the existing `Config`
struct:

```yaml
# These existing fields are used by the exporter:
server:
  host: "127.0.0.1"    # -> proxy URL
  port: 39400           # -> proxy URL
```

The exporter derives all output from the existing config. The `--name`,
`--mode`, and `--target` are CLI-only parameters.

---

## 7. Testing Strategy

### 7.1 Unit Tests (inline `#[cfg(test)]`)

| Test | Validates |
|------|-----------|
| `build_gateway_entry_proxy_mode` | Correct URL format with host:port |
| `build_gateway_entry_stdio_mode` | Correct command + args array |
| `build_gateway_entry_stdio_with_config` | -c flag appended with config path |
| `merge_into_new_file` | Creates new JSON with correct structure |
| `merge_into_existing_preserves_content` | Existing keys survive merge |
| `merge_into_existing_updates_entry` | Same-name entry is replaced |
| `merge_zed_shared_config` | Non-MCP keys in settings.json preserved |
| `client_specs_resolve_paths` | Each client resolves to correct platform path |
| `resolve_mode_auto_stdio_when_on_path` | Auto detects binary on PATH |
| `resolve_mode_auto_proxy_when_not_on_path` | Auto falls back to proxy |
| `dry_run_produces_no_writes` | No filesystem changes in dry-run mode |

### 7.2 Integration Tests (tests/cli_config_export.rs)

```rust
#[tokio::test]
async fn config_export_creates_all_client_configs() {
    // Create a tempdir, write a minimal gateway.yaml
    // Run the export command targeting the tempdir
    // Verify each client config file exists with correct structure
}

#[tokio::test]
async fn config_export_merge_idempotent() {
    // Run export twice
    // Second run should update, not duplicate
}
```

---

## 8. Design Characteristics

### 8.1 What exists today

| Tool | Capability |
|------|-----------|
| Claude Code | `claude mcp add` -- adds to its own config only |
| Cursor | Manual JSON editing |
| mcp-get | Installs MCP servers for one client at a time |
| smithery | Registry, but no cross-client config sync |

### 8.2 What this RFC adds

1. **Single source of truth**: One `gateway.yaml` generates all client configs
2. **Bidirectional**: Combined with `mcp-gateway setup` (import), this
   completes the import/export cycle
3. **Watch mode**: Config changes auto-propagate to all clients
4. **Merge-safe**: Never destroys existing client config content
5. **Mode-aware**: Auto-detects proxy vs stdio based on environment
6. **Dry-run**: Preview before committing changes

### 8.3 Future: Bidirectional Sync (v2.7+)

The bidirectional sync idea is captured but NOT in scope for this RFC:

```
gateway.yaml  <--import-->  Client configs
      |                          |
      +--- export (RFC-0070) --->+
      +<-- import (setup cmd) ---+
      +<-- watch (future) ------>+  <-- bidirectional watch
```

Future `mcp-gateway setup sync --watch` would watch BOTH gateway.yaml AND
client configs, merging changes in both directions using last-write-wins
semantics. This requires conflict resolution that warrants its own RFC.

---

## 9. Risk Register

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| R1 | Client config format changes | Medium | Medium | Version-detect client, gate behind --target to limit blast radius |
| R2 | Overwriting user's manual client config | Low | High | Merge strategy preserves all non-gateway keys; --dry-run for preview |
| R3 | File permission issues on Linux/macOS | Low | Low | Clear error messages with path and permission details |
| R4 | Zed settings.json is shared (non-MCP keys) | Medium | Medium | Parse full JSON, only touch `context_servers` key, preserve rest |
| R5 | Watch mode event storms | Low | Low | Debounce with 500ms delay (same as config_reload) |
| R6 | Binary not on PATH in stdio mode | Medium | Low | Auto-detect falls back to proxy; warn user with `mcp-gateway doctor` |

---

## ADR-0070: Config Export Architecture

### Context

The `mcp-gateway setup` command imports MCP servers from client configs. Users
requested the inverse: exporting gateway config to client configs. Two
approaches were considered:

1. **Template-based**: Ship static JSON templates per client, fill in values
2. **Merge-based**: Parse existing client JSON, upsert the gateway entry

### Decision

**Merge-based approach** (option 2). Rationale:

- Templates break when clients add new fields or change structure
- Merge preserves user's existing client configuration (other MCP servers,
  settings, custom keys)
- `serde_json::Value` manipulation is already proven in `setup.rs`
- Zero new dependencies

### Consequences

- Must handle malformed client JSON gracefully (report and skip, not crash)
- Must validate JSON structure after merge before writing
- Slightly more code than templates, but significantly more robust

---

## Implementation Order

1. Factor path helpers from `setup.rs` into shared module (~20 LOC)
2. Implement `ClientSpec` resolution for all 8 clients (~60 LOC)
3. Implement `build_gateway_entry` for proxy and stdio modes (~30 LOC)
4. Implement `merge_into_config` JSON merge logic (~50 LOC)
5. Implement `run_config_export` command handler (~60 LOC)
6. Wire into CLI (`cli/mod.rs`, `commands/mod.rs`, `main.rs`) (~50 LOC)
7. Add watch mode via `notify` (~30 LOC)
8. Write unit tests (~100 LOC)

**Total: ~400 LOC** (within 300-500 budget)
