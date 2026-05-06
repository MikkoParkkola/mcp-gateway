//! Implementation of `mcp-gateway setup export`.
//!
//! Reads `gateway.yaml` and writes client-native MCP configuration entries
//! into every supported AI client config file. Supports proxy mode (HTTP URL)
//! and stdio mode (subprocess spawn), with auto-detection based on whether a
//! gateway daemon is currently running.
//!
//! # Merge strategy
//!
//! Existing client config content is preserved. The exporter reads the file,
//! upserts the gateway entry under its configured name, and writes back via an
//! atomic tempfile-rename to prevent partial-write corruption.
//!
//! # Clients
//!
//! | Client         | Config key        | File                                   |
//! |----------------|-------------------|----------------------------------------|
//! | Claude Code    | `mcpServers`      | `~/.claude.json`                       |
//! | Claude Desktop | `mcpServers`      | platform-specific                      |
//! | Cursor         | `mcpServers`      | `.cursor/mcp.json` (workspace-rel)     |
//! | VS Code Copilot| `servers`         | `.vscode/mcp.json` (workspace-rel)     |
//! | Windsurf       | `mcpServers`      | `~/.codeium/windsurf/mcp_config.json`  |
//! | Cline          | `mcpServers`      | `.cline/mcp_servers.json` (ws-rel)     |
//! | Zed            | `context_servers` | `~/.config/zed/settings.json`          |
//! | Generic        | `mcpServers`      | stdout or `--output`                   |

mod watch;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};

use mcp_gateway::{
    cli::{ConnectionMode, ExportTarget},
    config::Config,
};

use crate::commands::paths::{claude_desktop_path, home_path, windsurf_path, zed_settings_path};

// ── Internal types ────────────────────────────────────────────────────────────

/// Resolved config spec for a single AI client.
pub(super) struct ClientSpec {
    /// Human-readable label used in CLI output.
    pub(super) label: &'static str,
    /// Resolved filesystem path to the client's config file.
    pub(super) path: PathBuf,
    /// JSON key that holds the server map (`"mcpServers"`, `"servers"`, etc.).
    pub(super) servers_key: &'static str,
}

/// Outcome of attempting to export to one client.
pub struct ExportResult {
    pub client: &'static str,
    pub path: PathBuf,
    pub action: ExportAction,
}

/// What the exporter did (or failed to do) for a single client.
pub enum ExportAction {
    /// A new config file was created.
    Created,
    /// An existing config file was updated (gateway entry upserted).
    Updated,
    /// Client config directory is absent — nothing to do.
    Skipped(String),
    /// An error occurred; the file was not modified.
    Failed(String),
}

// ── Core logic ────────────────────────────────────────────────────────────────

/// Build the JSON entry to insert for this gateway instance.
///
/// Proxy mode produces `{"url": "http://host:port/mcp"}`.
/// Stdio mode produces `{"command": "mcp-gateway", "args": ["serve", "--stdio", ...]}`.
pub fn build_gateway_entry(
    config: &Config,
    config_path: Option<&Path>,
    mode: ConnectionMode,
) -> Value {
    match resolve_mode(mode, config) {
        ConnectionMode::Proxy | ConnectionMode::Auto => {
            json!({
                "url": format!("http://{}:{}/mcp", config.server.host, config.server.port)
            })
        }
        ConnectionMode::Stdio => {
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

/// Resolve `Auto` mode to a concrete `Proxy` or `Stdio` decision.
///
/// Auto resolution:
/// 1. If a gateway daemon is reachable at `host:port/health` → Proxy.
/// 2. If `mcp-gateway` is on `PATH` → Stdio.
/// 3. Otherwise → Proxy (user must start daemon manually).
pub fn resolve_mode(mode: ConnectionMode, config: &Config) -> ConnectionMode {
    if mode != ConnectionMode::Auto {
        return mode;
    }
    let health_url = format!(
        "http://{}:{}/health",
        config.server.host, config.server.port
    );
    if probe_health(&health_url) {
        return ConnectionMode::Proxy;
    }
    if which_mcp_gateway().is_some() {
        ConnectionMode::Stdio
    } else {
        ConnectionMode::Proxy
    }
}

/// Probe the gateway health endpoint with a 500 ms TCP-connect timeout.
///
/// Returns `true` if a TCP connection succeeds (daemon is reachable).
fn probe_health(url: &str) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let host_port = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");

    let addr = host_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next());

    match addr {
        Some(a) => TcpStream::connect_timeout(&a, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

/// Return the path to `mcp-gateway` if it is on `PATH`, else `None`.
fn which_mcp_gateway() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join("mcp-gateway"))
            .find(|p| p.is_file())
    })
}

/// Merge (upsert) a gateway entry into a JSON config file.
///
/// If the file does not exist, it is created with minimal structure.
/// All existing content is preserved; only `servers_key[entry_name]` is set.
/// The write is atomic (tempfile + rename in the same directory).
///
/// Returns the action taken, or an error string if the operation failed.
pub fn merge_into_config(
    path: &Path,
    servers_key: &str,
    entry_name: &str,
    entry: &Value,
) -> Result<ExportAction, String> {
    let existed = path.exists();
    let mut doc: Value = if existed {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?
    } else {
        json!({})
    };

    {
        let root = doc
            .as_object_mut()
            .ok_or_else(|| "Config root is not a JSON object".to_string())?;
        let servers = root
            .entry(servers_key)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| format!("'{servers_key}' is not a JSON object"))?;
        servers.insert(entry_name.to_string(), entry.clone());
    }

    let action = if existed {
        ExportAction::Updated
    } else {
        ExportAction::Created
    };

    // Ensure parent directory exists before writing.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }

    let json_str = serde_json::to_string_pretty(&doc)
        .map_err(|e| format!("JSON serialization failed: {e}"))?;

    // Atomic write: write to a sibling tempfile, then rename.
    let parent = path.parent().unwrap_or(Path::new("."));
    let file_name = path.file_name().map_or_else(
        || "config.json".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = parent.join(format!(".{file_name}.tmp"));
    std::fs::write(&tmp, &json_str)
        .map_err(|e| format!("Cannot write temp file {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("Cannot rename {} -> {}: {e}", tmp.display(), path.display()))?;

    Ok(action)
}

// ── Client specs ──────────────────────────────────────────────────────────────

/// Build the list of `ClientSpec`s for the given target.
///
/// For workspace-relative paths (Cursor, VS Code, Cline), the path is resolved
/// relative to the current working directory — matching how those tools look
/// for their per-project configs.
pub(super) fn client_specs(target: ExportTarget) -> Vec<ClientSpec> {
    let cwd = std::env::current_dir().unwrap_or_default();

    let all_specs = vec![
        ClientSpec {
            label: "Claude Code",
            path: home_path(".claude.json"),
            servers_key: "mcpServers",
        },
        ClientSpec {
            label: "Claude Desktop",
            path: claude_desktop_path(),
            servers_key: "mcpServers",
        },
        ClientSpec {
            label: "Cursor",
            path: cwd.join(".cursor/mcp.json"),
            servers_key: "mcpServers",
        },
        ClientSpec {
            label: "VS Code Copilot",
            path: cwd.join(".vscode/mcp.json"),
            servers_key: "servers",
        },
        ClientSpec {
            label: "Windsurf",
            path: windsurf_path(),
            servers_key: "mcpServers",
        },
        ClientSpec {
            label: "Cline",
            path: cwd.join(".cline/mcp_servers.json"),
            servers_key: "mcpServers",
        },
        ClientSpec {
            label: "Zed",
            path: zed_settings_path(),
            servers_key: "context_servers",
        },
    ];

    match target {
        ExportTarget::All => all_specs,
        ExportTarget::ClaudeCode => all_specs
            .into_iter()
            .filter(|s| s.label == "Claude Code")
            .collect(),
        ExportTarget::ClaudeDesktop => all_specs
            .into_iter()
            .filter(|s| s.label == "Claude Desktop")
            .collect(),
        ExportTarget::Cursor => all_specs
            .into_iter()
            .filter(|s| s.label == "Cursor")
            .collect(),
        ExportTarget::VsCodeCopilot => all_specs
            .into_iter()
            .filter(|s| s.label == "VS Code Copilot")
            .collect(),
        ExportTarget::Windsurf => all_specs
            .into_iter()
            .filter(|s| s.label == "Windsurf")
            .collect(),
        ExportTarget::Cline => all_specs
            .into_iter()
            .filter(|s| s.label == "Cline")
            .collect(),
        ExportTarget::Zed => all_specs.into_iter().filter(|s| s.label == "Zed").collect(),
        ExportTarget::Generic => vec![], // handled separately in run_config_export
    }
}

// ── Command entry point ───────────────────────────────────────────────────────

/// Run `mcp-gateway setup export`.
///
/// Loads `gateway.yaml` from `config_path`, resolves the connection mode, then
/// writes (or prints, for dry-run) a gateway entry into every selected client's
/// config file.
#[allow(clippy::too_many_lines)]
pub async fn run_config_export(
    target: ExportTarget,
    mode: ConnectionMode,
    name: &str,
    watch: bool,
    dry_run: bool,
    config_path: &Path,
) -> ExitCode {
    let config = match Config::load(Some(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Cannot load {}: {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    };

    if dry_run {
        println!("Dry-run mode — no files will be written.");
        println!();
    }

    let resolved = resolve_mode(mode, &config);
    let mode_label = match resolved {
        ConnectionMode::Proxy | ConnectionMode::Auto => "proxy",
        ConnectionMode::Stdio => "stdio",
    };

    if target == ExportTarget::Generic {
        // Generic: print JSON to stdout.
        let entry = build_gateway_entry(&config, Some(config_path), mode);
        let wrapper = json!({ "mcpServers": { name: entry } });
        println!(
            "{}",
            serde_json::to_string_pretty(&wrapper).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }

    println!("Exporting gateway config to AI clients...");
    println!();

    let results = do_export(target, mode, name, dry_run, config_path, &config);

    let mut written = 0usize;
    let mut failed = false;

    for r in &results {
        let path = r.path.display();
        let status = match &r.action {
            ExportAction::Created => {
                written += 1;
                format!("Created  {path}")
            }
            ExportAction::Updated => {
                written += 1;
                format!("Updated  {path}")
            }
            ExportAction::Skipped(reason) => format!("Skipped  ({reason})"),
            ExportAction::Failed(err) => {
                failed = true;
                format!("FAILED   {err}")
            }
        };
        let client = r.client;
        println!("  {client:16} {status}");
    }

    println!();
    if dry_run {
        println!("Would export to {written} client(s) ({mode_label} mode).");
    } else {
        println!("Exported to {written} client(s) ({mode_label} mode).");
    }
    println!();
    println!("Entry name: \"{name}\"");
    println!("Gateway endpoint: configured from server.host/server.port");

    if watch {
        watch::run_watch_loop(target, mode, name, config_path).await;
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Perform the actual export for all specs; returns a result per client.
fn do_export(
    target: ExportTarget,
    mode: ConnectionMode,
    name: &str,
    dry_run: bool,
    config_path: &Path,
    config: &Config,
) -> Vec<ExportResult> {
    let specs = client_specs(target);
    let entry = build_gateway_entry(config, Some(config_path), mode);

    specs
        .into_iter()
        .map(|spec| {
            let action = export_one(&spec, name, &entry, dry_run);
            ExportResult {
                client: spec.label,
                path: spec.path,
                action,
            }
        })
        .collect()
}

/// Export (or dry-run) a single client spec.
pub(super) fn export_one(
    spec: &ClientSpec,
    name: &str,
    entry: &Value,
    dry_run: bool,
) -> ExportAction {
    // For workspace-relative paths (Cursor, VS Code, Cline): skip if the
    // parent directory does not exist, since there is no project open.
    if (!spec.path.is_absolute()
        || spec.label == "Cursor"
        || spec.label == "VS Code Copilot"
        || spec.label == "Cline")
        && let Some(parent) = spec.path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return ExportAction::Skipped(format!("no {} directory", parent.display()));
    }

    // For global paths (Claude Desktop, Windsurf, Zed): skip if the parent
    // directory doesn't exist (client not installed).
    if spec.label != "Claude Code"
        && let Some(parent) = spec.path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return ExportAction::Skipped(format!("{} not installed", spec.label));
    }

    if dry_run {
        // Dry-run: report what would happen without touching the filesystem.
        if spec.path.exists() {
            ExportAction::Updated
        } else {
            ExportAction::Created
        }
    } else {
        match merge_into_config(&spec.path, spec.servers_key, name, entry) {
            Ok(action) => action,
            Err(e) => ExportAction::Failed(e),
        }
    }
}
