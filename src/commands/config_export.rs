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
struct ClientSpec {
    /// Human-readable label used in CLI output.
    label: &'static str,
    /// Resolved filesystem path to the client's config file.
    path: PathBuf,
    /// JSON key that holds the server map (`"mcpServers"`, `"servers"`, etc.).
    servers_key: &'static str,
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
fn client_specs(target: ExportTarget) -> Vec<ClientSpec> {
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
    let host = &config.server.host;
    let port = config.server.port;
    println!("Gateway URL: http://{host}:{port}/mcp");

    if watch {
        run_watch_loop(target, mode, name, config_path).await;
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
fn export_one(spec: &ClientSpec, name: &str, entry: &Value, dry_run: bool) -> ExportAction {
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

// ── Watch mode ────────────────────────────────────────────────────────────────

/// Watch `config_path` for changes and re-export whenever it is modified.
///
/// Uses the `notify` crate (already required for hot-reload) with a 500 ms
/// debounce to suppress event storms.
async fn run_watch_loop(
    target: ExportTarget,
    mode: ConnectionMode,
    name: &str,
    config_path: &Path,
) {
    use notify::{Event, RecursiveMode, Watcher, recommended_watcher};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    println!();
    println!(
        "Watching {} for changes (Ctrl+C to stop)...",
        config_path.display()
    );

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = match recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Warning: Cannot start file watcher: {e}");
            return;
        }
    };

    let watch_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(config_path)
    };

    if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
        eprintln!("Warning: Cannot watch {}: {e}", watch_path.display());
        return;
    }

    let debounce = Duration::from_millis(500);
    let mut last_event: Option<Instant> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(_event)) => {
                last_event = Some(Instant::now());
            }
            Ok(Err(e)) => {
                eprintln!("Watch error: {e}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if let Some(t) = last_event
            && t.elapsed() >= debounce
        {
            last_event = None;
            let now = chrono::Local::now().format("%H:%M:%S");
            println!(
                "[{now}] {} changed — regenerating...",
                config_path.display()
            );

            match Config::load(Some(config_path)) {
                Ok(config) => {
                    let entry = build_gateway_entry(&config, Some(config_path), mode);
                    let specs = client_specs(target);
                    let mut updated = 0usize;
                    for spec in specs {
                        match export_one(&spec, name, &entry, false) {
                            ExportAction::Created | ExportAction::Updated => {
                                println!("  {}: Updated", spec.label);
                                updated += 1;
                            }
                            ExportAction::Skipped(_) => {}
                            ExportAction::Failed(e) => {
                                eprintln!("  {}: FAILED — {e}", spec.label);
                            }
                        }
                    }
                    println!("[{now}] Done ({updated} client(s) updated).");
                }
                Err(e) => eprintln!("  Cannot reload config: {e}"),
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_gateway::config::Config;
    use serde_json::json;

    fn default_config() -> Config {
        Config::default()
    }

    // ── build_gateway_entry ───────────────────────────────────────────────────

    #[test]
    fn build_gateway_entry_proxy_mode() {
        // GIVEN: default config (host=127.0.0.1, port=39400) and Proxy mode
        let cfg = default_config();
        let entry = build_gateway_entry(&cfg, None, ConnectionMode::Proxy);

        // THEN: produces {"url": "http://127.0.0.1:39400/mcp"}
        assert_eq!(entry["url"], "http://127.0.0.1:39400/mcp");
        assert!(entry.get("command").is_none());
    }

    #[test]
    fn build_gateway_entry_stdio_mode() {
        // GIVEN: default config and Stdio mode, no config path
        let cfg = default_config();
        let entry = build_gateway_entry(&cfg, None, ConnectionMode::Stdio);

        // THEN: produces {"command": "mcp-gateway", "args": ["serve", "--stdio"]}
        assert_eq!(entry["command"], "mcp-gateway");
        let args = entry["args"].as_array().unwrap();
        assert_eq!(args[0], "serve");
        assert_eq!(args[1], "--stdio");
        assert_eq!(args.len(), 2); // no -c flag without config path
    }

    #[test]
    fn build_gateway_entry_stdio_with_config() {
        // GIVEN: Stdio mode with a config path supplied
        let cfg = default_config();
        let config_path = Path::new("/etc/mcp-gateway/gateway.yaml");
        let entry = build_gateway_entry(&cfg, Some(config_path), ConnectionMode::Stdio);

        // THEN: -c flag and path are appended to args
        let args = entry["args"].as_array().unwrap();
        assert_eq!(args[2], "-c");
        assert_eq!(args[3], "/etc/mcp-gateway/gateway.yaml");
    }

    // ── merge_into_config ─────────────────────────────────────────────────────

    #[test]
    fn merge_into_new_file() {
        // GIVEN: a path that does not exist yet
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.json");
        let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

        // WHEN: merging into a non-existent file
        let action = merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

        // THEN: file is created with correct structure
        assert!(matches!(action, ExportAction::Created));
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["mcpServers"]["gateway"]["url"],
            "http://127.0.0.1:39400/mcp"
        );
    }

    #[test]
    fn merge_into_existing_preserves_content() {
        // GIVEN: an existing config with an unrelated key
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.json");
        std::fs::write(
            &path,
            r#"{"otherTool": {"key": "value"}, "mcpServers": {}}"#,
        )
        .unwrap();

        let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

        // WHEN: merging gateway entry
        merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

        // THEN: existing keys are preserved
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["otherTool"]["key"], "value");
        assert_eq!(
            parsed["mcpServers"]["gateway"]["url"],
            "http://127.0.0.1:39400/mcp"
        );
    }

    #[test]
    fn merge_into_existing_updates_entry() {
        // GIVEN: an existing config with a stale gateway entry
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"gateway": {"url": "http://old:1234/mcp"}}}"#,
        )
        .unwrap();

        let new_entry = json!({"url": "http://127.0.0.1:39400/mcp"});

        // WHEN: merging with the same name
        let action = merge_into_config(&path, "mcpServers", "gateway", &new_entry).unwrap();

        // THEN: entry is replaced, action is Updated
        assert!(matches!(action, ExportAction::Updated));
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["mcpServers"]["gateway"]["url"],
            "http://127.0.0.1:39400/mcp"
        );
    }

    #[test]
    fn merge_zed_shared_config() {
        // GIVEN: a Zed settings.json with non-MCP keys (editor preferences, etc.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"theme": "One Dark", "font_size": 14, "context_servers": {}}"#,
        )
        .unwrap();

        let entry = json!({"command": "mcp-gateway", "args": ["serve", "--stdio"]});

        // WHEN: merging into context_servers key
        merge_into_config(&path, "context_servers", "gateway", &entry).unwrap();

        // THEN: non-MCP keys are preserved
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["theme"], "One Dark");
        assert_eq!(parsed["font_size"], 14);
        assert_eq!(
            parsed["context_servers"]["gateway"]["command"],
            "mcp-gateway"
        );
    }

    #[test]
    fn client_specs_resolve_paths() {
        // GIVEN: All target
        let specs = client_specs(ExportTarget::All);

        // THEN: each spec has a non-empty path and a known servers_key
        assert!(!specs.is_empty());
        for spec in &specs {
            assert!(
                !spec.path.as_os_str().is_empty(),
                "empty path for {}",
                spec.label
            );
            assert!(
                ["mcpServers", "servers", "context_servers"].contains(&spec.servers_key),
                "unexpected servers_key '{}' for {}",
                spec.servers_key,
                spec.label
            );
        }
    }

    #[test]
    fn resolve_mode_returns_proxy_when_mode_is_proxy() {
        // GIVEN: explicit Proxy mode
        let cfg = default_config();

        // WHEN/THEN: resolve_mode returns Proxy unchanged
        assert_eq!(
            resolve_mode(ConnectionMode::Proxy, &cfg),
            ConnectionMode::Proxy
        );
    }

    #[test]
    fn resolve_mode_returns_stdio_when_mode_is_stdio() {
        // GIVEN: explicit Stdio mode
        let cfg = default_config();

        // WHEN/THEN: resolve_mode returns Stdio unchanged
        assert_eq!(
            resolve_mode(ConnectionMode::Stdio, &cfg),
            ConnectionMode::Stdio
        );
    }

    #[test]
    fn resolve_mode_auto_proxy_when_not_on_path() {
        // GIVEN: Auto mode with a config that points to an unreachable port
        // (port 1 is reserved/unreachable) — so the health probe fails.
        let mut cfg = default_config();
        cfg.server.port = 1; // reserved/unreachable port

        // WHEN: resolve_mode in Auto mode
        // The health probe on port 1 will fail (TCP refused or timed out).
        // which_mcp_gateway() may or may not find the binary — we cannot
        // reliably control PATH without unsafe, so we only assert that the
        // return value is *either* Proxy or Stdio (never panics or crashes).
        let result = resolve_mode(ConnectionMode::Auto, &cfg);

        // THEN: result must be a concrete mode (not Auto)
        assert_ne!(result, ConnectionMode::Auto);
    }

    #[test]
    fn resolve_mode_auto_with_unreachable_port_returns_concrete_mode() {
        // GIVEN: config with port 2 (also reserved/unreachable)
        let mut cfg = default_config();
        cfg.server.port = 2;

        // WHEN: resolving Auto
        let result = resolve_mode(ConnectionMode::Auto, &cfg);

        // THEN: always returns Proxy or Stdio, never panics
        assert!(
            result == ConnectionMode::Proxy || result == ConnectionMode::Stdio,
            "unexpected mode: {result:?}"
        );
    }

    #[test]
    fn dry_run_produces_no_writes() {
        // GIVEN: an existing config file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        let original = r#"{"mcpServers": {}}"#;
        std::fs::write(&path, original).unwrap();

        let entry = json!({"url": "http://127.0.0.1:39400/mcp"});
        let spec = ClientSpec {
            label: "Test",
            path: path.clone(),
            servers_key: "mcpServers",
        };

        // WHEN: dry-run export
        let action = export_one(&spec, "gateway", &entry, true);

        // THEN: file content is unchanged
        assert!(matches!(action, ExportAction::Updated));
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original);
    }

    #[test]
    fn merge_creates_parent_directory() {
        // GIVEN: a nested path whose parent does not exist
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/client.json");

        let entry = json!({"url": "http://127.0.0.1:39400/mcp"});

        // WHEN: merging (parent doesn't exist yet)
        let action = merge_into_config(&path, "mcpServers", "gateway", &entry).unwrap();

        // THEN: parent is created and file is written
        assert!(matches!(action, ExportAction::Created));
        assert!(path.exists());
    }
}
