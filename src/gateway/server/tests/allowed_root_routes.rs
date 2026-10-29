// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-tool allowed folders end to end: a real stdio backend behind a
//! gateway built from config, so both firewalls are the production ones
//! (`build_meta_mcp` and `response_firewall`), driven on every route that
//! reaches a backend (test plan 2.4, 9.1). The backend logs each call it
//! receives, so a row proves an outside path never arrived and an inside
//! path arrived as exactly the string checked. Batch 5.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::Gateway;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::router::{AppState, create_router};

/// A stdio MCP peer with `read_file(path)` and `read_multiple_files(paths)`.
/// It appends every `tools/call` line it reads to `__LOG__` and answers ok.
const PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fs","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"read_file","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"a":{"type":"object"}}}},{"name":"read_multiple_files","inputSchema":{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"}}}}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >> __LOG__
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}\n' "$id" ;;
  esac
done
"#;

/// What a row varies: the root rule's `servers` and `path_args` (YAML list
/// bodies) and an optional secret rule injecting into `secret_key`.
pub(super) struct Setup {
    pub(super) servers: &'static str,
    pub(super) path_args: &'static str,
    pub(super) secret_key: Option<&'static str>,
    pub(super) secret_value: &'static str,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            servers: "\"fs\"",
            path_args: "\"path?\", \"paths[]?\"",
            secret_key: None,
            secret_value: "x",
        }
    }
}

pub(super) struct Routes {
    pub(super) dir: tempfile::TempDir,
    pub(super) gateway: Gateway,
    pub(super) meta: Arc<MetaMcp>,
    pub(super) state: Arc<AppState>,
    log: PathBuf,
    _store: tempfile::TempDir,
}

impl Routes {
    /// A gateway with backend `fs` (the peer), `read_file` surfaced on
    /// `/mcp`, and a block root rule on `read_*` over `<dir>/safe`.
    pub(super) async fn new() -> Self {
        Self::build(Setup::default()).await
    }

    pub(super) async fn build(setup: Setup) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["safe", "outside"] {
            std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }
        let log = dir.path().join("calls.log");
        let script = dir.path().join("peer.sh");
        let peer = PEER.replace("__LOG__", &log.to_string_lossy());
        std::fs::write(&script, peer).expect("write the peer");
        let secrets = setup.secret_key.map_or_else(String::new, |key| {
            format!(
                "    secrets:\n      - name: fs_token\n        credential_type: api_key\n        \
                 value: \"{}\"\n        inject_as: argument\n        inject_key: {key}\n        \
                 tools: [\"*\"]\n",
                setup.secret_value
            )
        });
        let yaml = format!(
            "backends:\n  fs:\n    command: \"sh {script}\"\n{secrets}meta_mcp:\n  \
             surfaced_tools:\n    - {{server: fs, tool: read_file}}\nsecurity:\n  firewall:\n    \
             enabled: true\n    audit_log: \"{audit}\"\n    rules:\n      - {{match: \"read_*\", \
             servers: [{servers}], action: block, allowed_roots: [\"{safe}\"], path_args: \
             [{args}]}}\n",
            script = script.display(),
            audit = dir.path().join("audit.ndjson").display(),
            servers = setup.servers,
            safe = dir.path().join("safe").display(),
            args = setup.path_args,
        );
        let path = dir.path().join("gateway.yaml");
        crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
        let config = crate::config::Config::load(Some(&path)).expect("the config loads");
        let gateway = Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
        let meta = gateway
            .build_meta_mcp()
            .await
            .expect("meta-MCP builds")
            .meta_mcp;
        let firewall = gateway.response_firewall(&meta);
        let (mut state, store) = crate::gateway::router::tests::direct_route_state_with_identity(
            crate::config::AgentIdentityConfig::default(),
        )
        .await;
        let wired = Arc::get_mut(&mut state).expect("the fixture state is not shared yet");
        wired.backends = Arc::clone(&gateway.backends);
        wired.continuation = meta.continuation();
        wired.meta_mcp = Arc::clone(&meta);
        wired.firewall = Some(firewall);
        Self {
            dir,
            gateway,
            meta,
            state,
            log,
            _store: store,
        }
    }

    /// The absolute spelling of `rel` under the tree.
    pub(super) fn path(&self, rel: &str) -> String {
        self.dir.path().join(rel).to_string_lossy().into_owned()
    }

    /// Every `tools/call` line the backend has received.
    pub(super) fn received(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Every audit row the production firewalls wrote.
    pub(super) fn audited(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.ndjson")).unwrap_or_default()
    }

    /// One JSON-RPC `method` call on `uri` through the router.
    pub(super) async fn post(&self, uri: &str, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request");
        let response = create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("the router answers");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&bytes);
        // A streamable-HTTP answer may come as one server-sent event: the
        // JSON-RPC message is its `data:` line.
        let message = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap_or(&text);
        serde_json::from_str(message).unwrap_or_else(|_| json!({"raw": text}))
    }
}
