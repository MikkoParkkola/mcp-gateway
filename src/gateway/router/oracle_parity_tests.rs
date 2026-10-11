// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 rows on `/mcp` and the direct route (test plan v3): a tool the
//! caller's policy hides answers exactly as the same name does where the
//! backend's catalogue lacks it, on every entry, with clean and
//! firewall-tripping arguments, in every catalogue state.
//!
//! Each pair asks for the SAME name across two fixtures (v2 item 2): the
//! withheld twin is `k-deny` (denied `read`) over a catalogue holding `read`;
//! the absent twin is `k-deny-x` (denied only `other`) over the same
//! catalogue without `read`. Each twin asserts its premise first.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Fx, fixture_audited_built_on, post_direct, post_meta_invoke, send,
};
use crate::backend::Backend;
use crate::config::{BackendConfig, InputSchemaEnforcement, SurfacedToolConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The name every pair asks for.
const TOOL: &str = "read";
/// The backend both twins call.
const SERVER: &str = "alpha";
/// A sibling the catalogue always holds, so it is never empty.
const SIBLING: &str = "note";

/// Which twin of a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// `k-deny` over a catalogue holding [`TOOL`].
    Withheld,
    /// `k-deny-x` over a catalogue lacking [`TOOL`].
    Absent,
}

impl Side {
    const fn key(self) -> &'static str {
        match self {
            Self::Withheld => "k-deny",
            Self::Absent => "k-deny-x",
        }
    }
}

/// What the backend's `tools/list` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    /// One complete page.
    Complete,
    /// A fresh cursor on every page: the drain stops at the page cap.
    Truncated,
    /// Every list fails on transport.
    Fails,
}

/// One catalogue state for a pair.
#[derive(Clone, Copy, Debug)]
struct State {
    list: List,
    mode: InputSchemaEnforcement,
    /// Whether the shared slot is filled before the call.
    warm: bool,
}

impl State {
    const WARM: Self = Self {
        list: List::Complete,
        mode: InputSchemaEnforcement::Closed,
        warm: true,
    };
}

/// A backend serving a scripted catalogue, counting lists and calls.
struct Scripted {
    holds: bool,
    list: List,
    calls: Arc<AtomicUsize>,
    lists: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Scripted {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let body = match method {
            "tools/list" => {
                self.lists.fetch_add(1, Ordering::SeqCst);
                let cursor = params
                    .as_ref()
                    .and_then(|p| p.get("cursor"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let mut tools = vec![json!({"name": SIBLING, "inputSchema": {"type": "object"}})];
                // The tool sits on the first page only.
                if self.holds && cursor.is_none() {
                    tools.push(json!({"name": TOOL, "description": "Reads a record.",
                        "inputSchema": {"type": "object"}}));
                }
                match self.list {
                    List::Complete => json!({ "tools": tools }),
                    List::Truncated => {
                        let page = self.lists.load(Ordering::SeqCst);
                        json!({ "tools": tools, "nextCursor": format!("p{page}") })
                    }
                    List::Fails => {
                        return Err(crate::Error::Transport("scripted list failure".into()));
                    }
                }
            }
            _ => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
            }
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// One built twin.
struct Twin {
    fx: Fx,
    side: Side,
    calls: Arc<AtomicUsize>,
    lists: Arc<AtomicUsize>,
    audit: PathBuf,
    _dir: tempfile::TempDir,
}

/// What one call answered: status, body without `id`, and the backend's
/// sends and lists so far.
#[derive(Debug)]
struct Answered {
    status: StatusCode,
    body: Value,
    calls: usize,
    lists: usize,
}

/// Build `side`'s twin in `state`, firewalled and audited, with [`TOOL`]
/// surfaced so the surfaced-name entry can be called too.
async fn twin(side: Side, state: State) -> Twin {
    twin_surfacing(side, state, true).await
}

/// [`twin`], surfacing [`TOOL`] only when `surface_tool`: a surfaced name's
/// absent twin maps to no backend (design r3 item 3).
async fn twin_surfacing(side: Side, state: State, surface_tool: bool) -> Twin {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let (calls, lists) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let scripted = || {
        Arc::new(Scripted {
            holds: side == Side::Withheld,
            list: state.list,
            calls: Arc::clone(&calls),
            lists: Arc::clone(&lists),
        })
    };
    let surfaced = [SIBLING, TOOL]
        .into_iter()
        .filter(|tool| surface_tool || *tool != TOOL)
        .map(|tool| SurfacedToolConfig {
            server: SERVER.to_string(),
            tool: tool.to_string(),
        })
        .collect::<Vec<_>>();
    let fx = fixture_audited_built_on(scripted(), audit.clone(), |meta| {
        meta.with_surfaced_tools(surfaced)
    })
    .await;
    // The state's enforcement mode, on a fresh `alpha` serving the same
    // script (a live reload's replacement, as `replace_backend` does).
    let backend = Arc::new(Backend::new(
        SERVER,
        BackendConfig {
            input_schema_enforcement: state.mode,
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(scripted());
    assert!(fx.state.backends.register(backend), "premise: replacement");
    if state.warm {
        let backend = fx.state.backends.get(SERVER).expect("alpha");
        let warmed = backend.get_tools_shared().await;
        assert!(
            warmed.is_ok() || state.list == List::Fails,
            "premise: warming failed: {warmed:?}"
        );
    }
    let twin = Twin {
        fx,
        side,
        calls,
        lists,
        audit,
        _dir: dir,
    };
    twin.assert_premise(state);
    twin
}

impl Twin {
    /// v2 item 2: the withheld twin's catalogue holds the name and its key's
    /// policy denies it; the absent twin's catalogue lacks it and its key's
    /// policy does not name it.
    fn assert_premise(&self, state: State) {
        let denied = self
            .fx
            .state
            .auth_config
            .api_keys
            .iter()
            .find(|k| k.name == self.side.key())
            .and_then(|k| k.denied_tools.clone())
            .unwrap_or_default();
        let named = denied.iter().any(|t| t == TOOL);
        assert_eq!(
            named,
            self.side == Side::Withheld,
            "premise: {:?} key denies {denied:?}",
            self.side
        );
        if state.warm && state.list == List::Complete {
            let backend = self.fx.state.backends.get(SERVER).expect("alpha");
            assert_eq!(
                backend.get_cached_tool(TOOL).is_some(),
                self.side == Side::Withheld,
                "premise: {:?} catalogue",
                self.side
            );
        }
    }

    fn answered(&self, status: StatusCode, mut body: Value) -> Answered {
        if let Some(obj) = body.as_object_mut() {
            obj.remove("id");
        }
        Answered {
            status,
            body,
            calls: self.calls.load(Ordering::SeqCst),
            lists: self.lists.load(Ordering::SeqCst),
        }
    }

    /// Call [`TOOL`] on `entry` with `args`.
    async fn call(&self, entry: Entry, args: Value) -> Answered {
        let key = self.side.key();
        let (status, body) = match entry {
            Entry::Invoke => post_meta_invoke(&self.fx, key, SERVER, TOOL, args, None, None).await,
            Entry::Direct => post_direct(&self.fx, SERVER, key, TOOL, args, None, None).await,
            Entry::Execute => {
                let params = json!({"name": "gateway_execute", "arguments": {"chain": [
                    {"tool": format!("{SERVER}:{TOOL}"), "arguments": args}
                ]}});
                send(&self.fx, "/mcp", key, "tools/call", params, None).await
            }
            Entry::Surfaced => {
                let params = json!({"name": TOOL, "arguments": args});
                send(&self.fx, "/mcp", key, "tools/call", params, None).await
            }
        };
        self.answered(status, body)
    }

    /// The audit rows of `event` this twin wrote.
    fn audit_rows(&self, event: &str) -> Vec<Value> {
        std::fs::read_to_string(&self.audit)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|row| row["event"] == event)
            .collect()
    }
}

/// Where a pair's call enters.
#[derive(Clone, Copy, Debug)]
enum Entry {
    /// `/mcp` `gateway_invoke`.
    Invoke,
    /// `/mcp` `gateway_execute`, one chain step.
    Execute,
    /// `/mcp` the surfaced name itself.
    Surfaced,
    /// `/mcp/alpha` `tools/call`.
    Direct,
}

/// A shell-injection argument the request firewall blocks, assembled at run
/// time (the probe's and the route check matrix's finding).
fn tripping() -> Value {
    let cmd = [";", " rm", " -rf", " / "].concat();
    json!({ "cmd": cmd })
}

/// The arguments a row runs with.
#[derive(Clone, Copy, Debug)]
enum Args {
    Clean,
    Tripping,
}

impl Args {
    fn value(self) -> Value {
        match self {
            Self::Clean => json!({}),
            Self::Tripping => tripping(),
        }
    }
}

/// One pair in `state`: the withheld and the absent twin's answers.
async fn pair(entry: Entry, args: Args, state: State) -> (Answered, Answered) {
    let surfaced = matches!(entry, Entry::Surfaced);
    let withheld = twin(Side::Withheld, state).await;
    let absent = twin_surfacing(Side::Absent, state, !surfaced).await;
    (
        withheld.call(entry, args.value()).await,
        absent.call(entry, args.value()).await,
    )
}

/// The cell's mismatch: status or body differ, or the withheld call reached
/// the backend.
fn mismatch(cell: &str, withheld: &Answered, absent: &Answered) -> Option<String> {
    let same = (withheld.status, &withheld.body) == (absent.status, &absent.body);
    (!same || withheld.calls != 0).then(|| {
        format!(
            "{cell}: withheld {} {} (sends {}) vs absent {} {}",
            withheld.status, withheld.body, withheld.calls, absent.status, absent.body
        )
    })
}

/// Fail with every collected cell, so a red run publishes each cell's answer.
fn assert_cells(row: &str, cells: &[String]) {
    assert!(cells.is_empty(), "{row}:\n{}", cells.join("\n"));
}

/// ORACLE.2, policy reason, the entries that name a backend: a denied tool
/// answers exactly as the missing name, clean or firewall-tripping, and is
/// never sent. RED on base (probe: 403 policy refusal vs absent / firewall).
#[tokio::test]
async fn oracle2_policy_backend_entries_answer_as_the_missing_name() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Execute, Entry::Direct] {
        for args in [Args::Clean, Args::Tripping] {
            let (withheld, absent) = pair(entry, args, State::WARM).await;
            cells.extend(mismatch(&format!("{entry:?}/{args:?}"), &withheld, &absent));
        }
    }
    assert_cells("ORACLE.2 policy", &cells);
}

/// ORACLE.2, the surfaced name: a denied surfaced tool and a name that maps
/// to no backend both answer `Unknown tool`, clean or tripping (MIK-8340
/// keeps this; green on base, mutant MS1).
#[tokio::test]
async fn oracle2_policy_surfaced_name_answers_as_an_unmapped_name() {
    let mut cells = Vec::new();
    for args in [Args::Clean, Args::Tripping] {
        let (withheld, absent) = pair(Entry::Surfaced, args, State::WARM).await;
        cells.extend(mismatch(&format!("Surfaced/{args:?}"), &withheld, &absent));
    }
    assert_cells("ORACLE.2 surfaced", &cells);
}

/// F1/F2: the firewall judges the withheld and the missing name alike. A
/// tripping call gets the same block (F1, in the ORACLE.2 row) and writes
/// the same request audit rows; a clean call is scanned and recorded alike
/// (its stateful controls are charged alike). RED on base: the denied call
/// stops at authorize and never reaches the firewall.
#[tokio::test]
async fn f2_the_firewall_records_both_names_alike() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        for args in [Args::Clean, Args::Tripping] {
            let withheld = twin(Side::Withheld, State::WARM).await;
            let absent = twin(Side::Absent, State::WARM).await;
            withheld.call(entry, args.value()).await;
            absent.call(entry, args.value()).await;
            let rows = |twin: &Twin| {
                twin.audit_rows("request")
                    .into_iter()
                    .filter(|row| row["tool"] == TOOL)
                    .map(|row| (row["action"].clone(), row["findings_count"].clone()))
                    .collect::<Vec<_>>()
            };
            let (w, a) = (rows(&withheld), rows(&absent));
            if w != a || a.is_empty() {
                cells.push(format!("{entry:?}/{args:?}: request rows withheld {w:?} vs absent {a:?}"));
            }
        }
    }
    assert_cells("F2", &cells);
}

/// The catalogue-state rows run on the two entries that name a backend
/// directly.
const STATE_ENTRIES: [Entry; 2] = [Entry::Invoke, Entry::Direct];

/// Every cell of `state` on [`STATE_ENTRIES`], clean arguments.
async fn state_cells(row: &str, state: State) -> Vec<(String, Answered, Answered)> {
    let mut out = Vec::new();
    for entry in STATE_ENTRIES {
        let (withheld, absent) = pair(entry, Args::Clean, state).await;
        out.push((format!("{row} {entry:?}"), withheld, absent));
    }
    out
}

/// S1, Standard with a complete fresh list: both get text A and the missing
/// name is not forwarded (the upgrading.d behaviour row). RED on base.
#[tokio::test]
async fn s1_standard_complete_answers_both_and_forwards_neither() {
    let state = State {
        mode: InputSchemaEnforcement::Standard,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S1", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
        if absent.calls != 0 {
            cells.push(format!("{cell}: the missing name was forwarded: {}", absent.body));
        }
    }
    assert_cells("S1", &cells);
}

/// S2, cold, filled at the gate: both answered after one list fetch each.
#[tokio::test]
async fn s2_cold_catalogue_fills_once_and_answers_both_alike() {
    let state = State {
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S2", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
        if withheld.lists != absent.lists || absent.lists != 1 {
            cells.push(format!(
                "{cell}: list fetches withheld {} vs absent {}",
                withheld.lists, absent.lists
            ));
        }
    }
    assert_cells("S2", &cells);
}

/// S3, Closed, the fill fails: both get the same backend-unavailable answer.
#[tokio::test]
async fn s3_failed_fill_closed_answers_both_alike() {
    let state = State {
        list: List::Fails,
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S3", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
    }
    assert_cells("S3", &cells);
}

/// S4, Closed, the list is truncated at the page cap: both get text P,
/// byte-identical.
#[tokio::test]
async fn s4_truncated_closed_answers_both_with_text_p() {
    let state = State {
        list: List::Truncated,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S4", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
    }
    assert_cells("S4", &cells);
}

/// The residual rows (S5, S6, S3b): the withheld name is never sent; the
/// missing name is forwarded (pinned, not parity).
async fn assert_residual(row: &str, state: State) {
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells(row, state).await {
        if withheld.calls != 0 {
            cells.push(format!("{cell}: the withheld name was sent: {}", withheld.body));
        }
        if absent.calls != 1 {
            cells.push(format!(
                "{cell}: the residual moved, missing name sends {}: {}",
                absent.calls, absent.body
            ));
        }
    }
    assert_cells(row, &cells);
}

/// S5, Standard, truncated: stated residual.
#[tokio::test]
async fn s5_truncated_standard_withholds_and_forwards_the_missing_name() {
    let state = State {
        list: List::Truncated,
        mode: InputSchemaEnforcement::Standard,
        ..State::WARM
    };
    assert_residual("S5", state).await;
}

/// S6, Off: stated residual.
#[tokio::test]
async fn s6_off_withholds_and_forwards_the_missing_name() {
    let state = State {
        mode: InputSchemaEnforcement::Off,
        ..State::WARM
    };
    assert_residual("S6", state).await;
}

/// S3b, Standard, the fill fails: stated residual.
#[tokio::test]
async fn s3b_failed_fill_standard_withholds_and_forwards_the_missing_name() {
    let state = State {
        list: List::Fails,
        mode: InputSchemaEnforcement::Standard,
        warm: false,
    };
    assert_residual("S3b", state).await;
}
