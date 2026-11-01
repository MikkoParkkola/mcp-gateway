// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 rows on stdio (test plan v3): a tool stdio's tool policy denies
//! answers exactly as the same name does where the backend's catalogue lacks
//! it, on `gateway_invoke`, `gateway_execute` and the surfaced name, clean or
//! firewall-tripping.
//!
//! The same name across two fixtures (v2 item 2): the withheld twin's policy
//! denies `read` over a catalogue holding it; the absent twin's policy
//! denies only `other` over the same catalogue without `read`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, Fixture, dispatch, fixture_on_with};

const TOOL: &str = "read";
const SIBLING: &str = "note";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Withheld,
    Absent,
}

/// Why the withheld twin cannot see [`TOOL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    /// stdio's tool policy denies it.
    Policy,
    /// Its input schema is structurally invalid (ORACLE.5).
    Schema,
    /// Its description failed the poisoning check.
    Descriptor,
    /// The session's routing profile denies it.
    Profile,
}

#[derive(Clone, Copy, Debug)]
enum Entry {
    Invoke,
    Execute,
    Surfaced,
}

/// A loopback backend serving the side's catalogue, counting `tools/call`s.
async fn serve(holds: bool, reason: Reason) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let mut tools = vec![json!({"name": SIBLING, "inputSchema": {"type": "object"}})];
    if holds {
        let schema = if reason == Reason::Schema {
            json!({"type": "array"})
        } else {
            json!({"type": "object"})
        };
        tools.push(json!({"name": TOOL, "description": "Reads a record.", "inputSchema": schema}));
    }
    let tools = Value::Array(tools);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let tools = tools.clone();
            async move {
                let result = match request["method"].as_str() {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": tools}),
                    Some("tools/call") => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        json!({"content": [{"type": "text", "text": "ok"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let address = listener.local_addr().expect("backend address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), calls)
}

struct Twin {
    fixture: Fixture,
    calls: Arc<AtomicUsize>,
}

/// Build `side`'s stdio twin, warm, with [`TOOL`] surfaced unless this is a
/// surfaced row's absent twin (which maps the name to no backend).
async fn twin(side: Side, reason: Reason, surface_tool: bool) -> Twin {
    let (url, calls) = serve(side == Side::Withheld, reason).await;
    let denied = match (reason, side) {
        (Reason::Policy, Side::Withheld) => TOOL,
        _ => "other",
    };
    let policy = crate::security::ToolPolicyConfig {
        deny: vec![denied.to_string()],
        ..crate::security::ToolPolicyConfig::default()
    };
    let surfaced = [SIBLING, TOOL]
        .into_iter()
        .filter(|tool| surface_tool || *tool != TOOL)
        .map(|tool| crate::config::SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: tool.to_string(),
        })
        .collect::<Vec<_>>();
    // A profile twin's profile denies the name on the withheld side and
    // another name on the absent side, as the policy twin's policy does.
    let profiled = match (reason, side) {
        (Reason::Profile, Side::Withheld) => Some(TOOL),
        (Reason::Profile, Side::Absent) => Some("other"),
        _ => None,
    };
    let fixture = Box::pin(fixture_on_with(
        (url, Arc::clone(&calls)),
        Some(policy),
        |config| {
            config.meta_mcp.surfaced_tools = surfaced;
            if let Some(denied) = profiled {
                config.routing_profiles.insert(
                    "restricted".to_string(),
                    crate::routing_profile::RoutingProfileConfig {
                        deny_tools: Some(vec![denied.to_string()]),
                        ..Default::default()
                    },
                );
                config.default_routing_profile = "restricted".to_string();
            }
        },
    ))
    .await;
    let backend = fixture
        .meta
        .backends
        .for_test()
        .get(BACKEND)
        .expect("backend");
    backend
        .get_tools_shared()
        .await
        .expect("warm the catalogue");
    // v2 item 2: the withheld twin's catalogue holds the name, the absent
    // twin's lacks it.
    let cached = backend.get_cached_tool(TOOL);
    assert_eq!(
        cached.is_some(),
        side == Side::Withheld,
        "premise: {side:?} catalogue"
    );
    if let Some(cached) = cached {
        assert_eq!(
            crate::capability::validator::input_schema_is_structurally_valid(&cached.input_schema),
            reason != Reason::Schema,
            "premise: schema validity"
        );
    }
    // Blocked after the premise: blocking drops the cached entry.
    if (reason, side) == (Reason::Descriptor, Side::Withheld) {
        backend.block_tool_for_test(TOOL);
    }
    Twin { fixture, calls }
}

impl Twin {
    /// Call [`TOOL`] on `entry` with `args`: the body without `id`, and the
    /// backend's sends.
    async fn call(&self, entry: Entry, args: &Value) -> (Value, usize) {
        let params = match entry {
            Entry::Invoke => json!({"name": "gateway_invoke", "arguments":
                {"server": BACKEND, "tool": TOOL, "arguments": args}}),
            Entry::Execute => json!({"name": "gateway_execute", "arguments": {"chain": [
                {"tool": format!("{BACKEND}:{TOOL}"), "arguments": args}
            ]}}),
            Entry::Surfaced => json!({"name": TOOL, "arguments": args}),
        };
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let mut body = dispatch(&self.fixture, request).await;
        if let Some(obj) = body.as_object_mut() {
            obj.remove("id");
        }
        (body, self.calls.load(Ordering::SeqCst))
    }
}

/// ORACLE.2 / ORACLE.5 on stdio, policy, schema, descriptor and profile
/// reasons: every entry,
/// clean and tripping; a schema-withheld tool is never sent. RED on
/// base for the entries that name a backend; the surfaced name is MIK-8340's
/// (green on base, mutant MS1).
#[tokio::test]
async fn oracle2_stdio_policy_answers_as_the_missing_name() {
    let cmd = [";", " rm", " -rf", " / "].concat();
    let tripping = json!({ "cmd": cmd });
    let mut cells = Vec::new();
    for reason in [
        Reason::Policy,
        Reason::Schema,
        Reason::Descriptor,
        Reason::Profile,
    ] {
        for entry in [Entry::Invoke, Entry::Execute, Entry::Surfaced] {
            for (label, args) in [("clean", json!({})), ("tripping", tripping.clone())] {
                let surfaced = matches!(entry, Entry::Surfaced);
                let withheld = twin(Side::Withheld, reason, true).await;
                let (withheld, sent) = withheld.call(entry, &args).await;
                let absent = twin(Side::Absent, reason, !surfaced).await;
                let (absent, _) = absent.call(entry, &args).await;
                if withheld != absent || sent != 0 {
                    cells.push(format!(
                        "stdio {reason:?} {entry:?}/{label}: withheld {withheld} (sends {sent}) vs absent {absent}"
                    ));
                }
            }
        }
    }
    assert!(cells.is_empty(), "ORACLE.2 stdio:\n{}", cells.join("\n"));
}

/// A personal capability with no grant on the stdio twin, defined or not,
/// called through `entry`.
async fn capability_call(defined: bool, entry: Entry) -> Value {
    const CAPS: &str = "caps";
    const CAP: &str = "hook_or_day";
    let twin = twin(Side::Absent, Reason::Policy, true).await;
    let caps = Arc::new(crate::capability::CapabilityBackend::new(
        CAPS,
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    if defined {
        let metadata = "  exposure: personal\n  read_only: true\n  identity_owner:\n    authority: api_key\n    subject: alice\n";
        let definition = format!(
            "name: {CAP}\ndescription: A fixture capability\nmetadata:\n{metadata}\
             providers:\n  primary:\n    service: rest\n    config:\n      \
             base_url: http://127.0.0.1:9\n      path: /x\n      method: POST\n"
        );
        let parsed = crate::capability::parse_capability(&definition).expect("parses");
        caps.register_capability(parsed).expect("registers");
    }
    twin.fixture.meta.set_identity_grants(
        crate::identity_grants::LocalIdentityGrantStore::from_grants(Vec::new()),
    );
    twin.fixture.meta.set_capabilities(caps);
    let params = match entry {
        Entry::Execute => json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{CAPS}:{CAP}"), "arguments": {}}
        ]}}),
        _ => json!({"name": "gateway_invoke", "arguments":
            {"server": CAPS, "tool": CAP, "arguments": {}}}),
    };
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
    let mut body = dispatch(&twin.fixture, request).await;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("id");
    }
    body
}

/// ORACLE.2 on stdio for capabilities (#3872 test review, item 3): a personal
/// capability with no grant answers byte for byte as the undefined
/// capability, on `gateway_invoke` and `gateway_execute`. The admin rule has
/// no stdio case: stdio's caller is admin, so an admin-only capability is
/// visible to it and dispatched (measured: it reached the provider).
#[tokio::test]
async fn oracle2_stdio_capability_answers_as_the_undefined_one() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Execute] {
        let defined = capability_call(true, entry).await;
        let undefined = capability_call(false, entry).await;
        if defined.get("error").is_none() && defined.pointer("/result/isError").is_none() {
            cells.push(format!("{entry:?}: premise: not refused: {defined}"));
        }
        if defined != undefined {
            cells.push(format!(
                "{entry:?}: defined {defined} vs undefined {undefined}"
            ));
        }
    }
    assert!(
        cells.is_empty(),
        "ORACLE.2 stdio capability:\n{}",
        cells.join("\n")
    );
}

/// #3872 review (FIX 1, condition 4) on stdio: a keyed chain `[note, read]`
/// sent twice with the same key replays the first run. `read` hidden by the
/// tool policy was answered as missing and never ran, so the replay is the
/// stored answer, exactly as the missing twin's replay is; nothing is sent
/// for `read`.
#[tokio::test]
async fn a5r_stdio_a_replayed_keyed_chain_answers_as_one_with_a_missing_step() {
    let mut replays = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let twin = twin(side, Reason::Policy, true).await;
        let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{BACKEND}:{SIBLING}"), "arguments": {}},
            {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}}
        ]}}});
        request["params"]["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("a5r");
        dispatch(&twin.fixture, request.clone()).await;
        let mut replay = dispatch(&twin.fixture, request).await;
        if let Some(obj) = replay.as_object_mut() {
            obj.remove("id");
        }
        replays.push((replay, twin.calls.load(Ordering::SeqCst)));
    }
    assert_eq!(
        replays[0], replays[1],
        "stdio A5 replay: withheld vs missing"
    );
}
