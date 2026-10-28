// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Drivers for the response-stage matrix (MIK-8689): one real `/mcp` or
//! `/mcp/alpha` call on the router fixture, with the HMAC receipt and the
//! public seal both installed. Each returns the delivered JSON-RPC body; the
//! matrix (`route_check_matrix_tests::response`) owns every assertion.

use std::sync::Arc;

use serde_json::{Value, json};

use super::super::direct_guards_fixture::{self as fixture, Answer, post_direct, post_meta_invoke};
use super::{modern_call, surfacing};
use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::meta::Era;
use crate::trust::provenance_public::{ProvenancePublicSigner, TrustSet};

/// The backend answers the rows choose from.
pub(crate) use super::super::direct_guards_fixture::Answer as BackendAnswer;

/// The public seal's test seed and key id (as `provenance_delivery_tests`).
const SEED: [u8; 32] = [7u8; 32];
const KID: &str = "prov-test-1";

/// Both provenance signers on `meta`, `alpha`'s `read` surfaced by name so an
/// `/mcp` call delivers the backend's own envelope (Native) as the result.
fn dual_signed(meta: MetaMcp) -> MetaMcp {
    let mut meta = surfacing(meta);
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(SEED, KID));
    meta
}

/// The trust set holding the seal's public key.
pub(crate) fn trust_set() -> TrustSet {
    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, KID);
    let jwk = serde_json::to_string(&signer.public_jwk()).expect("the jwk serializes");
    TrustSet::from_json(&jwk).expect("the trust set loads")
}

/// The route an HTTP response row drives.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HttpRoute {
    /// `tools/call read` on `/mcp` (the surfaced name).
    Mcp,
    /// `tools/call read` on `/mcp/alpha`.
    Direct,
}

impl HttpRoute {
    fn uri(self) -> &'static str {
        match self {
            Self::Mcp => "/mcp",
            Self::Direct => "/mcp/alpha",
        }
    }
}

/// `tools/call read` on `route` as a caller of `era` declares it.
async fn call_read(fx: &fixture::Fx, route: HttpRoute, era: Era) -> Value {
    match era {
        Era::Modern => modern_call(fx, route.uri(), ("read", json!({})), &json!({})).await,
        Era::Legacy => {
            let params = json!({ "name": "read", "arguments": {} });
            fixture::send(fx, route.uri(), "k-std", "tools/call", params, None)
                .await
                .1
        }
    }
}

/// One `read` call on `route` in `era`, the backend answering `answer`.
pub(crate) async fn signed_call(route: HttpRoute, era: Era, answer: Answer) -> Value {
    let fx = fixture::fixture_built(answer, dual_signed).await;
    call_read(&fx, route, era).await
}

/// One legacy keyed call (`r1`) on `route`. Mcp goes through
/// `gateway_invoke`, the route a key is honoured on.
async fn keyed_call(fx: &fixture::Fx, route: HttpRoute) -> Value {
    match route {
        HttpRoute::Mcp => {
            post_meta_invoke(fx, "k-std", "alpha", "read", json!({}), Some("r1"), None)
                .await
                .1
        }
        HttpRoute::Direct => {
            post_direct(fx, "alpha", "k-std", "read", json!({}), Some("r1"), None)
                .await
                .1
        }
    }
}

/// Two keyed calls on one fixture: the first runs, the second is the replay.
/// Returns (first, replay, backend `tools/call` count).
pub(crate) async fn signed_replay(route: HttpRoute, answer: Answer) -> (Value, Value, usize) {
    let fx = fixture::fixture_built(answer, dual_signed).await;
    let first = keyed_call(&fx, route).await;
    let replay = keyed_call(&fx, route).await;
    (
        first,
        replay,
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
    )
}

/// A keyed `gateway_invoke` of `read` (`r1`) on `/mcp` declared modern:
/// the protocol version and the key in one `_meta`.
async fn modern_keyed_invoke(fx: &fixture::Fx) -> Value {
    let invoke = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let meta = json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "r1",
    }});
    modern_call(fx, "/mcp", ("gateway_invoke", invoke), &meta).await
}

/// Two calls with one key on `/mcp`: a legacy call stores the answer, then a
/// modern call with the same key (refused since MIK-8747). Returns (first, second,
/// backend `tools/call` count).
pub(crate) async fn signed_legacy_then_modern_replay(answer: Answer) -> (Value, Value, usize) {
    let fx = fixture::fixture_built(answer, dual_signed).await;
    let first = keyed_call(&fx, HttpRoute::Mcp).await;
    let second = modern_keyed_invoke(&fx).await;
    (
        first,
        second,
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
    )
}

/// The egress matrix's planted credential, which a Warn rule on `read`
/// redacts in a delivered answer (MIK-8155).
pub(crate) fn planted_credential() -> &'static str {
    // Leaked once per test that asks: `Answer::Text` holds a `'static` text.
    Box::leak(crate::gateway::egress_fixture::secret().into_boxed_str())
}

/// One `read` call on `route` in `era` whose backend answers `text`, under a
/// Warn rule on `read`: the egress firewall redacts a credential and still
/// delivers the answer.
pub(crate) async fn signed_redacted_call(route: HttpRoute, era: Era, text: &'static str) -> Value {
    let fx = fixture::fixture_firewalled_with_built(
        Answer::Text(text),
        Some(crate::security::firewall::FirewallAction::Warn),
        dual_signed,
    )
    .await;
    call_read(&fx, route, era).await
}

/// One message-signed call and the delivery rows the gateway wrote for it.
pub(crate) struct Recorded {
    /// The delivered JSON-RPC body.
    pub(crate) body: Value,
    /// The log's `response_delivery_attempt` rows.
    pub(crate) rows: Vec<Value>,
    /// Every row in the log, in order, read once the delivery rows landed.
    pub(crate) entries: Vec<Value>,
    _dir: tempfile::TempDir,
}

/// One hardened, message-signed `read` on `route` (modern, nonce `n1`), with
/// both provenance signers on and one transparency log shared by the
/// `MetaMcp` and the state, as the server wires it.
pub(crate) async fn signed_recorded_call(route: HttpRoute) -> Recorded {
    signed_recorded_answer(route, Answer::Ok).await
}

/// [`signed_recorded_call`] with the backend answering `answer`.
pub(crate) async fn signed_recorded_answer(route: HttpRoute, answer: Answer) -> Recorded {
    let (dir, log) = temp_log(None);
    let meta_log = Arc::clone(&log);
    let fx = fixture::fixture_hardened_signed_logged(answer, Arc::clone(&log), move |meta| {
        let mut meta = dual_signed(meta);
        meta.enable_transparency_log(meta_log);
        meta
    })
    .await;
    let body = match route {
        HttpRoute::Mcp => super::signed_invoke(&fx, "k-std", "n1", json!({})).await,
        HttpRoute::Direct => {
            super::super::direct_continuation_tests::signed_call(
                &fx,
                ("k-std", "alpha"),
                "n1",
                json!({}),
            )
            .await
            .1
        }
    };
    let rows = delivery_rows(&log).await;
    let entries = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    Recorded {
        body,
        rows,
        entries,
        _dir: dir,
    }
}

/// One `read` on `route` (modern) under the firewall with `rule` on `read`,
/// the backend answering `answer`, with one transparency log shared by the
/// `MetaMcp` and the state.
pub(crate) async fn firewalled_recorded_call(
    route: HttpRoute,
    answer: Answer,
    rule: Option<crate::security::firewall::FirewallAction>,
) -> Recorded {
    let (dir, log) = temp_log(None);
    let meta_log = Arc::clone(&log);
    let fx = fixture::fixture_firewalled_logged(answer, rule, Arc::clone(&log), move |mut meta| {
        meta.enable_transparency_log(meta_log);
        meta
    })
    .await;
    // `read` is not surfaced here, so the meta route invokes it by name.
    let body = match route {
        HttpRoute::Mcp => {
            fixture::post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), None, None)
                .await
                .1
        }
        HttpRoute::Direct => call_read(&fx, route, Era::Modern).await,
    };
    let rows = delivery_rows(&log).await;
    let entries = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    Recorded {
        body,
        rows,
        entries,
        _dir: dir,
    }
}

/// A transparency log in a fresh directory, under `policy` when one is given
/// (otherwise the logger's own default).
pub(crate) fn temp_log(
    policy: Option<crate::security::audit::AuditFailurePolicy>,
) -> (tempfile::TempDir, Arc<crate::security::TransparencyLogger>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "resp".to_string(),
        ..crate::security::transparency_log::TransparencyLogConfig::default()
    };
    let log = crate::security::TransparencyLogger::open(Arc::new(config)).expect("the log opens");
    let log = match policy {
        Some(policy) => log.with_failure_policy(policy),
        None => log,
    };
    (dir, Arc::new(log))
}

/// `log`'s `response_delivery_attempt` rows, once nothing is in flight.
pub(crate) async fn delivery_rows(log: &crate::security::TransparencyLogger) -> Vec<Value> {
    // Real time only as a hang guard: the append is out once nothing is in flight.
    let guard = std::time::Instant::now();
    while log.write_in_flight_for_test() {
        assert!(
            guard.elapsed() < std::time::Duration::from_secs(60),
            "the delivery record never landed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "response_delivery_attempt")
        .collect()
}

/// A signed read of a backend text, then a relayed send of that text.
pub(crate) struct ReadThenRelay {
    /// The read as delivered.
    pub(crate) read: Value,
    /// `k-budget` sending the read's text to `alpha` under nonce `b1`.
    pub(crate) relayed: Value,
    _dir: tempfile::TempDir,
}

/// On the signed, relayed fixture whose backend answers `text`, with a
/// fail-closed transparency log: `k-std` reads on `/mcp` (nonce `a1`), its
/// delivery record failing when `record_fails`, then `k-budget` sends the
/// text on `/mcp`. A relay refusal (-32002) means the read's receipt was
/// committed as delivered backend text. (The direct twin is
/// `collusion_direct_tests::verdict::a_read_record_failure_leaves_no_direct_receipt`.)
pub(crate) async fn read_then_relay(text: &'static str, record_fails: bool) -> ReadThenRelay {
    let (dir, log) = temp_log(Some(crate::security::audit::AuditFailurePolicy::FailClosed));
    let meta_log = Arc::clone(&log);
    let fx = fixture::fixture_signed_relayed_logged(
        Answer::Text(text),
        Arc::clone(&log),
        move |mut meta| {
            meta.enable_transparency_log(meta_log);
            meta
        },
    )
    .await;
    if record_fails {
        log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    }
    let read = super::signed_invoke(&fx, "k-std", "a1", json!({})).await;
    let relayed =
        super::signed_invoke_on(&fx, ("k-budget", "alpha"), "b1", json!({ "cmd": text })).await;
    ReadThenRelay {
        read,
        relayed,
        _dir: dir,
    }
}

/// Backend prose the gateway delivers, past the collusion detector's
/// 48-character floor, so a receipted copy is caught when relayed.
pub(crate) const DELIVERED_PROSE: &str =
    "Harbour dues for the winter quarter rise by four percent across every berth class.";

/// Backend text in its own `_meta` `serverInfo`, which the shaper overwrites
/// with the gateway's on a modern answer after the receipt is first staged,
/// so the client never receives it.
pub(crate) const STUFFED_INFO: &str =
    "Undelivered stuffing: the backend hid this sentence in the serverInfo the gateway stamps.";

/// A Native result carrying [`DELIVERED_PROSE`] as its text and
/// [`STUFFED_INFO`] as its own `serverInfo` name.
fn stuffed_info() -> Value {
    json!({"content": [{"type": "text", "text": DELIVERED_PROSE}], "isError": false,
           "_meta": {"io.modelcontextprotocol/serverInfo": {"name": STUFFED_INFO}}})
}

/// A Native result carrying [`DELIVERED_PROSE`] as its text.
fn prose_only() -> Value {
    json!({"content": [{"type": "text", "text": DELIVERED_PROSE}], "isError": false})
}

/// What the second relayed send carries.
#[derive(Clone, Copy)]
enum Relayed {
    /// This text.
    Text(&'static str),
    /// The `sig` of the gateway's own message signature on the read.
    OwnSignature,
}

/// What a read followed by two relayed sends saw.
pub(crate) struct Rebuilt {
    /// The read as delivered.
    pub(crate) read: Value,
    /// `k-budget` sending [`DELIVERED_PROSE`].
    pub(crate) prose: Value,
    /// `k-budget` sending the stuffed text.
    pub(crate) stuffing: Value,
}

/// On the signed, relayed fixture with `alpha`'s `read` surfaced, the backend
/// answering [`stuffed_info`]: `k-std` reads on `route` (a modern call, as
/// the hardened posture requires; on `/mcp` by the surfaced name, so the
/// backend envelope is the result), then `k-budget`
/// sends the delivered prose and the stuffing on the same route. The relay
/// receipt is rebuilt from the delivered bytes, so only the prose is caught.
pub(crate) async fn read_then_relay_rebuilt(route: HttpRoute) -> Rebuilt {
    read_then_relay_stuffed(route, stuffed_info, Relayed::Text(STUFFED_INFO)).await
}

/// [`read_then_relay_rebuilt`] with the backend answering [`prose_only`]:
/// the second send carries the `sig` of the gateway's own signature on the
/// read (R-OWNSIG).
pub(crate) async fn read_then_relay_own_signature(route: HttpRoute) -> Rebuilt {
    read_then_relay_stuffed(route, prose_only, Relayed::OwnSignature).await
}

/// The signed, relayed read of `answer`, then `k-budget` sending the
/// delivered prose and `stuffed`.
async fn read_then_relay_stuffed(
    route: HttpRoute,
    answer: fn() -> Value,
    relayed: Relayed,
) -> Rebuilt {
    let (_dir, log) = temp_log(None);
    let fx = fixture::fixture_signed_relayed_logged(Answer::Built(answer), log, surfacing).await;
    let read = match route {
        HttpRoute::Mcp => modern_call(&fx, "/mcp", ("read", json!({})), &json!({})).await,
        HttpRoute::Direct => {
            super::super::direct_continuation_tests::signed_call(
                &fx,
                ("k-std", "alpha"),
                "a1",
                json!({}),
            )
            .await
            .1
        }
    };
    let send = |nonce: &'static str, text: &'static str| {
        let fx = &fx;
        async move {
            match route {
                HttpRoute::Mcp => {
                    super::signed_invoke_on(
                        fx,
                        ("k-budget", "alpha"),
                        nonce,
                        json!({ "cmd": text }),
                    )
                    .await
                }
                HttpRoute::Direct => {
                    super::super::direct_continuation_tests::signed_call(
                        fx,
                        ("k-budget", "alpha"),
                        nonce,
                        json!({ "arguments": { "cmd": text } }),
                    )
                    .await
                    .1
                }
            }
        }
    };
    let prose = send("b1", DELIVERED_PROSE).await;
    let stuffed = match relayed {
        Relayed::Text(text) => text,
        // Leaked once per test that asks, as `planted_credential` is.
        Relayed::OwnSignature => Box::leak(
            read.pointer("/result/_signature/sig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("the read carries the gateway's signature: {read}"))
                .to_owned()
                .into_boxed_str(),
        ),
    };
    let stuffing = send("b2", stuffed).await;
    Rebuilt {
        read,
        prose,
        stuffing,
    }
}

/// A final `resources/read` answer claiming `cacheScope: "public"`: the one
/// kind of answer a backend may still send the member on, so the clamp has
/// something to change.
fn public_read() -> Value {
    json!({"contents": [{"uri": "file:///notes.txt", "text": "notes"}], "cacheScope": "public"})
}

/// One legacy `resources/read` on the direct route, the backend answering
/// [`public_read`].
pub(crate) async fn direct_public_read() -> Value {
    let fx = fixture::fixture_built(Answer::Built(public_read), |meta| meta).await;
    let params = json!({ "uri": "file:///notes.txt" });
    fixture::send(
        &fx,
        HttpRoute::Direct.uri(),
        "k-std",
        "resources/read",
        params,
        None,
    )
    .await
    .1
}

/// The reviewed Node verifier's verdict on a delivered, message-signed body
/// (`tests/common/signing_verifier.mjs`, independent of the Rust signer).
/// A process failure is not a rejection.
// Spawned as signing_delivery_tests.rs does; MIK-8738 moves both lib suites to one oracle.
pub(crate) fn node_verifies(body: &Value, nonce: &str) -> Result<Value, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let now = crate::clock::unix_secs().expect("clock after epoch");
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let input = json!({"wire": body.to_string(), "options": {
        "key": fixture::SIGNING_KEY, "keyId": "hardened",
        "expectedId": {"kind": "number", "value": id.to_string()},
        "expectedNonce": nonce, "now": now
    }});
    let mut child = Command::new("node")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/common/signing_verifier.mjs"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Node verifier must be installed");
    child
        .stdin
        .take()
        .expect("the verifier's stdin")
        .write_all(&serde_json::to_vec(&input).expect("the input serializes"))
        .expect("the verifier reads its input");
    let output = child.wait_with_output().expect("the verifier exits");
    match output.status.code() {
        Some(0) => Ok(serde_json::from_slice(&output.stdout).expect("verified diagnostic JSON")),
        Some(1) => Err(String::from_utf8_lossy(&output.stderr).into_owned()),
        code => panic!(
            "Node verifier infrastructure failure {code:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}
