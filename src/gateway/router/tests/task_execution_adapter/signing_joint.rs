// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The joint seam: response signing, nonce replay defense, and the durable task
//! adapter on ONE request.
//!
//! Signing here is what the source implements and nothing else: the gateway
//! signs its own `gateway_invoke` **result** (`signing.rs:217`,
//! `message_signing_v2.rs:55`) and refuses a client nonce it has already seen
//! (`message_signing.rs:270`). Nothing below verifies an *incoming* signature,
//! because nothing in the tree produces or checks one.
//!
//! Every row drives the real `/mcp` route with the suite's own fixture, and
//! signing is turned on the way production turns it on — `enable_message_signing`
//! (`meta_mcp/mod.rs:723`) on the fixture's `MetaMcp` before the state is shared
//! with a router — so no row can pass against a hand-built admission or a
//! hand-built signer.
//!
//! Three oracles, and each row uses at least two of them:
//! * [`MockBackend::calls`] — a real injected transport, counted on arrival.
//! * [`durable_records`] — the task store's own directory, read only, through
//!   the `TempDir` the fixture already retains for the test's lifetime.
//! * the delivered body — `taskId`, and the `_signature` block the client sees.
//!
//! # What is expected to be red, and why
//!
//! Rows A and B are claims about wiring that exists. Row
//! [`joint_c_one_key_must_not_admit_both_a_task_and_a_sync_execution`] is a
//! claim about wiring that does not: `MetaMcp::build` mints its own
//! `ExecutionAdmission` (`meta_mcp/mod.rs:464`) and `open_runtime` mints a
//! second one for the task service (`task_service/mod.rs:70`), with no setter on
//! either to join them. So one verified principal and one explicit idempotency
//! key can be admitted by BOTH authorities — `Mode::Task` in one and
//! `Mode::Sync` in the other — and the `Refusal::Mismatch` that a single
//! authority would raise on the mode field (`idempotency/admission.rs:236`)
//! never happens. That row is written to the intended semantics and is expected
//! to fail until the two authorities become one; its control beside it proves
//! the fixture can still dispatch, so the failure cannot be read as a broken
//! fixture.
use super::super::*;
use super::support::*;

use crate::security::message_signing::MessageSigner;

/// A signing secret of production width (>= `MIN_SECRET_BYTES`), so the fixture
/// stands where `validate_secret` would let a deployment stand.
const SIGNING_SECRET: &[u8] = b"joint-signing-secret-that-is-at-least-32-bytes";

/// Echoed in every `_signature` block, so a row can tell the fixture's signer
/// from any other.
const SIGNING_KEY_ID: &str = "joint-signing-key";

/// Wide enough that no row's nonce can expire mid-test: a replay row that passed
/// because the window elapsed would be measuring the clock.
const REPLAY_WINDOW: Duration = Duration::from_secs(300);

/// The ceiling on every await in this file. A route that never answers, or a
/// worker that never dispatches, must FAIL the row rather than hang the binary.
const BOUND: Duration = Duration::from_secs(5);

// =====================================================================
// Fixture
// =====================================================================

/// The suite's state with response signing and nonce enforcement on.
///
/// `require_nonce` is `true`, which is the posture the whole file is about: with
/// it false a missing nonce is not an error and row A2 would have nothing to
/// observe.
///
/// The signer is installed through the production entry point, on the fixture's
/// own `MetaMcp`, BEFORE the state is handed to a router. Both `get_mut` calls
/// are the exclusivity check, not a convenience: at this point the `AppState`
/// has been shared with nobody (no request has downgraded it into an owned task
/// context) and its `MetaMcp` was moved in whole, so a failure here means the
/// fixture changed shape and the row must be re-read rather than patched.
async fn signed_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (mut state, store) = state_with(mock).await;
    {
        let app = Arc::get_mut(&mut state)
            .expect("the fixture state must still be exclusively owned before signing is enabled");
        let meta = Arc::get_mut(&mut app.meta_mcp)
            .expect("the fixture meta layer must still be exclusively owned");
        meta.enable_message_signing(
            MessageSigner::new(SIGNING_SECRET.to_vec(), None, SIGNING_KEY_ID.to_owned()),
            REPLAY_WINDOW,
            true,
        );
    }
    (state, store)
}

/// Put a signing nonce where the production wire carries it: beside `server` and
/// `tool` in the `gateway_invoke` envelope, which is the one place
/// `SigningInvocationContext::capture` reads (`signing.rs:53`) and the shape
/// `tests/message_signing_delivery.rs` drives the shipped binary with.
///
/// A `Value` rather than a `&str` on purpose: rows A1 needs the malformed
/// spellings — a number, an empty string, `null`, an over-long string — and a
/// helper that only accepted valid nonces could not build them.
fn with_nonce(mut body: Value, nonce: Value) -> Value {
    body["params"]["arguments"]["nonce"] = nonce;
    body
}

/// Every durable task record on disk, by file name, sorted.
///
/// Read-only, and through the `TempDir` the fixture already returns; nothing
/// here opens the store, takes its lease, or installs a hook. The name rule
/// mirrors the store's own (`task_service/store.rs:460`, `:464`): a record is
/// `task-<uuid>.json`, and the lease sidecar and any orphaned temp file are
/// deliberately not records.
///
/// A missing directory is a panic naming the path, not an empty list: "no
/// records" and "counting the wrong directory" must never look alike.
fn durable_records(store: &tempfile::TempDir) -> Vec<String> {
    let directory = store.path().join("tasks");
    let mut records: Vec<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| {
            panic!(
                "the fixture's retained task store must be readable at {}: {error}",
                directory.display()
            )
        })
        .map(|entry| {
            entry
                .expect("a task store directory entry reads")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("task-") && name.ends_with(".json"))
        .collect();
    records.sort();
    records
}

/// Bound one await. Panics — with what was being waited for — rather than
/// letting a wedged route stall the test binary.
async fn bounded<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(BOUND, work)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within {BOUND:?}"))
}

// =====================================================================
// Reading the signature
// =====================================================================

/// Assert the delivered `_signature` is this gateway's, over this delivery, and
/// return its MAC so a caller can compare two deliveries.
///
/// The MAC covers the result body, the typed request id, the nonce and the
/// timestamp (`message_signing_v2.rs:79`), so a MAC is evidence about one
/// delivery and not a value that may be carried between them.
fn assert_signed_for_nonce(body: &Value, nonce: &str) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let signature = body.pointer("/result/_signature").unwrap_or_else(|| {
        panic!("a successful external `gateway_invoke` result must be signed: {body}")
    });
    std::assert_eq!(
        signature.get("nonce"),
        Some(&json!(nonce)),
        "the signature is bound to the nonce THIS delivery admitted: {body}"
    );
    std::assert_eq!(
        signature.get("key_id"),
        Some(&json!(SIGNING_KEY_ID)),
        "signed by the fixture's own key, not by some other signer: {body}"
    );
    std::assert_eq!(
        signature.get("alg"),
        Some(&json!("hmac-sha256")),
        "the algorithm the delivered envelope names: {body}"
    );
    std::assert_eq!(
        signature.get("version"),
        Some(&json!(2)),
        "the v2 envelope, which is the one that binds the request id: {body}"
    );
    let mac = signature
        .get("sig")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a signature block carries a MAC: {body}"));
    assert!(
        mac.len() == 64
            && mac
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "a SHA-256 MAC is 64 lowercase hex characters: {body}"
    );
    let expected_id = match body.get("id") {
        Some(Value::String(value)) => json!({"kind": "string", "value": value}),
        Some(Value::Number(value)) => {
            json!({"kind": "number", "value": value.as_i64().expect("signed i64 id").to_string()})
        }
        Some(Value::Null) => Value::Null,
        _ => panic!("the delivered response must carry a typed request id: {body}"),
    };
    // This ECMAScript verifier independently removes only the top-level
    // signature, applies JCS, and recomputes HMAC over the delivered body,
    // typed wire id, nonce, timestamp, algorithm, version and key id.
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/signing_verifier.mjs");
    let input = json!({
        "wire": serde_json::to_string(body).expect("delivered response JSON"),
        "options": {
            "key": std::str::from_utf8(SIGNING_SECRET).expect("fixture UTF-8 key"),
            "keyId": SIGNING_KEY_ID,
            "expectedId": expected_id,
            "expectedNonce": nonce
        }
    });
    let mut verifier = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("independent Node verifier is required by the signing suite");
    verifier
        .stdin
        .take()
        .expect("verifier stdin")
        .write_all(&serde_json::to_vec(&input).expect("verifier input JSON"))
        .expect("write verifier input");
    let verified = verifier.wait_with_output().expect("wait for MAC verifier");
    assert!(
        verified.status.success(),
        "independent delivered MAC verification failed: {}: {body}",
        String::from_utf8_lossy(&verified.stderr)
    );
    mac.to_owned()
}

/// The `error/code` a refusal carries, or a failure naming the whole body.
fn error_code(body: &Value) -> i64 {
    body.pointer("/error/code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("this call must be refused, and it answered {body}"))
}

/// One successful signed task, dispatched and settled.
///
/// Used to prime the two oracles: after it, the backend counter is 1 and the
/// store holds exactly one record. A refusal row that starts from zero cannot
/// tell "nothing was written" from "nothing is ever written here".
async fn prime_one_settled_task(state: &Arc<AppState>, id: i64, key: &str, nonce: &str) -> String {
    let created = bounded(
        "the priming task create",
        post(
            state,
            "key-a",
            with_nonce(task_invoke(id, key, json!({ "q": "prime" })), json!(nonce)),
        ),
    )
    .await;
    let task = task_id(&created);
    let settled = bounded(
        "the priming task settling",
        poll_until_terminal(state, "key-a", &task),
    )
    .await;
    assert_carries_the_backend_result(&settled);
    task
}

/// The baseline both A rows assert against: one dispatch, one durable record.
fn assert_primed(mock: &Arc<MockBackend>, store: &tempfile::TempDir) -> Vec<String> {
    std::assert_eq!(
        mock.calls(),
        1,
        "the priming task must have reached the backend, or every \
         'the refusal dispatched nothing' below is vacuous"
    );
    let records = durable_records(store);
    std::assert_eq!(
        records.len(),
        1,
        "the priming task must have left exactly one durable record — this is \
         also what proves `durable_records` reads the store the route writes to, \
         and not an empty directory that would agree with every refusal: \
         {records:?}"
    );
    records
}

mod cases;

mod policy;
