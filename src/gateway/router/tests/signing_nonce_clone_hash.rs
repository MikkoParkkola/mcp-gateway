// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5: refused nonces perform no dispatch clone or transparency request hash.
//! Counters observe real operations on the current test thread; the hash scope
//! excludes permitted credential hashing. Positive controls prove actual work
//! and a completed invocation record from the production logger and backend.
//! Refusals preserve the complete parsed log-entry sequence, including audit entries.
//! Missing/unreadable/malformed logs fail the test rather than reading as empty.
//! Pending: allocation ceilings, response hashing, stdio/other modes, retries,
//! siblings, batches, max-body and the remaining rows40–42 evidence.

use super::signing_nonce_cache_admission_support::{
    BACKEND, EchoBackend, FixtureOptions, TOOL, gateway, gateway_with, invoke, send,
};
use super::*;
use crate::hashing::observer::{self, Work};
use pretty_assertions::assert_eq;
use std::path::{Path, PathBuf};

/// A real NDJSON log path for one test, removed when the test ends.
///
/// A plain temp path rather than a new dev-dependency: the logger only needs a
/// writable file, and `pid + label` is unique across the tests in this process.
struct LogFile(PathBuf);

impl LogFile {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-gateway-signing-clone-hash-{}-{label}.jsonl",
            std::process::id()
        ));
        // A leftover file from a previous run would start the chain non-empty.
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Every entry in the chain, in file order.
    ///
    /// PANICS on a missing file or a line that is not JSON. After the logger
    /// has been built the log is readable by construction, so answering "no
    /// entries" to an I/O or parse failure would be the exact false oracle this
    /// file exists to avoid — an unreadable log would satisfy every
    /// "nothing was appended" assertion below.
    fn entries(&self) -> Vec<Value> {
        let text = std::fs::read_to_string(&self.0).unwrap_or_else(|error| {
            panic!(
                "the transparency log at {} must be readable once the logger is \
                 built: {error}",
                self.0.display()
            )
        });
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!(
                        "transparency log line {} is not JSON ({error}): {line}",
                        index + 1
                    )
                })
            })
            .collect()
    }
}

impl Drop for LogFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn transparent(log: &LogFile) -> FixtureOptions {
    FixtureOptions {
        transparency_path: Some(log.path().to_path_buf()),
        ..FixtureOptions::default()
    }
}

/// The builder logs and continues when it cannot open the log, so a fixture
/// with no logger installed would make every zero below meaningless.
fn assert_logger_installed(log: &LogFile) {
    assert!(
        log.path().exists(),
        "the production builder must have opened the transparency log at {}; \
         without it the request-hash block never runs and every 'no work' \
         assertion below is vacuous",
        log.path().display()
    );
}

/// An INVOCATION record, as `TransparencyLogger::log_invocation` writes it:
/// `caller`, `request_hash`, `response_hash`, `server`, `session_id`, `tool`
/// plus the chain fields. Another production writer shares this file through
/// `append_event` with its own domain fields (an audit entry accompanies each
/// call — the baseline run showed two lines per successful invocation), so an
/// invocation is identified by its OWN contract rather than by being the only
/// thing in the file.
fn is_invocation(entry: &Value) -> bool {
    ["server", "tool", "request_hash", "response_hash"]
        .iter()
        .all(|field| entry.get(field).and_then(Value::as_str).is_some())
}

/// Digests a stubbed, empty or truncated request hash would produce.
///
/// The exact expected digest is deliberately NOT asserted: the value hashed at
/// the request-hash block has passed through `extract_client_claim(&mut
/// arguments, …)`, and this author could not read that function within the
/// bounded source budget, so an exact expectation would be a guess dressed as
/// an oracle. What IS asserted is that the recorded hash is a well-formed
/// digest that is none of the degenerate values — an empty payload, an empty
/// string, or the fixture's argument tree hashed as `null`.
///
/// Computed with the same helpers production uses, deliberately OUTSIDE the
/// transparency scope and after every reading is taken, so it cannot move a
/// counter. A hash EXPECTATION only — the log's `sig`/MAC field is neither
/// asserted here nor conflated with the hash-work observer.
fn degenerate_hashes() -> Vec<String> {
    [json!({}), json!(""), Value::Null]
        .iter()
        .map(|value| {
            format!(
                "sha256:{}",
                crate::hashing::sha256_hex(crate::hashing::canonical_json(value).as_bytes())
            )
        })
        .collect()
}

fn assert_hash_shape(entry: &Value, field: &str, label: &str) {
    let hash = entry[field].as_str().expect("checked by is_invocation");
    let hex = hash.strip_prefix("sha256:").unwrap_or_else(|| {
        panic!("{label}: {field} must name its algorithm: {hash}");
    });
    assert!(
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{label}: {field} must be 64 lowercase hex characters: {hash}"
    );
}

/// Exactly one invocation record appended, and it is THIS call's.
///
/// The whole prior file must still be a prefix of the new one (the chain is
/// append-only), and the new entries must contain exactly one invocation —
/// so an extra invocation cannot hide behind the filter that lets the
/// accompanying audit entry through.
fn assert_one_new_invocation(log: &LogFile, before: &[Value], label: &str) {
    let after = log.entries();
    assert!(
        after.starts_with(before),
        "{label}: the transparency chain is append-only; earlier entries changed"
    );
    let appended = &after[before.len()..];
    let invocations: Vec<&Value> = appended.iter().filter(|e| is_invocation(e)).collect();
    assert_eq!(
        invocations.len(),
        1,
        "{label}: exactly one invocation record must be appended; appended \
         entries were {appended:#?}"
    );
    let entry = invocations[0];
    assert_eq!(entry["server"], json!(BACKEND), "{label}: logged server");
    assert_eq!(entry["tool"], json!(TOOL), "{label}: logged tool");
    assert_hash_shape(entry, "request_hash", label);
    assert_hash_shape(entry, "response_hash", label);
    let request_hash = entry["request_hash"].as_str().expect("shape checked above");
    assert!(
        !degenerate_hashes().iter().any(|d| d == request_hash),
        "{label}: the request hash must cover a real payload, not an empty or \
         null one: {request_hash}"
    );
    assert_ne!(
        entry["request_hash"], entry["response_hash"],
        "{label}: request and response hashes must be distinct digests"
    );
}

/// Nothing at all was appended: not an invocation record, and not any other
/// entry either. Compared as a whole snapshot rather than as a filtered count,
/// so unexpected logging cannot pass by not looking like an invocation.
fn assert_log_unchanged(log: &LogFile, before: &[Value], label: &str) {
    assert_eq!(
        log.entries().as_slice(),
        before,
        "{label}: a refusal must append nothing to the transparency chain"
    );
}

/// One request through the real router, with the thread's work counters reset
/// immediately before it and read immediately after.
async fn measured(
    state: &Arc<AppState>,
    id: &str,
    idempotency_key: &str,
    nonce: Option<Value>,
) -> (StatusCode, Value, Work) {
    observer::reset();
    let (status, body) = send(state, invoke(id, idempotency_key, nonce)).await;
    (status, body, observer::work())
}

fn assert_completed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none() || body["error"].is_null(),
        "a completed call must not carry a json-rpc error: {body}"
    );
}

fn assert_refused(status: StatusCode, body: &Value, code: i64, message: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!(code), "refusal code: {body}");
    assert_eq!(
        body["error"]["message"],
        json!(message),
        "refusal message: {body}"
    );
}

/// The whole reading in one assertion: no clone, no canonicalization, no
/// digest, no hashed bytes.
fn assert_no_work(work: Work, label: &str) {
    assert_eq!(
        work,
        Work::default(),
        "{label}: a refusal must clone no dispatch arguments and perform no \
         transparency canonicalization or hashing"
    );
}

/// What an accepted call must demonstrably do, so the counters are known to be
/// reachable on this fixture rather than merely never incremented.
fn assert_real_work(work: Work, label: &str) {
    assert!(
        work.argument_clones >= 1,
        "{label}: an accepted call must clone its dispatch arguments: {work:?}"
    );
    assert!(
        work.transparency_canonicalizations >= 1 && work.transparency_hashes >= 1,
        "{label}: an accepted call must canonicalize and hash for the \
         transparency log: {work:?}"
    );
    // The fixture's nested argument tree canonicalizes to several kilobytes, so
    // a token digest over an empty or truncated buffer would not clear this.
    // A work measure over the digest input — NOT an allocation claim.
    assert!(
        work.transparency_hashed_bytes > 1_000,
        "{label}: the request hash must cover the large nested arguments: {work:?}"
    );
}

// ── Positive control: both mechanisms are live on this fixture ───────────────

#[tokio::test]
async fn a_valid_nonce_clones_its_arguments_and_hashes_them_into_the_transparency_log() {
    let log = LogFile::new("valid");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(&backend.url, transparent(&log)).await;
    assert_logger_installed(&log);
    let before = log.entries();
    assert!(before.is_empty(), "the chain must start empty: {before:#?}");

    let (status, body, work) = measured(&state, "valid", "valid-key", Some(json!("nonce-1"))).await;
    assert_completed(status, &body);
    assert_real_work(work, "a valid nonce");
    assert_eq!(
        backend.tools_call_count(),
        1,
        "the accepted call must reach the backend"
    );
    // The logger is wired to a real file AND this call produced an invocation
    // record of its own — a `Some` handle proves neither, and an unrelated
    // append satisfies a line count but not this.
    assert_one_new_invocation(&log, &before, "a valid nonce");
}

// ── The negatives, each paired with a control on the same fixture ────────────

#[tokio::test]
async fn a_missing_required_nonce_performs_no_clone_and_no_transparency_hash() {
    let log = LogFile::new("missing");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(&backend.url, transparent(&log)).await;
    assert_logger_installed(&log);

    // Cold: nothing has been dispatched yet on this gateway.
    let cold = log.entries();
    let (status, body, work) = measured(&state, "cold-missing", "cold-key", None).await;
    assert_refused(
        status,
        &body,
        -32001,
        "Nonce required when message signing is enforced",
    );
    assert_no_work(work, "cold missing nonce");
    assert_log_unchanged(&log, &cold, "cold missing nonce");

    // The control, on THIS gateway: the work the refusal did not do is work
    // this configuration can in fact do.
    let before_control = log.entries();
    let (status, body, work) =
        measured(&state, "control", "control-key", Some(json!("n-ok"))).await;
    assert_completed(status, &body);
    assert_real_work(work, "the control call");
    assert_one_new_invocation(&log, &before_control, "the control call");

    // Warm: a live cache entry and a settled admission entry now exist, and the
    // refusal reuses the control's idempotency key.
    let warmed = log.entries();
    let (status, body, work) = measured(&state, "warm-missing", "control-key", None).await;
    assert_refused(
        status,
        &body,
        -32001,
        "Nonce required when message signing is enforced",
    );
    assert_no_work(work, "warm missing nonce");
    assert_log_unchanged(&log, &warmed, "warm missing nonce");
}

#[tokio::test]
async fn malformed_nonce_shapes_perform_no_clone_and_no_transparency_hash() {
    let log = LogFile::new("malformed");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(&backend.url, transparent(&log)).await;
    assert_logger_installed(&log);

    let malformed = [
        ("null", Value::Null),
        ("non-string", json!(42)),
        ("boolean", json!(true)),
        ("object", json!({"nonce": "nested"})),
        ("empty", json!("")),
        ("oversized-ascii", json!("a".repeat(257))),
        // 65 four-byte characters: 260 bytes, refused on bytes despite being
        // only 65 characters.
        ("oversized-unicode", json!("😀".repeat(65))),
    ];

    for warmed in [false, true] {
        if warmed {
            let before = log.entries();
            let (status, body, work) =
                measured(&state, "warm", "shared-key", Some(json!("warm-nonce"))).await;
            assert_completed(status, &body);
            assert_real_work(work, "the warming call");
            assert_one_new_invocation(&log, &before, "the warming call");
        }
        let before = log.entries();
        for (label, nonce) in &malformed {
            let id = format!("{label}-{warmed}");
            // The warming call's idempotency key: a refusal that ran late would
            // be served that call's retained result.
            let (status, body, work) =
                measured(&state, &id, "shared-key", Some(nonce.clone())).await;
            assert_refused(status, &body, -32602, "Invalid signing nonce");
            let case = format!("{label} (warm={warmed})");
            assert_no_work(work, &case);
            assert_log_unchanged(&log, &before, &case);
        }
    }
}

#[tokio::test]
async fn a_replayed_nonce_performs_no_clone_and_no_transparency_hash() {
    let log = LogFile::new("replay");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(&backend.url, transparent(&log)).await;
    assert_logger_installed(&log);

    let before = log.entries();
    let (status, body, work) = measured(&state, "first", "first-key", Some(json!("live"))).await;
    assert_completed(status, &body);
    assert_real_work(work, "the call that registers the nonce");
    assert_one_new_invocation(&log, &before, "the call that registers the nonce");

    // Only the nonce is reused: a different request id and a different
    // idempotency key, so nothing but the nonce store can refuse this.
    let registered = log.entries();
    let (status, body, work) =
        measured(&state, "replayed", "second-key", Some(json!("live"))).await;
    assert_refused(status, &body, -32001, "Nonce replay detected");
    assert_no_work(work, "a replayed nonce");
    assert_log_unchanged(&log, &registered, "a replayed nonce");

    // The store is still usable: a refusal must not wedge the path it guards.
    let (status, body, work) = measured(&state, "after", "third-key", Some(json!("fresh"))).await;
    assert_completed(status, &body);
    assert_real_work(work, "the call after a replay refusal");
}

#[tokio::test]
async fn nonces_at_the_byte_bound_do_the_work_and_ones_over_it_do_none() {
    let log = LogFile::new("bound");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(&backend.url, transparent(&log)).await;
    assert_logger_installed(&log);

    let ascii_at_bound = "a".repeat(256);
    let (status, body, work) =
        measured(&state, "ascii-256", "k-a256", Some(json!(ascii_at_bound))).await;
    assert_completed(status, &body);
    assert_real_work(work, "a 256-byte ASCII nonce");

    // 64 four-byte characters: 256 bytes, 64 characters. Accepted.
    let unicode_at_bound = "😀".repeat(64);
    assert_eq!(unicode_at_bound.len(), 256);
    let (status, body, work) = measured(
        &state,
        "unicode-256",
        "k-u256",
        Some(json!(unicode_at_bound)),
    )
    .await;
    assert_completed(status, &body);
    assert_real_work(work, "a 64-character 256-byte nonce");

    let over_ascii = "a".repeat(257);
    let (status, body, work) =
        measured(&state, "ascii-257", "k-a257", Some(json!(over_ascii))).await;
    assert_refused(status, &body, -32602, "Invalid signing nonce");
    assert_no_work(work, "a 257-byte ASCII nonce");

    let over_unicode = "😀".repeat(65);
    assert_eq!(over_unicode.len(), 260);
    let (status, body, work) =
        measured(&state, "unicode-260", "k-u260", Some(json!(over_unicode))).await;
    assert_refused(status, &body, -32602, "Invalid signing nonce");
    assert_no_work(work, "a 65-character 260-byte nonce");
}

// ── The two operator postures either side of this checkpoint ─────────────────

#[tokio::test]
async fn an_optional_nonce_works_when_absent_and_still_refuses_when_malformed() {
    let log = LogFile::new("optional");
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway_with(
        &backend.url,
        FixtureOptions {
            transparency_path: Some(log.path().to_path_buf()),
            require_nonce: false,
        },
    )
    .await;
    assert_logger_installed(&log);

    // Absent and optional: the call proceeds, so the work is done.
    let before = log.entries();
    let (status, body, work) = measured(&state, "absent", "absent-key", None).await;
    assert_completed(status, &body);
    assert_real_work(work, "an absent optional nonce");
    assert_one_new_invocation(&log, &before, "an absent optional nonce");

    // Present and malformed is a client error whether or not a nonce is
    // required — the refusal, and the absence of work, must survive the
    // optional posture.
    let signed = log.entries();
    let (status, body, work) = measured(&state, "bad", "bad-key", Some(json!(42))).await;
    assert_refused(status, &body, -32602, "Invalid signing nonce");
    assert_no_work(work, "a malformed optional nonce");
    assert_log_unchanged(&log, &signed, "a malformed optional nonce");
}

#[tokio::test]
async fn with_transparency_logging_disabled_a_valid_call_clones_but_hashes_nothing() {
    // The counters are not blind to configuration: with the logger absent the
    // request-hash block is skipped by production code, so the transparency
    // half reads zero on a call that plainly succeeded — which is also why
    // every test above proves the logger IS installed before reading a zero.
    let backend = EchoBackend::start().await;
    let (state, _owner) = gateway(&backend.url).await;

    let (status, body, work) = measured(&state, "no-log", "no-log-key", Some(json!("n"))).await;
    assert_completed(status, &body);
    assert!(
        work.argument_clones >= 1,
        "the call still clones its dispatch arguments: {work:?}"
    );
    assert_eq!(work.transparency_canonicalizations, 0);
    assert_eq!(work.transparency_hashes, 0);
    assert_eq!(work.transparency_hashed_bytes, 0);
}
