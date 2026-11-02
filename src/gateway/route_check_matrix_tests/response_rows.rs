// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response matrix's HTTP seal rows (MIK-8689 phase A1): each drives a
//! real `/mcp` or `/mcp/alpha` call with both provenance signers installed
//! and reads the order of two stages off the delivered answer. The oracle is
//! the delivered JSON-RPC body, so a stage that runs after the seal and
//! changes a sealed member turns the receipt from Bound to a mismatch.

use serde_json::Value;

use crate::gateway::router::route_matrix_driver_tests::response::{
    BackendAnswer, DELIVERED_PROSE, HttpRoute, STUFFED_INFO, direct_public_read, node_verifies,
    planted_credential, read_then_relay, read_then_relay_own_signature, read_then_relay_rebuilt,
    signed_call, signed_legacy_then_modern_replay, signed_recorded_call, signed_redacted_call,
    signed_replay, trust_set,
};
use crate::protocol::meta::Era;
use crate::trust::provenance_public::{VerifyRefusal, VerifyStatus, verify_public};

/// The delivered result of `body`.
fn delivered(body: &Value) -> &Value {
    body.get("result")
        .unwrap_or_else(|| panic!("the call answered with a result: {body}"))
}

/// The receipt on a delivered result.
fn receipt(result: &Value) -> &Value {
    result
        .pointer("/_meta/provenance")
        .unwrap_or_else(|| panic!("the delivered result carries a receipt: {result}"))
}

/// The receipt on `result` is sealed and Bound to exactly `result`.
fn assert_sealed_bound(row: &str, result: &Value) {
    let prov = receipt(result);
    assert!(
        prov.get("public_signature").is_some(),
        "{row}: the delivered receipt is sealed: {result}"
    );
    let verified = verify_public(prov, &trust_set(), Some(result))
        .unwrap_or_else(|refusal| panic!("{row}: the delivered receipt verifies: {refusal:?}"));
    assert_eq!(verified.status, VerifyStatus::Bound, "{row}: {result}");
}

/// R-SHAPE `shape_precedes_seal` (`Shape` < `Seal`; `Mcp`, `Direct` ×
/// `Fresh` × `Modern`). The backend answer carries no `resultType`, so only the shaper
/// writes it; a seal taken before the shaper binds a result without it and
/// fails against the delivered bytes.
#[tokio::test]
async fn r_shape_shape_precedes_seal() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let body = signed_call(route, Era::Modern, BackendAnswer::Ok).await;
        let result = delivered(&body);
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete"),
            "R-SHAPE {route:?}: the shaper wrote the result type: {result}"
        );
        assert_sealed_bound(&format!("R-SHAPE {route:?}"), result);
    }
}

/// R-STAMP `stamp_precedes_seal` (`ProvenanceStamp` < `Seal`; `Mcp`,
/// `Direct` × `Fresh` × both eras). A seal needs a receipt this request
/// minted, so a sealed, Bound receipt shows the stamp ran first. The backend
/// claims `cacheScope: "public"`, which ingress removes from a `tools/call`
/// answer, so the receipt is Bound to the delivered bytes and refuses the
/// backend's.
#[tokio::test]
async fn r_stamp_seal_binds_the_delivered_bytes() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-STAMP {route:?} {era:?}");
            let body = signed_call(route, era, BackendAnswer::PublicScope).await;
            let result = delivered(&body);
            assert_eq!(
                result.get("cacheScope"),
                None,
                "{row}: ingress removed the backend's scope: {result}"
            );
            assert_sealed_bound(&row, result);
            let mut sent = result.clone();
            sent["cacheScope"] = Value::from("public");
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&sent)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the backend's body"
            );
        }
    }
}

/// R-FWSEAL `firewall_precedes_seal` (`Firewall` < `Seal`; `Mcp`, `Direct`
/// × `Fresh` × both eras). The backend answers a credential; under a Warn
/// rule the egress firewall redacts it and still delivers the answer. The
/// receipt is Bound to the redacted bytes and refuses the unredacted body, so
/// a seal taken before the redaction fails here.
#[tokio::test]
async fn r_fwseal_firewall_precedes_seal() {
    let leak = planted_credential();
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-FWSEAL {route:?} {era:?}");
            let body = signed_redacted_call(route, era, leak).await;
            let result = delivered(&body);
            let text = result
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{row}: the answer carries its text: {result}"));
            assert!(
                !text.contains(leak) && text.contains("[REDACTED:credential]"),
                "{row}: the firewall redacted the delivered text: {text}"
            );
            assert_sealed_bound(&row, result);
            let mut unredacted = result.clone();
            unredacted["content"][0]["text"] = Value::from(leak);
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&unredacted)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the unredacted body"
            );
        }
    }
}

/// The delivery record's hash of `document`, as the record computes it
/// (`sorted-json-v1`).
fn record_hash(document: &Value) -> String {
    format!("sha256:{}", crate::hashing::canonical_json_sha256(document))
}

/// R-RECSIGN `sign_precedes_delivery_record` (`Sign` < `DeliveryRecord`;
/// `Mcp`, `Direct` × `Fresh` × `Modern`). A message-signed call delivers a
/// result carrying `_signature`, and its one delivery row hashes the
/// delivered document with that signature in it: a record taken before
/// signing would hash the unsigned document and differ.
#[tokio::test]
async fn r_recsign_sign_precedes_delivery_record() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-RECSIGN {route:?}");
        let recorded = signed_recorded_call(route).await;
        let result = delivered(&recorded.body);
        assert!(
            result.get("_signature").is_some(),
            "{row}: the answer is message-signed: {result}"
        );
        assert_eq!(
            recorded.rows.len(),
            1,
            "{row}: one delivery row: {:?}",
            recorded.rows
        );
        let record = &recorded.rows[0];
        assert_eq!(record["response_hash_encoding"], "sorted-json-v1", "{row}");
        let expected = record_hash(&recorded.body);
        assert_eq!(
            record["response_hash"].as_str(),
            Some(expected.as_str()),
            "{row}: the record hashes the delivered, signed document"
        );
        let mut unsigned = recorded.body.clone();
        if let Some(result) = unsigned.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("_signature");
        }
        assert_ne!(
            record_hash(&unsigned),
            expected,
            "{row}: the hash tells a signed document from an unsigned one"
        );
    }
}

/// Backend prose past the collusion detector's 48-character floor
/// (`security/firewall/collusion.rs:73`), so a receipted copy is caught when
/// another key sends it on.
const LONG_PROSE: &str =
    "The quarterly ledger reconciles every account against the vendor statements on file.";

/// R-COMMIT `delivery_record_precedes_relay_commit`, `Mcp` × `Fresh` ×
/// `Modern` (`DeliveryRecord` < `RelayCommit`). With a fail-closed log whose
/// `response_delivery_attempt` append fails, the read's answer is replaced by
/// the audit refusal, and a relayed send of its text runs: no receipt was
/// committed for an answer the client never got. The control is the same read
/// with the record written: its text is receipted and the relay refused. The
/// existing `/mcp` pin fails the next append of any kind; this one fails the
/// delivery record itself.
#[tokio::test]
async fn r_commit_delivery_record_precedes_relay_commit() {
    let control = read_then_relay(LONG_PROSE, false).await;
    assert!(
        control.read.to_string().contains(LONG_PROSE),
        "R-COMMIT Mcp: control: the read delivers the prose: {}",
        control.read
    );
    assert_eq!(
        control.relayed["error"]["code"], -32002,
        "R-COMMIT Mcp: control: delivered prose is receipted and its relay refused: {}",
        control.relayed
    );
    let failed = read_then_relay(LONG_PROSE, true).await;
    assert!(
        failed.read.get("error").is_some() && !failed.read.to_string().contains(LONG_PROSE),
        "R-COMMIT Mcp: the failed delivery record replaced the answer: {}",
        failed.read
    );
    assert!(
        failed.relayed.get("error").is_none(),
        "R-COMMIT Mcp: no receipt for the withheld answer, so the send runs: {}",
        failed.relayed
    );
}

/// R-REBUILD `relay_receipt_reflects_the_delivered_bytes` (`Mcp`, `Direct` ×
/// `Fresh` × `Modern`): the relay receipt is rebuilt from the delivered
/// bytes. Beside the prose it delivers, the backend stuffs prose into its own
/// `_meta` `serverInfo`, which the shaper overwrites with the gateway's after
/// the receipt is first staged. The relay receipt is rebuilt from the
/// delivered bytes: relaying the delivered prose is refused, and relaying the
/// stuffing runs. A receipt taken from the backend's own answer would catch
/// the stuffing too.
#[tokio::test]
async fn r_rebuild_relay_receipt_reflects_the_delivered_bytes() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-REBUILD {route:?}");
        let seen = read_then_relay_rebuilt(route).await;
        let read = seen.read.to_string();
        assert!(
            read.contains(DELIVERED_PROSE) && !read.contains(STUFFED_INFO),
            "{row}: the read delivers the prose under the gateway's serverInfo: {read}"
        );
        assert_eq!(
            seen.prose["error"]["code"], -32002,
            "{row}: the delivered prose is receipted and its relay refused: {}",
            seen.prose
        );
        assert!(
            seen.stuffing.get("error").is_none(),
            "{row}: the undelivered stuffing is not receipted, so its send runs: {}",
            seen.stuffing
        );
    }
}

/// R-OWNSIG (`Mcp`, `Direct` × `Fresh` × `Modern`): the relay receipt leaves
/// out the gateway's own message signature. Signing notes `_signature` as a
/// gateway write (`meta_mcp/signing.rs`, the note after the signature), and
/// the rebuild strips what was noted: relaying the delivered prose is refused,
/// and relaying the signature's `sig`, which the backend never wrote, runs.
/// Without the note, the receipt would hold the gateway's own `sig`. The
/// `Sign` < `RelayRebuild` order is invisible by outcome
/// (`IngressStripsBackendSignature`).
#[tokio::test]
async fn r_ownsig_the_gateway_signature_is_not_receipted() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-OWNSIG {route:?}");
        let seen = read_then_relay_own_signature(route).await;
        let read = seen.read.to_string();
        assert!(
            read.contains(DELIVERED_PROSE) && read.contains("\"_signature\""),
            "{row}: the read delivers the prose under the gateway's own signature: {read}"
        );
        assert_eq!(
            seen.prose["error"]["code"], -32002,
            "{row}: the delivered prose is receipted and its relay refused: {}",
            seen.prose
        );
        assert!(
            seen.stuffing.get("error").is_none(),
            "{row}: the gateway's own signature is not receipted, so its send runs: {}",
            seen.stuffing
        );
    }
}

/// R-CLAMP-READ: where a backend may still send `cacheScope`, a final
/// `resources/read`, its `public` claim is delivered `private` on the direct
/// route. On `tools/call` ingress removes the member, and the direct route
/// links and seals no cacheable method, so no order is stated here; this row
/// keeps the clamp's own effect at route level.
#[tokio::test]
async fn r_clamp_read_delivers_private() {
    let body = direct_public_read().await;
    let result = delivered(&body);
    assert_eq!(
        result.get("cacheScope").and_then(Value::as_str),
        Some("private"),
        "the clamp delivers private: {result}"
    );
    assert_eq!(result["contents"][0]["text"], "notes", "{result}");
}

/// R-SIGN `seal_precedes_sign` (`Seal` < `Sign`; `Mcp`, `Direct` × `Fresh` ×
/// `Modern`). A message-signed call delivers a result carrying both the public
/// seal and `_signature`; the reviewed Node verifier accepts the signature,
/// and rejects it once `public_signature` is removed, so the MAC covers the
/// seal: a signature taken before the seal would not.
#[tokio::test]
async fn r_sign_seal_precedes_sign() {
    for route in [HttpRoute::Mcp, HttpRoute::Direct] {
        let row = format!("R-SIGN {route:?}");
        let body = signed_recorded_call(route).await.body;
        assert!(
            receipt(delivered(&body)).get("public_signature").is_some(),
            "{row}: the delivered receipt is sealed: {body}"
        );
        node_verifies(&body, "n1")
            .unwrap_or_else(|e| panic!("{row}: the Node verifier accepts the signature: {e}"));
        let mut unsealed = body.clone();
        if let Some(prov) = unsealed
            .pointer_mut("/result/_meta/provenance")
            .and_then(Value::as_object_mut)
        {
            prov.remove("public_signature");
        }
        assert!(
            node_verifies(&unsealed, "n1").is_err(),
            "{row}: the signature covers the public seal"
        );
    }
}

/// R-REPLAY-Mcp, `Mcp` × `IdempotentReplay` (`NotApplicable`:
/// `ReplayReservesTheStoredDelivery`). The route stores the finalized, sealed
/// delivery, and a keyed replay re-serves those bytes: the same result, its
/// receipt Bound and minted once (`cache: "miss"`, nothing minted in the
/// replay), and the backend ran once. A replay that served a pre-seal copy
/// would arrive unsealed and fail here.
#[tokio::test]
async fn r_replay_mcp_reserves_the_stored_delivery() {
    let (first, replay, calls) = signed_replay(HttpRoute::Mcp, BackendAnswer::Ok).await;
    assert_eq!(calls, 1, "R-REPLAY-Mcp: the replay sent nothing: {replay}");
    assert_eq!(
        delivered(&replay),
        delivered(&first),
        "R-REPLAY-Mcp: the replay re-serves the stored delivery"
    );
    assert_sealed_bound("R-REPLAY-Mcp replay", delivered(&replay));
    assert_eq!(
        receipt(delivered(&replay))
            .pointer("/receipt/cache")
            .and_then(Value::as_str),
        Some("miss"),
        "R-REPLAY-Mcp: the receipt was minted once, by the first call"
    );
}

/// R-FWSTAMP `redaction_keeps_the_counted_text`, `Mcp`, `Stdio` × `Fresh`,
/// `CacheHit` × both eras: `LatentGap(MIK-8707)`. Those routes stamp at
/// dispatch, before the egress scan (`source_order`), so the receipt counts
/// the backend's text. Since MIK-8745 a `github_search_repos` answer carrying
/// a database URI in a string value (compact with the count before or after
/// it, or as `wrap_tool_success` prints it), scanned under a Warn rule as the
/// egress scan runs it, is delivered redacted, still parseable and not an
/// error: the count the stamp read (3) is still the count the delivered text
/// states, so the order changes no counted fact.
#[test]
fn r_fwstamp_redaction_keeps_the_counted_text() {
    use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
    use crate::trust::extract_row_count;
    const TOOL: &str = "github_search_repos";
    let uri = "postgres://user:secret@db.internal/prod";
    let page = serde_json::json!({
        "total_count": 3,
        "incomplete_results": false,
        "items": [{"clone_url": uri}]
    });
    let texts = [
        // The count before the credential, compact.
        format!(
            r#"{{"total_count":3,"incomplete_results":false,"items":[{{"clone_url":"{uri}"}}]}}"#
        ),
        // The count after it, the order the old tail-eating redaction broke.
        format!(
            r#"{{"items":[{{"clone_url":"{uri}"}}],"incomplete_results":false,"total_count":3}}"#
        ),
        // `wrap_tool_success`'s printing, the text the stamp counts when the
        // answer has no structuredContent (keys sorted: the count comes last).
        serde_json::to_string_pretty(&page).expect("prints"),
    ];
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            credential_redaction: true,
            rules: vec![FirewallRule {
                tool_match: TOOL.to_string(),
                action: FirewallAction::Warn,
                reason: None,
                scan: Vec::new(),
                servers: None,
                keys: None,
                except: None,
                allowed_roots: None,
                path_args: None,
            }],
            ..FirewallConfig::default()
        },
        None,
    );
    for text in texts {
        let mut result = serde_json::json!({
            "content": [{"type": "text", "text": text}],
            "isError": false
        });
        assert_eq!(
            extract_row_count("gh", TOOL, &result, true),
            Some(3),
            "R-FWSTAMP: the stamp counts the backend's text: {text}"
        );
        let verdict = firewall.check_response("s", "gh", TOOL, &mut result, "c");
        assert!(
            verdict.allowed && verdict.action == FirewallAction::Warn,
            "R-FWSTAMP: a Warn rule redacts and still delivers: {verdict:?}"
        );
        assert_eq!(
            result["isError"], false,
            "R-FWSTAMP: redaction never flips isError: {result}"
        );
        let delivered = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("R-FWSTAMP: the answer keeps its text: {result}"));
        assert!(
            !delivered.contains("secret"),
            "R-FWSTAMP: the URI was redacted: {delivered}"
        );
        assert_eq!(
            extract_row_count("gh", TOOL, &result, true),
            Some(3),
            "R-FWSTAMP: the redacted text no longer states the stamped count \
             ({delivered}): the cells are no longer {:?}",
            super::AFTER_MIK_8745
        );
    }
}

/// R-ERAREPLAY `cross_era_replay_is_refused`, `Mcp` × `IdempotentReplay` ×
/// `Modern` × `ShapeSeal`: `NotApplicable(ReplayReservesTheStoredDelivery)`.
/// A legacy call stores its sealed answer; a modern call with the same key is
/// refused (MIK-8747), so the stored answer is never shaped for an era it was
/// not stored in, and the backend ran once.
#[tokio::test]
async fn r_erareplay_cross_era_replay_is_refused() {
    let (first, second, calls) = signed_legacy_then_modern_replay(BackendAnswer::Ok).await;
    assert_eq!(calls, 1, "R-ERAREPLAY: the backend ran once: {second}");
    assert_sealed_bound("R-ERAREPLAY legacy first", delivered(&first));
    assert_era_refusal("R-ERAREPLAY", &second);
}

/// The MIK-8747 refusal of a keyed replay from the other era.
fn assert_era_refusal(row: &str, reply: &Value) {
    assert_eq!(
        reply.pointer("/error/code").and_then(Value::as_i64),
        Some(409),
        "{row}: a cross-era replay is refused: {reply}"
    );
    assert_eq!(
        reply.pointer("/error/data/reason").and_then(Value::as_str),
        Some("idempotency_era_mismatch"),
        "{row}: {reply}"
    );
}

/// R-REPLAYSEAL `direct_replay_seal_gap`, `Direct` × `IdempotentReplay`:
/// `ExpectedGap(MIK-8705)`. The first call is sealed (the control); the replay
/// serves its stored receipt unsealed: the route stores the answer
/// (`settle_direct_idempotency`) before `finish_tail` seals it. When MIK-8705
/// lands this fails: flip the cell to the /mcp shape and assert what
/// R-REPLAY-Mcp asserts (the stored, sealed delivery re-served).
#[tokio::test]
async fn r_replayseal_direct_replay_seal_gap() {
    let (first, replay, calls) = signed_replay(HttpRoute::Direct, BackendAnswer::Ok).await;
    assert_eq!(calls, 1, "R-REPLAYSEAL: the replay sent nothing: {replay}");
    assert_sealed_bound("R-REPLAYSEAL first", delivered(&first));
    let sealed = delivered(&replay)
        .pointer("/_meta/provenance/public_signature")
        .is_some();
    assert!(
        !sealed,
        "R-REPLAYSEAL: MIK-8705 gap closed? the direct replay is now sealed: flip the cell"
    );
}

/// Phase B: the stdio twins of the seal, clamp, firewall and link rows, on
/// the real stdio dispatch (`server::route_matrix_driver_tests::response`).
mod stdio {
    use serde_json::{Value, json};

    use super::{assert_sealed_bound, delivered, receipt};
    use crate::gateway::router::route_matrix_driver_tests::response::{
        planted_credential, trust_set,
    };
    use crate::gateway::server::route_matrix_driver_tests::response::{
        StdioSetup, stdio_legacy_then_modern_replay, stdio_sealed, stdio_sealed_replay,
        stdio_signed_recorded,
    };
    use crate::protocol::meta::Era;
    use crate::trust::provenance_public::{VerifyRefusal, verify_public};

    fn text(text: &str) -> Value {
        json!({"content": [{"type": "text", "text": text}], "isError": false})
    }

    fn public_scope() -> Value {
        json!({"content": [{"type": "text", "text": "ok"}], "isError": false,
               "cacheScope": "public"})
    }

    /// R-SHAPE on stdio (`Stdio` × `Fresh` × `Modern`): the answer lacks
    /// `resultType`, the shaper writes it, and the seal binds the shaped bytes.
    #[tokio::test]
    async fn r_shape_stdio_shape_precedes_seal() {
        let body = stdio_sealed(StdioSetup::Plain, Era::Modern, text("ok")).await;
        let result = delivered(&body);
        assert_eq!(
            result.get("resultType").and_then(Value::as_str),
            Some("complete"),
            "R-SHAPE Stdio: the shaper wrote the result type: {result}"
        );
        assert_sealed_bound("R-SHAPE Stdio", result);
    }

    /// R-STAMP on stdio (`Stdio` × `Fresh` × both eras): a sealed, Bound
    /// receipt shows the stamp ran first; the backend's `public` claim is
    /// removed at ingress, and the receipt refuses the backend's body.
    #[tokio::test]
    async fn r_stamp_stdio_seal_binds_the_delivered_bytes() {
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-STAMP Stdio {era:?}");
            let body = stdio_sealed(StdioSetup::Plain, era, public_scope()).await;
            let result = delivered(&body);
            assert_eq!(
                result.get("cacheScope"),
                None,
                "{row}: ingress removed the backend's scope: {result}"
            );
            assert_sealed_bound(&row, result);
            let mut sent = result.clone();
            sent["cacheScope"] = Value::from("public");
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&sent)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the backend's body"
            );
        }
    }

    /// R-FWSEAL on stdio (`Stdio` × `Fresh` × both eras): under a Warn rule
    /// the credential is redacted, and the seal binds the redacted bytes.
    #[tokio::test]
    async fn r_fwseal_stdio_firewall_precedes_seal() {
        let leak = planted_credential();
        for era in [Era::Modern, Era::Legacy] {
            let row = format!("R-FWSEAL Stdio {era:?}");
            let body = stdio_sealed(StdioSetup::Redacting, era, text(leak)).await;
            let result = delivered(&body);
            let delivered_text = result
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{row}: the answer carries its text: {result}"));
            assert!(
                !delivered_text.contains(leak) && delivered_text.contains("[REDACTED:credential]"),
                "{row}: the firewall redacted the delivered text: {delivered_text}"
            );
            assert_sealed_bound(&row, result);
            let mut unredacted = result.clone();
            unredacted["content"][0]["text"] = Value::from(leak);
            assert_eq!(
                verify_public(receipt(result), &trust_set(), Some(&unredacted)).err(),
                Some(VerifyRefusal::ResultMismatch),
                "{row}: the receipt does not bind the unredacted body"
            );
        }
    }

    /// R-REPLAY-Stdio, `Stdio` × `IdempotentReplay` (`NotApplicable`:
    /// `ReplayReservesTheStoredDelivery`). stdio stores the finalized, sealed
    /// delivery (`stdio_delivery.rs:83`, stored at `:162`) and the shared sync
    /// admission re-serves it (`admission.rs:394`): the same result, Bound,
    /// minted once (`cache: "miss"`), the backend run once.
    #[tokio::test]
    async fn r_replay_stdio_reserves_the_stored_delivery() {
        let (first, replay, calls) = stdio_sealed_replay().await;
        assert_eq!(
            calls, 1,
            "R-REPLAY-Stdio: the replay sent nothing: {replay}"
        );
        assert_eq!(
            delivered(&replay),
            delivered(&first),
            "R-REPLAY-Stdio: the replay re-serves the stored delivery"
        );
        assert_sealed_bound("R-REPLAY-Stdio replay", delivered(&replay));
        assert_eq!(
            receipt(delivered(&replay))
                .pointer("/receipt/cache")
                .and_then(Value::as_str),
            Some("miss"),
            "R-REPLAY-Stdio: the receipt was minted once, by the first call"
        );
    }

    /// R-ERAREPLAY-Stdio `stdio_cross_era_replay_is_refused`, `Stdio` ×
    /// `IdempotentReplay` × `Modern` × `ShapeSeal`: as on `/mcp`, a modern
    /// stdio call reusing a legacy call's key is refused (MIK-8747).
    #[tokio::test]
    async fn r_erareplay_stdio_cross_era_replay_is_refused() {
        let (first, second, calls) = stdio_legacy_then_modern_replay().await;
        assert_eq!(
            calls, 1,
            "R-ERAREPLAY-Stdio: the backend ran once: {second}"
        );
        assert_sealed_bound("R-ERAREPLAY-Stdio legacy first", delivered(&first));
        super::assert_era_refusal("R-ERAREPLAY-Stdio", &second);
    }

    /// R-RECSIGN-Stdio `stdio_sign_precedes_delivery_record` (`Sign` <
    /// `DeliveryRecord`; `Stdio` × `Fresh`). Stdio signs inside
    /// `finalize_routed` and records later, in `judge_and_commit`: the one
    /// delivery row hashes the delivered document with `_signature` in it.
    #[tokio::test]
    async fn r_recsign_stdio_sign_precedes_delivery_record() {
        let (body, rows, _dir) = stdio_signed_recorded().await;
        let result = delivered(&body);
        assert!(
            result.get("_signature").is_some(),
            "R-RECSIGN-Stdio: the answer is message-signed: {result}"
        );
        assert_eq!(rows.len(), 1, "R-RECSIGN-Stdio: one delivery row: {rows:?}");
        let expected = super::record_hash(&body);
        assert_eq!(
            rows[0]["response_hash"].as_str(),
            Some(expected.as_str()),
            "R-RECSIGN-Stdio: the record hashes the delivered, signed document"
        );
        let mut unsigned = body.clone();
        if let Some(result) = unsigned.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("_signature");
        }
        assert_ne!(
            super::record_hash(&unsigned),
            expected,
            "R-RECSIGN-Stdio: the hash tells a signed document from an unsigned one"
        );
    }
}
