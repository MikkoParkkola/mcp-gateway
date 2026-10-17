// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 audit rows: a keyed no-principal call refused at intake still
//! leaves exactly one invocation record, attributed to the caller it came
//! from and recording the refusal as `invalid` (the outcome admission's
//! -32003 records at the base). D2-a capture (`direct_caller.rs`
//! `read_envelope`) runs before the intake check, so moving the check above
//! it would drop the record; these rows catch that.

use super::*;

/// The params object as sent; D2-e hashes exactly that object.
fn params_of(body: &str) -> Value {
    let request: Value = serde_json::from_str(body).expect("a row body is JSON");
    request["params"].clone()
}

/// One keyed no-principal call on `route`, refused -32003 / 400, then the
/// one record it left: `invalid`, -32003, the target it named, the request
/// hash and an anonymous caller (no subject, credential kind `none`, empty
/// principal), as admission's refusal records it on the direct route.
async fn assert_one_attributed_record(route: &str) {
    let (uri, body, hashed, caller) = if route == "meta" {
        let invoke = keyed_invoke("alpha", "t");
        let hashed = params_of(&invoke)["arguments"].clone();
        ("/mcp", invoke, hashed, Caller::Session)
    } else {
        (
            "/mcp/alpha",
            keyed("t"),
            params_of(&keyed("t")),
            Caller::Anonymous,
        )
    };
    let fx = fixture(idempotent()).await;
    let (status, answer) = post_to(&fx, uri, &body, &caller).await;
    assert_eq!(
        refusal(&answer),
        (Some(-32003), NO_PRINCIPAL),
        "{route}: {answer}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {answer}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], route, "{route}: {entry}");
    assert_eq!(entry["outcome"], "invalid", "{route}: {entry}");
    assert_eq!(entry["error_code"], -32003, "{route}: {entry}");
    assert_eq!(entry["server"], "alpha", "{route}: {entry}");
    assert_eq!(entry["tool"], "t", "{route}: {entry}");
    assert_eq!(entry["caller"], "anonymous", "{route}: {entry}");
    assert_eq!(entry["who"]["account"], "anonymous", "{route}: {entry}");
    assert!(entry["who"].get("subject").is_none(), "{route}: {entry}");
    assert_eq!(entry["who"]["credential_kind"], "none", "{route}: {entry}");
    assert_eq!(entry["who"]["principal"], "", "{route}: {entry}");
    let hash = format!("sha256:{}", crate::hashing::canonical_json_sha256(&hashed));
    assert_eq!(entry["request_hash"], hash.as_str(), "{route}: {entry}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{route}: dispatched");
}

/// CONTROL (UNIFY.1a′, audit), direct route: the refusal is one attributed
/// `invalid` record. Green at the base (admission's refusal is recorded);
/// stays green only if the intake check sits below D2-a capture.
#[tokio::test]
async fn direct_intake_refusal_is_one_attributed_record() {
    assert_one_attributed_record("direct").await;
}

/// RED (UNIFY.1a′, audit), `/mcp`: the same refusal on `gateway_invoke` is
/// recorded as the direct route records it. At the base admission's -32003
/// on `/mcp` writes no invocation record at all; the `/mcp` intake refusal
/// must write one, as the router's other `/mcp` refusals do (#2420,
/// `meta_refusal`). Its field values are a lead ruling, not an observation:
/// `invalid` with an anonymous caller, for parity with the direct record (the
/// same event on two routes); `denied` stays for authorization decisions on a
/// known caller.
#[tokio::test]
async fn mcp_intake_refusal_is_one_attributed_record() {
    assert_one_attributed_record("meta").await;
}
