// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 audit rows: a keyed no-principal call refused at intake still
//! leaves exactly one invocation record, attributed to the caller it came
//! from and recording the refusal. D2-a capture (`direct_caller.rs`
//! `read_envelope`) runs before the intake check, so moving the check above
//! it would drop the record; these rows catch that.

use super::*;

/// The params object as sent; D2-e hashes exactly that object.
fn params_of(body: &str) -> Value {
    let request: Value = serde_json::from_str(body).expect("a row body is JSON");
    request["params"].clone()
}

/// CONTROL (UNIFY.1a′, audit): on both routes the refused call is one
/// `denied` record carrying -32003, the target it named, the request hash and
/// an anonymous caller (no subject, no credential kind).
#[tokio::test]
async fn intake_refusal_is_one_attributed_denied_record() {
    let invoke = keyed_invoke("alpha", "t");
    let invoke_params = params_of(&invoke);
    for (route, uri, body, hashed) in [
        ("direct", "/mcp/alpha", keyed("t"), params_of(&keyed("t"))),
        ("meta", "/mcp", invoke.clone(), invoke_params["arguments"].clone()),
    ] {
        let fx = fixture(idempotent()).await;
        let caller = if route == "meta" {
            Caller::Session
        } else {
            Caller::Anonymous
        };
        let (status, answer) = post_to(&fx, uri, &body, &caller).await;
        assert_eq!(message(&answer), NO_PRINCIPAL, "{route}: {answer}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {answer}");
        let entry = only_invocation(&fx);
        assert_eq!(entry["route"], route, "{route}: {entry}");
        assert_eq!(entry["outcome"], "denied", "{route}: {entry}");
        assert_eq!(entry["error_code"], -32003, "{route}: {entry}");
        assert_eq!(entry["server"], "alpha", "{route}: {entry}");
        assert_eq!(entry["tool"], "t", "{route}: {entry}");
        assert_eq!(entry["caller"], "anonymous", "{route}: {entry}");
        assert_eq!(entry["who"]["account"], "anonymous", "{route}: {entry}");
        assert!(entry["who"].get("subject").is_none(), "{route}: {entry}");
        assert!(
            entry["who"].get("credential_kind").is_none(),
            "{route}: {entry}"
        );
        let hash = format!("sha256:{}", crate::hashing::canonical_json_sha256(&hashed));
        assert_eq!(entry["request_hash"], hash.as_str(), "{route}: {entry}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{route}: dispatched");
    }
}
