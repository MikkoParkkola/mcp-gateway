// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use super::*;

// MIK-6746 D.4 — passthrough resolution (ADR-008 rung 2).
mod passthrough {
    use axum::http::HeaderMap;

    use super::*;
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    const HEADER: &str = "x-mcp-passthrough-authorization";

    fn cfg(required: bool) -> IdentityPropagationConfig {
        IdentityPropagationConfig {
            strategy: PropagationStrategyKind::Passthrough,
            audience: "https://backend".to_string(),
            required,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }
    }

    fn headers_with(cred: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HEADER, cred.parse().unwrap());
        h
    }

    // D.1/D.4 — the caller's own credential is forwarded verbatim to the
    // backend under `Authorization`. Nothing else is emitted; the function
    // is pure over its inputs, so it cannot persist a token (INV-4).
    #[test]
    fn present_credential_is_forwarded_as_authorization() {
        let (headers, _key) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-caller-tok"), true)
                .expect("present credential resolves");
        assert_eq!(
            headers,
            vec![("Authorization".to_string(), "cred-caller-tok".to_string())]
        );
    }

    // D.4 — concurrent callers are isolated: each request forwards only its
    // own header value; there is no shared/mutable state between calls.
    #[test]
    fn concurrent_callers_are_isolated() {
        let (a, _) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-alice"), true).unwrap();
        let (b, _) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-bob"), true).unwrap();
        assert_eq!(a[0].1, "cred-alice");
        assert_eq!(b[0].1, "cred-bob");
        assert_ne!(a[0].1, b[0].1);
    }

    // MIK.PT.1 — two DISTINCT passthrough credentials against one stateful
    // backend resolve to DISTINCT upstream session buckets. `identity_key` is
    // the bucket selector fed to `HttpTransport::bucket_key` (which is just
    // `identity_key.unwrap_or("")`), so distinct `Some` keys ==> distinct
    // `MCP-Session-Id` buckets ==> no cross-caller session-bound data leak
    // (MIK-6785). Verified at the cheapest network-free seam.
    #[test]
    fn distinct_credentials_get_distinct_session_buckets() {
        let (_, key_a) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-alice"), true).unwrap();
        let (_, key_b) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-bob"), true).unwrap();
        assert!(key_a.is_some() && key_b.is_some(), "both must key a bucket");
        assert_ne!(
            key_a, key_b,
            "distinct credentials must select distinct upstream session buckets"
        );
    }

    // MIK.PT.2 — the SAME passthrough credential reuses the SAME bucket, so a
    // caller keeps its own negotiated upstream session across requests.
    #[test]
    fn same_credential_reuses_same_session_bucket() {
        let (_, first) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-alice"), true).unwrap();
        let (_, second) =
            resolve_passthrough_headers(&cfg(true), &headers_with("cred-alice"), true).unwrap();
        assert!(first.is_some(), "credential must key a bucket");
        assert_eq!(
            first, second,
            "the same credential must select the same upstream session bucket"
        );
    }

    // MIK-6785 privacy invariant — the bucket key is the SHA-256 hex digest of
    // the credential, NOT the raw credential. The raw token must never appear
    // in the key that is stored as the in-memory session-map key.
    #[test]
    fn identity_key_is_sha256_hex_not_raw_credential() {
        const CRED: &str = "cred-super-secret-token-value";
        let (_, key) = resolve_passthrough_headers(&cfg(true), &headers_with(CRED), true).unwrap();
        let key = key.expect("credential must key a bucket");
        // 64 lowercase hex chars — a SHA-256 digest, never the token.
        assert_eq!(key.len(), 64, "SHA-256 hex is 64 chars");
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "hex only");
        assert!(!key.contains(CRED), "raw credential must not appear in key");
        assert!(
            !key.contains("super-secret-token-value"),
            "raw token bytes must not appear in key"
        );
        // Exactly the digest `passthrough_identity_key` computes.
        assert_eq!(key, passthrough_identity_key(CRED));
    }

    // D.3 — a required backend with no caller credential fails closed.
    #[test]
    fn required_and_absent_refuses() {
        assert!(resolve_passthrough_headers(&cfg(true), &HeaderMap::new(), true).is_err());
        // A blank credential counts as absent.
        assert!(resolve_passthrough_headers(&cfg(true), &headers_with("   "), true).is_err());
    }

    // MIK.PT.3 — a non-required backend with no caller credential yields the
    // static path (empty headers) AND no per-caller session bucket (`None`), so
    // `HttpTransport::bucket_key` returns the shared default (`""`) bucket
    // exactly as before MIK-6785. The INV-2 shared-token guard then decides.
    #[test]
    fn optional_and_absent_is_empty() {
        let (headers, key) =
            resolve_passthrough_headers(&cfg(false), &HeaderMap::new(), true).unwrap();
        assert!(headers.is_empty());
        assert!(
            key.is_none(),
            "no credential must select the shared default (\"\") bucket"
        );
    }

    // MIK-6710 — a `required` backend on a transport that cannot carry
    // per-request headers (stdio, websocket) must be refused BEFORE the
    // inbound passthrough header is even read, even when the caller
    // supplied a well-formed credential.
    #[test]
    fn required_and_transport_incapable_refuses_even_with_credential() {
        let err = resolve_passthrough_headers(&cfg(true), &headers_with("cred-caller-tok"), false)
            .expect_err("incapable transport must refuse regardless of credential");
        assert!(err.contains("MIK-6710"), "error: {err}");
    }

    // A non-required backend on a transport-incapable backend still
    // proceeds with the static path — best-effort, unaffected by MIK-6710.
    #[test]
    fn optional_and_transport_incapable_is_unaffected() {
        let (headers, _key) =
            resolve_passthrough_headers(&cfg(false), &HeaderMap::new(), false).unwrap();
        assert!(headers.is_empty());
    }
}

// MIK-6740 — identity-propagation credential events on the tamper-evident
// transparency log (IDP4).
mod identity_propagation_audit {
    use std::sync::Arc;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::key_server::oidc::VerifiedIdentity;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    fn open_logger() -> (NamedTempFile, TransparencyLogger) {
        let file = NamedTempFile::new().expect("tempfile");
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path: file.path().to_string_lossy().to_string(),
            key_id: "test".to_string(),
            shared_secret: String::new(),
        });
        let logger = TransparencyLogger::open(cfg).expect("logger opens");
        (file, logger)
    }

    fn read_entries(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .expect("log file readable")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("valid JSON line"))
            .collect()
    }

    fn identity(subject: &str) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: subject.to_string(),
            email: "user@test.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://idp.test.invalid".to_string(),
        }
    }

    // IDP4.2 — no verified identity resolves to the documented sentinel
    // subject rather than an empty string.
    #[test]
    fn audit_subject_falls_back_to_unauthenticated_sentinel() {
        assert_eq!(audit_subject(None), "unauthenticated");
    }

    // Subject must match the control-plane governance audit's actor id
    // derivation so the two audit trails describe the same actor.
    #[test]
    fn audit_subject_uses_stable_actor_id_for_verified_identity() {
        let id = identity("alice");
        assert_eq!(audit_subject(Some(&id)), id.stable_actor_id());
    }

    // A disabled transparency log (`logger = None`) must not panic and
    // must not create a log file — pure no-op.
    #[test]
    fn audit_identity_propagation_is_noop_when_logger_disabled() {
        audit_identity_propagation(
            None,
            "idp_mint",
            "unauthenticated",
            "some-backend",
            Some("https://aud.test.invalid"),
            None,
        );
    }

    // IDP4.1 — a successful mint records `action="idp_mint"` with subject,
    // audience, backend, and timestamp; no `reason` field is present.
    #[test]
    fn mint_records_idp_mint_with_domain_fields() {
        let (file, logger) = open_logger();
        let id = identity("alice");
        let subject = audit_subject(Some(&id));

        audit_identity_propagation(
            Some(&logger),
            "idp_mint",
            &subject,
            "github",
            Some("https://github.test.invalid/api"),
            None,
        );

        let entries = read_entries(file.path());
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["action"], "idp_mint");
        assert_eq!(entry["subject"], subject);
        assert_eq!(entry["backend"], "github");
        assert_eq!(entry["audience"], "https://github.test.invalid/api");
        assert!(entry["timestamp"].is_string());
        assert!(entry.get("reason").is_none());
    }

    // IDP4.2 — a fail-closed refusal records `action="idp_refuse"` with
    // subject ("unauthenticated" when no identity was presented), backend,
    // and the fail-closed reason string.
    #[test]
    fn refuse_records_idp_refuse_with_reason_and_unauthenticated_subject() {
        let (file, logger) = open_logger();
        let subject = audit_subject(None);

        audit_identity_propagation(
            Some(&logger),
            "idp_refuse",
            &subject,
            "github",
            Some("https://github.test.invalid/api"),
            Some(
                "identity propagation required for this backend but the caller supplied \
                     no passthrough credential (ADR-008 D.3, fail-closed)",
            ),
        );

        let entries = read_entries(file.path());
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["action"], "idp_refuse");
        assert_eq!(entry["subject"], "unauthenticated");
        assert_eq!(entry["backend"], "github");
        assert_eq!(
            entry["reason"],
            "identity propagation required for this backend but the caller supplied no \
                 passthrough credential (ADR-008 D.3, fail-closed)"
        );
        assert!(entry["timestamp"].is_string());
    }

    // IDP4.3 — redaction is load-bearing: drive a mint and a refuse through
    // the *same* logger with a fake credential-shaped value that would
    // appear verbatim in the log if any code path forwarded it, then
    // assert those bytes never appear anywhere in the on-disk log and only
    // the whitelisted domain fields (plus the chain fields the logger
    // itself adds) exist on each entry.
    #[test]
    fn no_secret_or_token_bytes_ever_reach_the_log() {
        // A LIVE, credential-shaped canary. The point of this test (IDP4.3 /
        // fail-fast: "no raw assertion/token appears in any audit entry") is
        // defeated if the canary is a value we simply never hand to the audit
        // sink — that proves nothing. So we resolve it into the request's
        // forwarded headers with the SAME function the mint path uses
        // (`resolve_passthrough_headers`, backend_handlers.rs:420), then audit
        // with the exact argument shape of the real call site
        // (backend_handlers.rs:436) — subject/backend/audience only, never the
        // header vec. The credential is thus provably live in the flow yet
        // provably absent from the log.
        use axum::http::HeaderMap;

        use crate::identity_propagation::{
            IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
        };

        // Opaque credential shape (no auth-scheme prefix) — a raw token the
        // audit must never persist.
        const CANARY_SECRET: &str = "tok-do-not-leak-9f3a1c2b7e4d6f8801";

        let (file, logger) = open_logger();
        let id = identity("bob");
        let subject = audit_subject(Some(&id));
        let audience = "https://backend-a.test.invalid";

        // Resolve the caller credential exactly as the mint path does: the
        // canary lands in the forwarded headers, not in any audit argument.
        let cfg = IdentityPropagationConfig {
            strategy: PropagationStrategyKind::Passthrough,
            audience: audience.to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        };
        let mut inbound = HeaderMap::new();
        inbound.insert(
            "x-mcp-passthrough-authorization",
            CANARY_SECRET.parse().unwrap(),
        );
        let (headers, _key) = resolve_passthrough_headers(&cfg, &inbound, true)
            .expect("canary credential resolves into forwarded headers");
        assert!(
            headers.iter().any(|(_, v)| v.contains(CANARY_SECRET)),
            "precondition: the canary must actually be live in the forwarded headers"
        );

        // Mint audit — the call-site contract passes metadata only; the
        // `headers` above are forwarded to the backend, never logged.
        audit_identity_propagation(
            Some(&logger),
            "idp_mint",
            &subject,
            "backend-a",
            Some(audience),
            None,
        );
        // A refuse: the reason string is a fixed fail-closed message, never
        // the credential the caller failed to supply.
        audit_identity_propagation(
            Some(&logger),
            "idp_refuse",
            &audit_subject(None),
            "backend-b",
            Some("https://backend-b.test.invalid"),
            Some("identity propagation required but no credential was supplied"),
        );

        let raw = std::fs::read_to_string(file.path()).expect("log file readable");
        assert!(
            !raw.contains(CANARY_SECRET),
            "a live forwarded credential must never reach the transparency log"
        );

        let allowed_keys = [
            "action",
            "subject",
            "backend",
            "audience",
            "reason",
            "timestamp",
            // Chain fields TransparencyLogger::append_core adds itself —
            // not supplied by the caller, but present on every entry.
            "counter",
            "prev_entry_hash",
            "entry_hash",
        ];
        let entries = read_entries(file.path());
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            let obj = entry.as_object().expect("entry is a JSON object");
            for key in obj.keys() {
                assert!(
                    allowed_keys.contains(&key.as_str()),
                    "unexpected field `{key}` in audit entry: {entry}"
                );
            }
        }
        assert_eq!(entries[0]["action"], "idp_mint");
        assert_eq!(entries[1]["action"], "idp_refuse");
    }
}

#[test]
fn normalize_tools_list_response_fills_direct_backend_proxy_annotations() {
    let mut response = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({
            "tools": [
                {
                    "name": "search",
                    "description": "Search things",
                    "inputSchema": {"type": "object"},
                    "annotations": {"readOnlyHint": true}
                },
                {
                    "name": "archive_chat",
                    "description": "Archive a chat",
                    "inputSchema": {"type": "object"},
                    "annotations": {}
                }
            ],
            "nextCursor": "abc",
            "extra": "preserved"
        }),
    );

    normalize_tools_list_response("beeper", &mut response);

    let result = response.result.expect("success result");
    assert_eq!(result["nextCursor"], "abc");
    assert_eq!(result["extra"], "preserved");

    let search = &result["tools"][0]["annotations"];
    assert_eq!(search["readOnlyHint"], true);
    assert_eq!(search["destructiveHint"], false);
    assert_eq!(search["idempotentHint"], true);
    assert_eq!(search["openWorldHint"], true);
    assert_eq!(
        result["tools"][0]["trustCard"]["schemaVersion"],
        "trust_card.v1"
    );
    assert_eq!(
        result["tools"][0]["trustCard"]["serverId"],
        "backend:beeper"
    );
    assert_eq!(result["tools"][0]["trustCard"]["toolName"], "search");
    assert_eq!(
        result["tools"][0]["trustCard"]["trustCardDigestSha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    let archive = &result["tools"][1]["annotations"];
    assert_eq!(archive["readOnlyHint"], false);
    assert_eq!(archive["destructiveHint"], true);
    assert_eq!(archive["idempotentHint"], false);
    assert_eq!(archive["openWorldHint"], true);
}
