// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 R4 (BIND.1/2): the in-band confirmation on `/mcp` binds a
//! key-only caller to its credential, not to the key's configured NAME.
//!
//! A key's principal is a prefix of its digest (`auth.rs`), so a key re-issued
//! under the same name is another credential, and another caller, as a watch
//! poll already treats it (`a_key_reissued_under_the_same_name_is_another_caller`).
use super::*;

use crate::gateway::meta_mcp::Authentication;
use crate::protocol::continuation::ContinuationState;
use crate::protocol::mrtr::RetryFields;

use super::confirmation::CONFIRMATION_INPUT_KEY;

const TOOL: &str = "gateway_kill_server";

fn arguments() -> serde_json::Value {
    json!({ "server": "brave" })
}

/// A key-only caller on the modern in-band path: no identity, the key's
/// principal `credential`, and the configured name `ops` either way.
fn key_only<'a>(
    credential: &'a str,
    retry: &'a RetryFields,
    continuation: &'a Arc<ContinuationState>,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'a> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        credential_principal: Some(credential),
        authentication: Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        api_key_name: Some("ops"),
        verified_identity: None,
        is_modern: true,
        era: crate::protocol::meta::Era::Modern,
        retry,
        confirmation: ConfirmationChannel::InBand { continuation },
        ..allow_all_ctx()
    }
}

async fn gate(ctx: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>) -> super::GateOutcome {
    super::destructive_confirmation_gate(&RequestId::Number(1), TOOL, &arguments(), None, ctx).await
}

fn answered(envelope: &str) -> RetryFields {
    RetryFields {
        input_responses: Some(json!({ CONFIRMATION_INPUT_KEY: true })),
        request_state: Some(envelope.to_string()),
        idempotency_key: None,
        malformed: Vec::new(),
        attestation: None,
    }
}

#[tokio::test]
async fn a_key_reissued_under_the_same_name_cannot_answer_the_old_keys_confirmation() {
    let continuation = Arc::new(ContinuationState::new());
    let fresh = &crate::protocol::mrtr::NO_RETRY;
    let super::GateOutcome::Refuse(asked) = gate(&key_only("aaaa0001", fresh, &continuation)).await
    else {
        panic!("a key-only caller is asked in-band");
    };
    let envelope = asked
        .result
        .as_ref()
        .and_then(|result| result["requestState"].as_str())
        .expect("the question carries its envelope")
        .to_string();
    let retry = answered(&envelope);

    // Same name, another credential: not the caller the question was asked of.
    let reissued = gate(&key_only("bbbb0002", &retry, &continuation)).await;
    assert!(
        !matches!(reissued, super::GateOutcome::ProceedConfirmed),
        "a key re-issued under the same name answered the old key's confirmation"
    );
    // The refused attempt did not spend it: the key it was asked of confirms.
    assert!(matches!(
        gate(&key_only("aaaa0001", &retry, &continuation)).await,
        super::GateOutcome::ProceedConfirmed
    ));
}

/// R10: binding a key does not collapse the subjects proven behind one shared
/// key. Each proven subject is its own principal, ahead of the key: a verified
/// identity (R10a) and a `GrantSubject` from trusted headers, mTLS or an OAuth
/// agent (R10b). Mutant: the key ahead of a proven subject.
#[test]
fn subjects_proven_behind_one_shared_key_stay_apart() {
    use crate::protocol::mrtr::source_fingerprint;

    let continuation = Arc::new(ContinuationState::new());
    let retry = &crate::protocol::mrtr::NO_RETRY;
    let shared = || key_only("cafe0001", retry, &continuation);
    let bare = source_fingerprint(shared().principal_source(None));

    let (mut alice, mut bob) = (NAMED_CALLER.clone(), NAMED_CALLER.clone());
    alice.subject = "alice".to_string();
    bob.subject = "bob".to_string();
    let by_identity = |who| {
        source_fingerprint(
            crate::gateway::meta_mcp::MetaMcpCallerContext {
                verified_identity: Some(who),
                ..shared()
            }
            .principal_source(None),
        )
    };
    let by_subject = |subject: &str| {
        source_fingerprint(
            crate::gateway::meta_mcp::MetaMcpCallerContext {
                grant_subject: Some(crate::identity_grants::GrantSubject::new(
                    "local", subject, None,
                )),
                ..shared()
            }
            .principal_source(None),
        )
    };
    for (case, a, b) in [
        ("identity", by_identity(&alice), by_identity(&bob)),
        ("grant subject", by_subject("alice"), by_subject("bob")),
    ] {
        assert!(a.is_some() && b.is_some(), "{case}: bindable");
        assert_ne!(
            a, b,
            "{case}: two subjects behind one key are one principal"
        );
        assert_ne!(a, bare, "{case}: a proven subject is not the bare key");
    }
}

/// R11 (D6): every production site binds a caller through
/// `principal_source` -> `source_fingerprint`. The identity-only spelling,
/// which refuses a key-only caller, is called from exactly one reviewed
/// residue: the direct route's A2A round (`a2a_round_binding`), whose caller
/// type cannot reach `principal_source` (MIK-8330). A new caller fails here.
#[test]
fn the_identity_only_binding_is_called_only_by_the_a2a_residue() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut callers = Vec::new();
    for entry in walkdir::WalkDir::new(&root) {
        let entry = entry.expect("src is readable");
        let rel = entry.path().strip_prefix(&root).expect("under src");
        let rel = rel.to_string_lossy().replace('\\', "/");
        let test_file = rel.ends_with("tests.rs")
            || rel.contains("_tests/")
            || rel.contains("/tests/")
            || rel.ends_with("_fixture.rs");
        let rust = entry.path().extension().is_some_and(|ext| ext == "rs");
        if !rust || test_file {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).expect("readable source");
        // The file's own inline unit-test module (by convention its tail) is
        // not production; a `#[path]` test module is a separate file.
        let tail = text.match_indices("#[cfg(test)]\nmod ").find(|(at, _)| {
            text[*at..]
                .lines()
                .nth(1)
                .is_some_and(|line| line.trim_end().ends_with('{'))
        });
        let production = &text[..tail.map_or(text.len(), |(at, _)| at)];
        for line in production.lines().map(str::trim_start) {
            if line.starts_with("//") || line.contains("fn principal_fingerprint(") {
                continue;
            }
            if line.contains("principal_fingerprint(") {
                callers.push(rel.clone());
            }
        }
    }
    assert_eq!(
        callers,
        ["gateway/router/backend_handlers/direct_preflight.rs"],
        "an identity-only binding outside the reviewed residue"
    );
}
