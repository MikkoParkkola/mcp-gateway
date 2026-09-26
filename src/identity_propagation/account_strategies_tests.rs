// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Lease-lifetime rows for the account strategies, moved out of the module.
use super::*;

struct NeverMints;

#[async_trait::async_trait]
impl IdentityPropagation for NeverMints {
    async fn propagate(
        &self,
        _identity: &crate::key_server::oidc::VerifiedIdentity,
        _backend: &BackendDescriptor,
    ) -> std::result::Result<super::super::PropagatedCredential, super::super::PropagationError>
    {
        unreachable!("the lifetime predicate never mints")
    }
}

/// `managed: None` is the EXTERNAL shape: no lease, so the durable custody
/// half of `revalidate` is skipped and this predicate is the only thing
/// standing between a stale published expiry and the wire.
fn external(expires_at: i64, minted_at: i64) -> PreparedAccountCredential {
    PreparedAccountCredential {
        descriptor_id: "acct".to_string(),
        auth_key: "oauth:google".to_string(),
        actor_id: "actor".to_string(),
        audience: "https://partner.invalid/".to_string(),
        cache_binding: "binding".to_string(),
        expires_at,
        minted_at,
        strategy: Arc::new(NeverMints),
        managed: None,
        headers: vec![("Authorization".to_string(), "Bearer x".to_string())],
    }
}

#[test]
fn execution_context_debug_redacts_prepared_credential_headers() {
    let secrets = [
        "Bearer fixture-token-never-log-1839",
        "fixture-api-key-never-log-2940",
    ];
    let mut credential = external(1_800_000_060, 1_800_000_000);
    credential.headers = vec![
        ("Authorization".to_string(), secrets[0].to_string()),
        ("X-Api-Key".to_string(), secrets[1].to_string()),
    ];
    let context = crate::capability::CapabilityExecutionContext::default()
        .with_account_credential(Arc::new(credential));
    let output = format!("{context:?}");
    assert!(output.contains("PreparedAccountCredential"));
    assert!(output.contains("Authorization"));
    assert!(output.contains("X-Api-Key"));
    assert!(output.contains("<redacted>"));
    for secret in secrets {
        assert!(
            !output.contains(secret),
            "execution context exposed credential material"
        );
    }
}

/// THE REGRESSION, at the predicate itself. An external credential whose
/// published expiry is in the past looks exactly like `expires_at <=
/// minted_at`, which the old universal reading treated as "no lifetime
/// published" and therefore as usable.
#[test]
fn an_external_credential_with_a_past_expiry_is_closed() {
    let now = 1_800_000_000;
    assert!(
        !external(now - 3600, now).published_lifetime_open(now),
        "an external credential whose expiry has already passed must never be open"
    );
    assert!(
        !external(now, now).published_lifetime_open(now),
        "expiry exactly at now is not a lifetime an external credential may use"
    );
    assert!(
        !external(0, now).published_lifetime_open(now),
        "an external strategy publishing no usable expiry publishes no usable credential"
    );
    assert!(
        external(now + 60, now).published_lifetime_open(now),
        "an external credential inside its own published lifetime stays usable; nothing \
         here shortens it"
    );
}
