// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T5: a bound anonymous caller's continuation quota on the meta and direct
//! routes, and the one cap both routes share.

use super::*;

/// T5 meta-bound (GREEN): a bound anonymous caller mints on meta at
/// the key-name quota.
#[tokio::test]
async fn t5_bound_anonymous_mints_on_meta() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    let ctx = context_for(&client);
    assert_eq!(
        ctx.quota_key(),
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "meta charges the key-name quota"
    );
    let quota = ctx.quota_key().expect("meta has a quota key");
    let source = ctx.principal_source(Some("binding-a"));
    let arguments = serde_json::json!({});
    let minted = super::mint_continuation(
        &state,
        source,
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(minted.is_some(), "bound anonymous mints on meta");
}

/// T5 direct-bound quota (RED): a bound anonymous caller is charged
/// to the shared key-name quota on direct too. Today the direct route has no
/// fallback, so the quota is `None` and the mint never starts.
#[test]
fn t5_bound_anonymous_gets_key_name_quota_on_direct() {
    let client = crate::gateway::auth::anonymous_client();
    let key = direct_quota_key((None, (Some("binding-a"), None), Some(&client)));
    assert_eq!(
        key,
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "direct charges the shared key-name quota"
    );
}

/// T5 unbound (GREEN): an unbound anonymous caller is refused on
/// both routes: no fingerprint, so no mint.
#[tokio::test]
async fn t5_unbound_anonymous_is_refused_on_both_routes() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    // Meta: quota exists, but the source has no fingerprint.
    let ctx = context_for(&client);
    let quota = ctx
        .quota_key()
        .expect("meta still charges the key-name quota");
    let source = ctx.principal_source(None);
    let arguments = serde_json::json!({});
    let minted = super::mint_continuation(
        &state,
        source,
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(minted.is_none(), "meta refuses the unbound caller");
    // Direct: quota exists, but the source has no fingerprint.
    let unbound = (None, (None, None), Some(&client));
    assert_eq!(
        direct_quota_key(unbound),
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "direct charges the key-name quota"
    );
    let direct_minted = super::mint_continuation(
        &state,
        super::direct_source(unbound),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(direct_minted.is_none(), "direct refuses the unbound caller");
}

/// T5 wrong-binding-first (GREEN on meta): the wrong binding is
/// refused without consuming the round, then the rightful binding still
/// redeems. Proves the refusal is the binding check, not replay protection.
#[tokio::test]
async fn t5_wrong_binding_first_then_rightful_redeems_on_meta() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let quota = QuotaKey::new(QuotaSource::KeyName("anonymous"));
    let arguments = serde_json::json!({});
    let (envelope, _) = super::mint_continuation(
        &state,
        crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-a".to_owned()),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await
    .expect("bound anonymous mints");
    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(envelope),
        ..Default::default()
    };
    let wrong = super::redeem_retry(
        &state,
        (
            crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-b".to_owned()),
            &retry,
        ),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(
        wrong.is_err(),
        "wrong binding is refused, consuming nothing: {wrong:?}"
    );
    let right = super::redeem_retry(
        &state,
        (
            crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-a".to_owned()),
            &retry,
        ),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(right.is_ok(), "rightful binding still redeems: {right:?}");
}

/// T5 wrong-binding-first on direct (RED): the direct route charges a bound anonymous
/// caller to the key-name quota and binds it to its passthrough binding; a different binding is
/// refused without consuming the round, and the rightful one still redeems. Today
/// `direct_quota_key` gives None, so the mint never starts.
#[tokio::test]
async fn t5_wrong_binding_first_then_rightful_redeems_on_direct() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    let a = (None, (Some("binding-a"), None), Some(&client));
    let b = (None, (Some("binding-b"), None), Some(&client));
    let quota = direct_quota_key(a).expect("direct charges a bound anonymous caller");
    let arguments = serde_json::json!({});
    let (envelope, _) = super::mint_continuation(
        &state,
        super::direct_source(a),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await
    .expect("bound anonymous mints");
    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(envelope),
        ..Default::default()
    };
    let wrong = super::redeem_retry(
        &state,
        (super::direct_source(b), &retry),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(
        wrong.is_err(),
        "wrong binding is refused, consuming nothing: {wrong:?}"
    );
    let right = super::redeem_retry(
        &state,
        (super::direct_source(a), &retry),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(right.is_ok(), "rightful binding still redeems: {right:?}");
}

/// T5 shared cap (RED): one `ContinuationState` serves both routes;
/// different bindings filling the shared anonymous key-name cap refuse the
/// next mint. Today the direct leg cannot even reach the cap (no quota key),
/// so the shared fill fails.
#[tokio::test]
async fn t5_shared_anonymous_cap_spans_both_routes() {
    let slots = crate::protocol::continuation::PRINCIPAL_SLOTS;
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let quota = QuotaKey::new(QuotaSource::KeyName("anonymous"));
    let arguments = serde_json::json!({});
    let client = crate::gateway::auth::anonymous_client();
    let half = slots / 2;
    for i in 0..half {
        let binding = format!("binding-{i}");
        let key = format!("idp:{}:{binding}", binding.len());
        let minted = super::mint_continuation(
            &state,
            crate::protocol::mrtr::PrincipalSource::Key(key),
            &quota,
            ("fixture", None),
            "tool",
            &arguments,
            None,
        )
        .await;
        assert!(minted.is_some(), "meta fill {i} mints");
    }
    let direct_bindings: Vec<String> = (half..slots)
        .map(|i| format!("cap-direct-{i:03}"))
        .collect();
    for (i, binding) in direct_bindings.iter().enumerate() {
        let caller = (None, (Some(binding.as_str()), None), Some(&client));
        let direct_quota = direct_quota_key(caller).expect("direct charges a bound caller");
        let minted = super::mint_continuation(
            &state,
            super::direct_source(caller),
            &direct_quota,
            ("fixture", None),
            "tool",
            &arguments,
            None,
        )
        .await;
        assert!(minted.is_some(), "direct fill {i} mints");
    }
    let overflow = super::mint_continuation(
        &state,
        crate::protocol::mrtr::PrincipalSource::Key("idp:16:binding-overflow".to_owned()),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(overflow.is_none(), "meta refuses past the shared cap");
    let overflow_caller = (None, (Some("cap-direct-overflow"), None), Some(&client));
    let overflow_quota = direct_quota_key(overflow_caller).expect("direct still charges quota");
    let direct_overflow = super::mint_continuation(
        &state,
        super::direct_source(overflow_caller),
        &overflow_quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(
        direct_overflow.is_none(),
        "direct refuses past the shared cap"
    );
}
