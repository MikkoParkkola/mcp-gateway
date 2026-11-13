// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K5, the identity fields a reload changes on a kept key, observed in the
//! audit record the next call writes: `name` is the record's `who.account`,
//! and `principal` keys its `who.principal`.

use std::sync::Arc;

use serde_json::Value;

use super::ui_tool_call_tests::{ADMIN, Fx, fixture, invoke, post_mcp, records};
use crate::config_reload::ReloadContext;

/// The admin key `fixture` starts with, as a reload writes it: `name` and
/// `principal` as given, the secret still `ADMIN`.
fn admin_key_yaml(name: &str, principal: Option<&str>) -> String {
    let digest = crate::config::api_key_digest_spec(ADMIN.as_bytes());
    let mut text = format!(
        "auth:\n  enabled: true\n  api_keys:\n    - name: {name}\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n      admin: true\n"
    );
    if let Some(principal) = principal {
        use std::fmt::Write as _;
        let _ = writeln!(text, "      principal: \"{principal}\"");
    }
    text
}

/// Reload `text` into `fx`'s gateway.
async fn reload(fx: &Fx, dir: &std::path::Path, text: String) {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write");
    ReloadContext::new(
        path,
        Arc::clone(&fx.state.live_config),
        Arc::clone(&fx.state.backends),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .reload_outcome()
    .await
    .expect("the key edit applies");
}

/// One `gateway_invoke` call with the admin key; the `who` of every record it
/// wrote.
async fn call_whos(fx: &Fx) -> Vec<Value> {
    let before = records(fx).len();
    let _ = post_mcp(fx, ADMIN, invoke("read"), None).await;
    let whos: Vec<Value> = records(fx)
        .into_iter()
        .skip(before)
        .filter_map(|record| record.get("who").cloned())
        .collect();
    assert!(
        !whos.is_empty(),
        "premise: the call wrote a record with a who"
    );
    whos
}

/// K5 `name` (MIK-9255.IDENT.4): a kept key renamed by reload is recorded
/// under its new name on the next call.
#[tokio::test]
async fn k5_a_key_renamed_by_reload_is_recorded_under_its_new_name() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    for who in call_whos(&fx).await {
        assert_eq!(
            who["account"], ADMIN,
            "premise: recorded under its first name: {who}"
        );
    }

    reload(&fx, dir.path(), admin_key_yaml("k5-renamed-admin", None)).await;

    for who in call_whos(&fx).await {
        assert_eq!(
            who["account"], "k5-renamed-admin",
            "the next call is recorded under the old name: {who}"
        );
    }
}

/// K5 `principal` (MIK-9255.IDENT.5): a principal written by reload on a kept
/// key keys the next call's record (the digest-derived one did before).
#[tokio::test]
async fn k5_a_principal_written_by_reload_keys_the_next_record() {
    let fx = fixture().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let principal_of = |whos: &[Value]| -> Value {
        let first = whos[0]["principal"].clone();
        assert!(
            whos.iter().all(|who| who["principal"] == first),
            "premise: one call, one principal: {whos:?}"
        );
        assert!(
            first.as_str().is_some_and(|p| !p.is_empty()),
            "premise: a keyed principal: {first}"
        );
        first
    };
    let before = principal_of(&call_whos(&fx).await);

    reload(&fx, dir.path(), admin_key_yaml(ADMIN, Some("0123456789ab"))).await;
    let after = principal_of(&call_whos(&fx).await);
    assert_ne!(
        after, before,
        "the next call's record kept the principal from before the reload"
    );

    // A second, distinct principal keys a record of its own: the value
    // follows the field, not merely "some value other than before".
    reload(&fx, dir.path(), admin_key_yaml(ADMIN, Some("abcdef012345"))).await;
    let second = principal_of(&call_whos(&fx).await);
    assert!(
        second != after && second != before,
        "a second principal did not key a record of its own: {second}"
    );

    // The same principal written again keys the same record: the change
    // above is the field, not the reload itself.
    reload(&fx, dir.path(), admin_key_yaml(ADMIN, Some("abcdef012345"))).await;
    assert_eq!(
        principal_of(&call_whos(&fx).await),
        second,
        "an unchanged principal recorded differently"
    );
}
