// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every published grant store is keyed with the gateway's own rule key:
//! after `set_identity_grants`, after the audited startup publish, and after
//! a changed-file reload through the startup sink.

use super::{Started, add, config, grants_path, reload_with, row};
use crate::gateway::meta_mcp::MetaMcp;
use crate::identity_grants::IdentityGrant;
use crate::identity_grants::journal::apply_change;
use crate::security::rule_id::RuleId;

/// The published store's id for each of `rows`, beside the id expected under
/// the gateway's record key.
fn published(
    meta: &MetaMcp,
    rows: &[&IdentityGrant],
) -> (Vec<Option<RuleId>>, Vec<Option<RuleId>>) {
    let key = meta.record_key().rule_id_key();
    let (live, _) = meta.identity_grant_sink();
    let store = live.read();
    let got = rows
        .iter()
        .map(|g| store.rule_id(&g.grant_id).cloned())
        .collect();
    let want = rows
        .iter()
        .map(|g| {
            let bytes = serde_json::to_vec(g).expect("serialises");
            Some(RuleId::of("grant", &key, &bytes))
        })
        .collect();
    (got, want)
}

#[tokio::test]
async fn a_grant_store_published_by_set_identity_grants_is_keyed() {
    let dir = crate::test_dir_keep::kept_tempdir();
    // The startup read needs a grant file.
    apply_change(&grants_path(dir.path()), true, add(row("g0", "r")))
        .await
        .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    let g1 = row("g1", "set");
    s.meta.set_identity_grants(
        crate::identity_grants::LocalIdentityGrantStore::from_grants(vec![g1.clone()]),
    );
    let (got, want) = published(&s.meta, &[&g1]);
    assert_eq!(got, want, "expected rule_ids {want:?}, got {got:?}");
}

#[tokio::test]
async fn a_grant_store_published_at_startup_is_keyed() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let g1 = row("g1", "r");
    apply_change(&grants_path(dir.path()), true, add(g1.clone()))
        .await
        .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    assert_eq!(s.served(), vec![g1.clone()], "premise: the row is served");
    let (got, want) = published(&s.meta, &[&g1]);
    assert_eq!(got, want, "expected rule_ids {want:?}, got {got:?}");
}

#[tokio::test]
async fn a_grant_store_published_by_a_file_reload_is_keyed() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let config = config(dir.path(), true);
    let g1 = row("g1", "r");
    apply_change(&grants_path(dir.path()), true, add(g1.clone()))
        .await
        .unwrap();
    let s = Box::pin(Started::run(config.clone())).await.unwrap();
    let g2 = row("g2", "later");
    apply_change(&grants_path(dir.path()), true, add(g2.clone()))
        .await
        .unwrap();
    reload_with(&config, s.sink.clone()).await;
    assert_eq!(
        s.served(),
        vec![g1.clone(), g2.clone()],
        "premise: reloaded"
    );
    let (got, want) = published(&s.meta, &[&g1, &g2]);
    assert_eq!(got, want, "expected rule_ids {want:?}, got {got:?}");
}
