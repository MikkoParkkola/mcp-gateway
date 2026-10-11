// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365 key change, as the upgrade note gives it: stop, move both log
//! sets signed with the old key aside, start with the new key. The governance
//! store's grants and policies live in `store/` (`control_plane_store.rs`
//! `open_store`, `store/file.rs` `grants_file`/`policies_file`), not in the
//! log, so they survive; the gateway starts both logs as fresh chains.

use std::path::Path;
use std::sync::Arc;

use super::load;
use crate::control_plane::{
    ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlanePolicy, ControlPlaneStore,
};
use crate::security::transparency_log::{TransparencyLogConfig, TransparencyLogger};

const OLD: &str = "old-8365-governance-key-0123456789abcdef";
const NEW: &str = "new-8365-governance-key-0123456789abcdef";

fn yaml(store: &Path, inv: &Path, key: &str, key_id: &str) -> String {
    format!(
        "security:\n  transparency_log:\n    enabled: true\n    path: '{}'\n    key_id: '{key_id}'\n    \
         shared_secret: '{key}'\nauth:\n  enabled: true\n  bearer_token: f6-test-token\n\
         control_plane:\n  store_dir: '{}'\n",
        inv.display(),
        store.display()
    )
}

fn open(dir: &Path, yaml: &str) -> Arc<dyn ControlPlaneStore> {
    let (config, path) = load(dir, yaml);
    let base = super::super::control_plane_base(&config, Some(&path));
    super::super::build_control_plane_store(&config, &base)
        .expect("the gateway starts")
        .expect("auth on opens the governance store")
}

/// Three entries signed with `key`, so the set has a chain and a `.hwm`.
fn sign(log: &Path, key: &str, key_id: &str) {
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log.to_string_lossy().into_owned(),
        key_id: key_id.into(),
        shared_secret: key.into(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    for i in 0..3 {
        logger
            .log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .expect("append");
    }
}

/// The note's "move the log set aside": the file and every file named after it.
fn move_aside(log: &Path, to: &Path) -> usize {
    let dir = log.parent().expect("parent");
    let stem = log
        .file_stem()
        .expect("stem")
        .to_string_lossy()
        .into_owned()
        + ".";
    std::fs::create_dir_all(to).expect("archive dir");
    let mut moved = 0;
    for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(&stem) && entry.path().is_file() {
            std::fs::rename(entry.path(), to.join(&name)).expect("move");
            moved += 1;
        }
    }
    moved
}

#[test]
fn a_key_change_keeps_grants_and_policies_and_starts_fresh_logs() {
    let (cfg, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store_dir = data.path().join("cp");
    let inv = data.path().join("invocation.jsonl");
    let gov = store_dir.join("audit.jsonl");

    let store = open(cfg.path(), &yaml(&store_dir, &inv, OLD, "v1"));
    let grant = ControlPlaneGrant {
        grant_id: "g-8365".into(),
        subject_id: "user-1".into(),
        server_id: "srv-1".into(),
        tool_id: None,
        status: ControlPlaneGrantStatus::Approved,
    };
    store.put_grant(grant.clone()).expect("grant");
    store
        .put_policy(ControlPlanePolicy {
            policy_id: "p-8365".into(),
            name: "policy".into(),
            enforced: true,
        })
        .expect("policy");
    drop(store);
    sign(&gov, OLD, "v1");
    sign(&inv, OLD, "v1");

    // Both sets, each with its active file and `.hwm` at least.
    assert!(move_aside(&gov, &data.path().join("old-gov")) >= 2);
    assert!(move_aside(&inv, &data.path().join("old-inv")) >= 2);

    let store = open(cfg.path(), &yaml(&store_dir, &inv, NEW, "v2"));
    assert_eq!(store.list_grants().expect("grants"), vec![grant]);
    let policies = store.list_policies().expect("policies");
    assert_eq!(policies.len(), 1, "the policy was lost: {policies:?}");
    assert_eq!(policies[0].policy_id, "p-8365");
    drop(store);
    // The invocation log opens as a fresh chain under the new key.
    sign(&inv, NEW, "v2");
}
