// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7334.CATALOGUE.1` revocation conjunct — the live grant-reload trigger.
//!
//! Cells from `docs/internal/design/2026-09-22-live-identity-grant-reload.md`
//! §3. T1-T5, T2b, T3b, T7, T8, T8b, T9, T11 and R (the §4 rollback delta)
//! are here. T6, T10b and W (the watcher entry point) need `config_reload`
//! internals and live in `config_reload/grant_reload_trigger_tests.rs`, which
//! also records why T10 collapses into T10b. The pool-slot eviction chain is
//! pinned separately in `backend/grant_reload_eviction_tests.rs`.
//!
//! WHERE THE NO-CHANGE COMPARISON LIVES, and why it is not in the publisher.
//! T8/T8b were first written against `set_identity_grants`, because
//! `reload_identity_grants` did not exist. That placement is unsatisfiable:
//! `policy_epoch_tests` publishes an empty store into an empty one and
//! requires the epoch to MOVE, so to it the publish IS the event, and a
//! no-change check inside the publisher reds it. The design puts the
//! comparison one level up, on the LOADED store, which is where these cells
//! now drive it. Their assertions are unchanged.

// Declared here rather than in `meta_mcp/mod.rs`, which sits at its
// file-size ratchet: the doc-example cells are grant cells too.
#[path = "identity_grant_doc_tests.rs"]
mod identity_grant_doc_tests;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use chrono::{Duration as ChronoDuration, Utc};

use super::BackendRegistry;
use super::MetaMcp;
use crate::config_reload::{IdentityGrantSink, ReloadContext};
use crate::identity_grants::{
    CapabilityExposure, GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantRequest,
    LocalIdentityGrantStore,
};

fn grant(grant_id: &str, subject: &str, capability: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("https://idp".to_string(), subject.to_string(), None),
        agent: GrantAgent::Any,
        capability: capability.to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "fixture".to_string(),
        reason: "grant-reload cell".to_string(),
    }
}

fn meta() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

/// Write a grants file the production reader accepts.
fn write_grants(path: &std::path::Path, rows: &[IdentityGrant]) {
    let file = serde_json::json!({
        "schema_version": crate::identity_grants::IDENTITY_GRANTS_FILE_SCHEMA_VERSION,
        "grants": rows,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&file).expect("serialize")).expect("write");
}

/// A reload context wired to `meta`'s live store and to `path`.
///
/// DRIVEN THROUGH THE REAL TRIGGER. An earlier draft of T8/T8b called
/// `set_identity_grants` directly, because `reload_identity_grants` did not
/// exist. That form cannot be satisfied: `policy_epoch_tests` publishes an
/// empty store into an empty one and requires the epoch to MOVE, so a
/// no-change comparison inside the publisher would red it. The comparison
/// belongs one level up, on the loaded store, which is where the design put
/// it and where these cells now observe it. The assertions are unchanged.
fn reload_ctx(meta: &MetaMcp, path: &std::path::Path) -> ReloadContext {
    let (store, epoch) = meta.identity_grant_sink();
    ReloadContext::new(
        path.to_path_buf(),
        Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    )
    .with_identity_grant_sink(Arc::new(IdentityGrantSink::new(
        store,
        epoch,
        path.to_path_buf(),
    )))
}

// T7 — goes red when the publisher forgets the epoch, so a stale response-cache
// entry outlives the grant change.
//
// GREEN TODAY, and labelled rather than counted: `set_identity_grants` bumps
// unconditionally, which is exactly the behaviour T8 says is wrong in the other
// direction. The pair is the point — T7 pins that a real change advances the
// epoch, T8 pins that a non-change does not, and an implementation of piece 4
// that over-corrects by never bumping goes red HERE.
//
// HONEST LIMIT: driven through `set_identity_grants` rather than through
// `reload_identity_grants`, which does not exist. Driven that way it re-proves
// `policy_epoch_tests.rs`'s existing assertion; it earns its place only once
// the reload path is the caller.
#[test]
fn t7_a_grant_change_advances_the_epoch() {
    let meta = meta();
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([grant(
        "g1", "alice", "cal",
    )]));
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // A genuine change: the grant is revoked.
    let mut revoked = grant("g1", "alice", "cal");
    revoked.revoked_at = Some(Utc::now());
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([revoked]));

    assert!(
        meta.policy_epoch.load(Ordering::Acquire) > before,
        "T7: a grant change must strand every key minted under the old grants"
    );
}

// T8 — RED TODAY against shipped code.
//
// Goes red when a no-op reload churns every caller's response cache.
// `set_identity_grants` bumps unconditionally, so a reload against a file
// byte-identical to the live store advances the global epoch and invalidates
// every caller's entries for nothing. This cell is what forces the `PartialEq`
// comparison, and why that comparison is MVP rather than polish.
#[tokio::test]
async fn t8_publishing_an_unchanged_store_must_not_advance_the_epoch() {
    let meta = meta();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let rows = [grant("g1", "alice", "cal"), grant("g2", "bob", "mail")];
    write_grants(&path, &rows);
    let ctx = reload_ctx(&meta, &path);

    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is valid");

    // PREMISE, in this cell's own body: the store really is populated, so the
    // cell cannot pass by publishing nothing into nothing.
    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8 premise: the live store must be populated before the no-op reload"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // The same file again, byte for byte.
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is still valid");

    assert_eq!(
        meta.policy_epoch.load(Ordering::Acquire),
        before,
        "T8: a reload that changed nothing must not flush every caller's cache"
    );
}

// T8b — RED TODAY, same blast radius as T8 reached by a different route.
//
// Goes red when a REORDERED file reads as a change. This is the cell that
// forces the comparison to be defined on normalised store contents rather than
// on file bytes or the file's `Vec` order: `LocalIdentityGrantStore` is a
// `BTreeMap` keyed by grant id, so loading normalises order for free — but only
// if the comparison happens on the loaded store.
#[tokio::test]
async fn t8b_a_reordered_file_must_not_read_as_a_change() {
    let meta = meta();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let a = grant("g1", "alice", "cal");
    let b = grant("g2", "bob", "mail");
    write_grants(&path, &[a.clone(), b.clone()]);
    let ctx = reload_ctx(&meta, &path);

    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture file is valid");

    assert_eq!(
        meta.identity_grant_rows().len(),
        2,
        "T8b premise: the live store must be populated before the reorder"
    );
    let before = meta.policy_epoch.load(Ordering::Acquire);

    // The same two rows, in the opposite file order.
    write_grants(&path, &[b, a]);
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("a reordered file is still valid");

    assert_eq!(
        meta.policy_epoch.load(Ordering::Acquire),
        before,
        "T8b: row order in the file is not a policy change"
    );
}

// T11 — the guard, and labelled as one rather than counted as new coverage.//
// Goes red when expiry regressed: the one liveness property that already works
// against in-memory data, and the cheapest thing for this change to break.
// Time advances against the store with NO reload at all.
// GREEN BEFORE AND AFTER by design.
#[test]
fn t11_guard_expiry_is_live_without_any_reload() {
    let subject = GrantSubject::new("https://idp".to_string(), "alice".to_string(), None);
    let mut expiring = grant("g1", "alice", "cal");
    expiring.expires_at = Some(Utc::now() + ChronoDuration::seconds(60));
    let store = LocalIdentityGrantStore::from_grants([expiring]);

    let request = |now| IdentityGrantRequest {
        identity: Some(subject.clone()),
        agent_id: None,
        capability: "cal".to_string(),
        tool: None,
        scope: GrantScope::Read,
        exposure: CapabilityExposure::Personal,
        owner: Some(subject.clone()),
        now,
    };

    // PREMISE, in this cell's own body: the grant allows BEFORE its expiry.
    // Without it the denial below would hold for a store that denies
    // everything, which is the one-sided form this house has already refused.
    assert!(
        store.evaluate(&request(Utc::now())).allowed,
        "T11 premise: an unexpired grant must allow"
    );
    // Only the clock moves. No reload, no publish, no epoch bump.
    assert!(
        !store
            .evaluate(&request(Utc::now() + ChronoDuration::seconds(120)))
            .allowed,
        "T11: an elapsed expiry must deny with no reload at all"
    );
}

// T3b — the torn read that is VALID, and the dangerous half.
//
// Goes red when an interrupted grant-file write can be observed as a SHORT
// but well-formed file. `IdentityGrantFile` defaults both `schema_version`
// and `grants`, and the schema check compares against the constant it
// defaults to, so a write interrupted after the header parses cleanly as zero
// grants — bit-for-bit the deliberate revoke-everything file. With a
// truncating write, an interrupted `identity grant add` revokes EVERYTHING,
// through the success path.
//
// THE ASSERTION IS THAT THE STATE IS UNREACHABLE, NOT THAT THE PARSER REJECTS
// IT. A parse rejection would pin the wrong layer and would break the
// legitimate `grants: []` escape hatch, which is the same bytes. No parser can
// separate them; only the writer can, by never publishing a prefix.
//
// The observable is the destination's IDENTITY. A truncating write keeps the
// inode and empties it in place, so a reader holding the path can see a
// prefix. An atomic replace writes a scratch file, fsyncs it, and renames it
// over the destination, so the inode CHANGES and every observer sees either
// the whole old file or the whole new one. Deterministic: it goes red against
// `tokio::fs::write` without needing a race to be lost.
#[tokio::test]
async fn t3b_a_grant_file_write_is_never_observable_as_a_valid_prefix() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    write_grants(&path, &[grant("g1", "alice", "cal")]);

    // PREMISE, in this cell's own body: the destination exists and holds a
    // row, so the write below really replaces real content.
    let before = std::fs::metadata(&path).expect("seeded file").ino();
    assert_eq!(
        crate::identity_grants::read_identity_grants_file(&path)
            .await
            .expect("the seeded file parses")
            .grants
            .len(),
        1,
        "T3b premise: the destination must hold a row before it is replaced"
    );

    let file = crate::identity_grants::IdentityGrantFile::new(vec![
        grant("g1", "alice", "cal"),
        grant("g2", "bob", "mail"),
    ]);
    crate::identity_grants::write_identity_grants_file(&path, &file)
        .await
        .expect("the production writer replaces the grants file");

    assert_ne!(
        std::fs::metadata(&path).expect("replaced file").ino(),
        before,
        "T3b: the destination must be REPLACED by rename, not truncated in \
         place; a truncating write is observable as a valid short file"
    );
    assert_eq!(
        crate::identity_grants::read_identity_grants_file(&path)
            .await
            .expect("the replaced file parses")
            .grants
            .len(),
        2,
        "T3b: and the replacement must be the COMPLETE new content"
    );

    // No scratch debris beside the destination: a stranded partial grants file
    // is its own hazard.
    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| name != "grants.json")
        .collect();
    assert!(
        strays.is_empty(),
        "T3b: the atomic write must leave no scratch file behind, found {strays:?}"
    );
}

// -------------------------------------------------------------------------
// MIK-7537 — the remaining §3 cells, driven through the grants file.
// -------------------------------------------------------------------------

fn revoked(mut row: IdentityGrant) -> IdentityGrant {
    row.revoked_at = Some(Utc::now() - ChronoDuration::seconds(1));
    row
}

/// The live authorization decision, read from `meta`'s store as `invoke` does.
fn allows(meta: &MetaMcp, subject: &str, capability: &str) -> bool {
    let subject = GrantSubject::new("https://idp".to_string(), subject.to_string(), None);
    meta.identity_grants
        .read()
        .evaluate(&IdentityGrantRequest {
            identity: Some(subject.clone()),
            agent_id: None,
            capability: capability.to_string(),
            tool: None,
            scope: GrantScope::Read,
            exposure: CapabilityExposure::Personal,
            owner: Some(subject),
            now: Utc::now(),
        })
        .allowed
}

/// `meta` with alice/cal and bob/mail live, loaded through the reload path.
async fn populated(path: &std::path::Path) -> (MetaMcp, ReloadContext) {
    let meta = meta();
    write_grants(
        path,
        &[grant("g1", "alice", "cal"), grant("g2", "bob", "mail")],
    );
    let ctx = reload_ctx(&meta, path);
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture grants are valid");
    assert!(
        allows(&meta, "alice", "cal") && allows(&meta, "bob", "mail"),
        "premise: both grants allow before the cell acts"
    );
    (meta, ctx)
}

// T1 — the bug: a revocation never reaches the running process.
// GREEN since #707 on this entry point; labelled as a control. The red cell for
// the entry point that still skipped grants is W in
// `config_reload/grant_reload_trigger_tests.rs`.
#[tokio::test]
async fn t1_control_a_revocation_on_disk_denies_after_a_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;

    write_grants(
        &path,
        &[
            revoked(grant("g1", "alice", "cal")),
            grant("g2", "bob", "mail"),
        ],
    );
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("a revocation is a valid grants file");

    assert!(
        !allows(&meta, "alice", "cal"),
        "T1: the revoked grant must deny"
    );
    assert!(
        allows(&meta, "bob", "mail"),
        "T1: an unrelated grant must still allow"
    );
}

// T5 — "revoke everything" must stay expressible: a VALID empty list applies.
// Mirror image of T2 on the same input shape; the two fail in opposite
// directions, so neither passes vacuously. Control.
#[tokio::test]
async fn t5_control_a_valid_empty_list_revokes_everything() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;

    write_grants(&path, &[]);
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("T5: a valid empty list must apply, not refuse");

    assert!(
        meta.identity_grant_rows().is_empty(),
        "T5: the store must be empty"
    );
    assert!(
        !allows(&meta, "alice", "cal"),
        "T5: nothing may allow afterwards"
    );
}

/// The four assertions T2, T3 and T4 share: the reload refuses, naming the
/// path, and the live store, the decision and the epoch are all untouched.
async fn assert_refused_and_inert(
    cell: &str,
    meta: &MetaMcp,
    ctx: &ReloadContext,
    path: &std::path::Path,
) {
    let rows_before = meta.identity_grant_rows();
    let epoch_before = meta.policy_epoch.load(Ordering::Acquire);

    let refusal = ctx
        .reload_identity_grants()
        .await
        .expect("a wired sink reports")
        .expect_err(&format!(
            "{cell}: an unusable grants file must refuse, not report Ok"
        ));

    assert!(
        refusal.contains(&path.display().to_string()),
        "{cell}: the refusal must name the path: {refusal}"
    );
    assert_eq!(
        meta.identity_grant_rows(),
        rows_before,
        "{cell}: a refused reload must leave the live store identical"
    );
    assert!(
        allows(meta, "alice", "cal"),
        "{cell}: the live grant must still allow"
    );
    assert_eq!(
        meta.policy_epoch.load(Ordering::Acquire),
        epoch_before,
        "{cell}: a refused reload must not advance the epoch"
    );
}

// T2 — a corrupt grants file must not drop live grants (fail open, §D3). Control.
#[tokio::test]
async fn t2_control_a_corrupt_grants_file_keeps_the_live_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;
    std::fs::write(&path, b"{ this is not json").expect("corrupt");
    assert_refused_and_inert("T2", &meta, &ctx, &path).await;
}

// T3 — a torn read that is INVALID must not drop live grants. Control; T3b is
// the valid-prefix half.
#[tokio::test]
async fn t3_control_a_grants_file_cut_mid_token_keeps_the_live_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;
    let whole = std::fs::read(&path).expect("read");
    std::fs::write(&path, &whole[..whole.len() / 2]).expect("truncate");
    assert_refused_and_inert("T3", &meta, &ctx, &path).await;
}

// T4 — a missing grants file is not a revocation. Control.
#[tokio::test]
async fn t4_control_a_deleted_grants_file_keeps_the_live_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;
    std::fs::remove_file(&path).expect("delete");
    assert_refused_and_inert("T4", &meta, &ctx, &path).await;
}

// T2b — a refused reload must not flush every caller's result cache. The key
// is REBUILT from the live epoch after three refusals, never remembered: the
// property is that the epoch did not move. Control.
#[tokio::test]
async fn t2b_control_repeated_refusals_keep_every_cached_answer_servable() {
    use super::support::response_cache_key_for;
    use crate::cache::{KeyContext, ResponseCache};
    use crate::protocol::mrtr::RetryFields;

    let key_now = |meta: &MetaMcp| {
        response_cache_key_for(
            "srv",
            "tool",
            &serde_json::json!({"a": 1}),
            "",
            &super::support::CachePrincipal::Caller("bob".to_string()),
            &RetryFields::default(),
            KeyContext {
                routing_profile: "default",
                protocol_revision: None,
                policy_epoch: meta.policy_epoch.load(Ordering::Acquire),
            },
        )
        .expect("a resolved principal has a key")
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;
    let cache = ResponseCache::new();
    assert!(
        cache.set(
            &key_now(&meta),
            serde_json::json!({"answer": "cached"}),
            std::time::Duration::from_secs(60)
        ),
        "T2b premise: the answer must actually be cached"
    );

    std::fs::write(&path, b"{ still not json").expect("corrupt");
    for _ in 0..3 {
        assert!(
            matches!(ctx.reload_identity_grants().await, Some(Err(_))),
            "T2b premise: every attempt must refuse"
        );
    }
    assert!(
        cache.get(&key_now(&meta)).is_some(),
        "T2b: three refused reloads must leave every cached answer servable"
    );
}

// T9 — RED before MIK-7537: a config refusal must not hide the grant step.
//
// Driven through `reload_config`, the body of the `gateway_reload_config`
// meta-tool (the dispatcher's admin gate is not the subject here), against a
// config the posture check refuses and a grants file carrying a revocation.
// The denial proves the grant step ran through the same invocation that
// refused the config step. The error text is the red half: §D4 requires both
// outcomes on every path, and a refusal that drops the grants line tells the
// operator nothing happened when their revocation in fact landed.
#[tokio::test]
async fn t9_a_config_refusal_still_reports_and_applies_the_revocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let grants_path = dir.path().join("grants.json");
    let config_path = dir.path().join("gateway.yaml");
    let meta = meta();
    write_grants(
        &grants_path,
        &[grant("g1", "alice", "cal"), grant("g2", "bob", "mail")],
    );
    let (store, epoch) = meta.identity_grant_sink();
    let ctx = ReloadContext::new(
        config_path.clone(),
        Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        Arc::new(BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    )
    .with_identity_grant_sink(Arc::new(IdentityGrantSink::new(
        store,
        epoch,
        grants_path.clone(),
    )));
    ctx.reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("the fixture grants are valid");
    assert!(allows(&meta, "alice", "cal"), "T9 premise: alice allowed");
    meta.set_reload_context(Arc::new(ctx));

    // Publishing a URL over open tools is refused before any publication.
    crate::gateway::test_helpers::write_owner_only(
        &config_path,
        "server:\n  public_url: \"https://gw.example.com\"\n",
    )
    .expect("write config");
    write_grants(
        &grants_path,
        &[
            revoked(grant("g1", "alice", "cal")),
            grant("g2", "bob", "mail"),
        ],
    );

    let err = meta
        .reload_config()
        .await
        .expect_err("T9 premise: the config half must refuse")
        .to_string();

    assert!(
        !allows(&meta, "alice", "cal"),
        "T9: the revocation must apply"
    );
    assert!(
        allows(&meta, "bob", "mail"),
        "T9: an unrelated grant must still allow"
    );
    assert!(
        err.contains("config reload refused:"),
        "T9 premise: the config refusal is the one reported: {err}"
    );
    assert!(
        err.contains("identity grants reloaded"),
        "T9: the refusal must still report the grant step that applied: {err}"
    );
}

// R — RED before MIK-7537: a rollback must show as a negative revocation
// count (§4 item 2). The grants file is authoritative on reload, so restoring
// an old one silently un-revokes; the reported delta is the cheap tripwire.
#[tokio::test]
async fn r_a_restored_backup_reports_a_negative_revocation_delta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.json");
    let (meta, ctx) = populated(&path).await;

    write_grants(
        &path,
        &[
            revoked(grant("g1", "alice", "cal")),
            grant("g2", "bob", "mail"),
        ],
    );
    let revoke = ctx
        .reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("valid");
    assert!(
        revoke.contains("revoked +1"),
        "R: a revocation reports +1: {revoke}"
    );

    // The backup from before the revocation comes back.
    write_grants(
        &path,
        &[grant("g1", "alice", "cal"), grant("g2", "bob", "mail")],
    );
    let rollback = ctx
        .reload_identity_grants()
        .await
        .expect("a wired sink reloads")
        .expect("valid");
    assert!(
        rollback.contains("revoked -1"),
        "R: an un-revocation must be visible as a negative count: {rollback}"
    );
    assert!(
        allows(&meta, "alice", "cal"),
        "R premise: the backup re-granted"
    );
}
