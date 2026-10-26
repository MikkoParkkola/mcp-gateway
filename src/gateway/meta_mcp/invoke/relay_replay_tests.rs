// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 3, first batch of design rows at unit level, for the
//! gateway staging in `relay_replay` (stage 2's names:
//! `stage_task_replay`, `stage_plan_replay`, `stage_entries` behind
//! them, `note_replay_call`, `commit_with`). Entries are built by
//! hand — a crafted snapshot in the firewall's store plus a crafted
//! `calls` list — because no production path nests a plan (see
//! `plan_step_guard_tests`). Each row names the mutant it kills.
//!
//! Test plan: the relay replay test plan,
//! as retargeted by design d4 H4.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{
    Kind, RELAY_RECEIPTS, RelayKey, collecting, commit_with, noting_plan_members, plan_step,
};
use super::{ReplayCallList, note_sync_lookup, stage_plan_replay, stage_task_replay, take_capture};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::task_service::{CommittedTask, Target};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, DeliveryDigest, Firewall, FirewallConfig, RelayCaller,
    StoredKey,
};

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

const OTHER_PROSE: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale.";

fn text_result(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

/// A meta whose firewall blocks relays of `alpha:*` and `beta:*` text,
/// every k-gram kept, one fingerprint enough.
fn relay_meta() -> (Arc<MetaMcp>, Arc<Firewall>) {
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec!["alpha:*".to_string(), "beta:*".to_string()],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test()
        .keeping_every_kgram(),
    );
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.share_keyring_with_for_test(&firewall);
    (Arc::new(meta), firewall)
}

/// Whether bob sending `text` through `alpha:send` is refused as a relay.
fn relayed_by_bob(fw: &Firewall, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    !fw.check_relay(
        RelayCaller::Keyed("bob"),
        "alpha",
        "send",
        &params,
        ("s", "bob"),
    )
    .allowed
}

/// A committed receipt's digest for `server:tool` delivering `text`.
fn digest_for(fw: &Firewall, server: &str, tool: &str, text: &str) -> DeliveryDigest {
    fw.receipt_digest(server, tool, &text_result(text), None)
        .expect("relay detection is on: fixture")
}

/// A composite seam's tool identity, as `add_seams` spells it.
fn seam_identity(names: &[&str]) -> String {
    format!("seam{}", serde_json::to_string(&names).unwrap_or_default())
}

/// A sensitive composite seam digest over `names` (`server:tool`s).
fn seam_digest(names: &[&str]) -> DeliveryDigest {
    let sources: Vec<String> = names.iter().map(ToString::to_string).collect();
    DeliveryDigest::of_seam(vec![42], true, Some(sources.into_boxed_slice()))
}

fn at(second: u32) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(&format!("2026-09-07T00:00:{second:02}Z"))
        .expect("fixture timestamp parses: fixture")
        .with_timezone(&chrono::Utc)
}

/// A stored plan task over `targets`, ended as `end` says, revision 1.
fn stored_task(
    targets: &[(&str, &str)],
    end: impl FnOnce(&mut crate::gateway::task_service::Task),
) -> CommittedTask {
    let mut task = crate::gateway::task_service::Task::create_at(
        "gateway_execute",
        at(0),
        crate::protocol::tasks::TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    end(&mut task);
    CommittedTask {
        task,
        revision: 1,
        targets: targets
            .iter()
            .map(|(server, tool)| Target {
                server: server.to_string(),
                tool: tool.to_string(),
            })
            .collect(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    }
}

fn completed(targets: &[(&str, &str)]) -> CommittedTask {
    stored_task(targets, |task| {
        task.complete(&text_result(PROSE))
            .expect("a live task takes its outcome: fixture");
    })
}

/// Store `sources` as `stored`'s replay entry, with its `calls`.
fn store_entry(
    fw: &Firewall,
    stored: &CommittedTask,
    sources: &[(&DeliveryDigest, Option<u32>, &str, &str)],
    calls: ReplayCallList,
) {
    fw.store_replay(
        StoredKey::Task {
            id: stored.task.id().to_owned(),
            revision: stored.revision,
        },
        sources,
        calls,
        "",
        Duration::from_secs(3600),
    );
}

/// One staged receipt, read back: `(server, tool, step, in_plan, replayed)`.
type Summary = (String, String, Option<u32>, bool, bool);

fn staged_summaries() -> Vec<Summary> {
    RELAY_RECEIPTS
        .try_with(|receipts| {
            receipts
                .borrow()
                .iter()
                .map(|r| {
                    (
                        r.server.clone(),
                        r.tool.clone(),
                        r.step,
                        r.in_plan,
                        r.kind == Kind::Replayed,
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn summary(server: &str, tool: &str, step: Option<u32>) -> Summary {
    (server.to_owned(), tool.to_owned(), step, false, true)
}

/// G2: `commit_with(fw, false)` records nothing; `commit_with(fw,
/// true)` records the staged replay receipts. The same staged task
/// replay is committed both ways, and only the delivered one makes
/// bob's relay of the step's text refusable.
/// Mutant killed: commit regardless of delivery (bob would already
/// be refused after the `false` commit).
#[tokio::test]
async fn g2_an_undelivered_commit_records_no_replayed_receipt() {
    let (meta, fw) = relay_meta();
    let stored = completed(&[("alpha", "read"), ("beta", "read")]);
    let digest = digest_for(&fw, "alpha", "read", PROSE);
    store_entry(
        &fw,
        &stored,
        &[(&digest, Some(0), "alpha", "read")],
        vec![(Some(0), "alpha".to_owned(), "read".to_owned())],
    );
    let alice = RelayKey::new("alice", true);
    collecting(async {
        stage_task_replay(&meta, alice, &stored);
        assert_eq!(
            staged_summaries().len(),
            1,
            "premise: the replay staged its receipt"
        );
        commit_with(&fw, false);
    })
    .await;
    assert!(
        !relayed_by_bob(&fw, PROSE),
        "an undelivered frame recorded the staged replay receipt"
    );
    collecting(async {
        stage_task_replay(&meta, alice, &stored);
        commit_with(&fw, true);
    })
    .await;
    assert!(
        relayed_by_bob(&fw, PROSE),
        "control: a delivered commit records the staged replay receipt"
    );
}

/// G3 / G35: the task-path targets check. A snapshot whose plain
/// source (`gamma:read`) is not in `stored.targets` stages nothing;
/// a composite seam stages only when every constituent is in
/// `targets`, and then keeps its composite identity (empty server,
/// `seam[...]` tool) and its `seam_sources`, from which recording
/// derives the every-source-must-allow flow policy. With one
/// constituent (`beta:read`) missing from `targets`, the seam
/// stages nothing while the present plain source still does.
/// Mutants killed: drop the targets check (gamma and the
/// beta-missing seam would stage); compare the composite identity
/// string to `targets` (the seam would never stage).
#[tokio::test]
async fn g3_g35_sources_outside_the_task_targets_stage_nothing() {
    let (meta, fw) = relay_meta();
    let plain = digest_for(&fw, "alpha", "read", PROSE);
    let outside = digest_for(&fw, "gamma", "read", OTHER_PROSE);
    let seam_names = ["alpha:read", "beta:read"];
    let seam = seam_digest(&seam_names);
    let identity = seam_identity(&seam_names);
    let alice = RelayKey::new("alice", true);
    for (targets, seam_stages) in [
        (vec![("alpha", "read"), ("beta", "read")], true),
        (vec![("alpha", "read")], false),
    ] {
        let stored = completed(&targets);
        let calls: ReplayCallList = vec![
            (Some(0), "alpha".to_owned(), "read".to_owned()),
            (Some(1), "gamma".to_owned(), "read".to_owned()),
        ];
        store_entry(
            &fw,
            &stored,
            &[
                (&plain, Some(0), "alpha", "read"),
                (&outside, Some(1), "gamma", "read"),
                (&seam, None, "", identity.as_str()),
            ],
            calls,
        );
        if seam_stages {
            let (digests, _) = fw
                .replay_digests(&StoredKey::Task {
                    id: stored.task.id().to_owned(),
                    revision: stored.revision,
                })
                .expect("the entry was just stored: fixture");
            let seam_entry = digests
                .iter()
                .find(|entry| entry.seam_sources.is_some())
                .expect("the stored entry holds the seam: fixture");
            assert_eq!(
                seam_entry.seam_sources.as_deref(),
                Some(["alpha:read".to_owned(), "beta:read".to_owned()].as_slice()),
                "premise: the seam keeps its constituents, so its flow policy is kept"
            );
        }
        let staged = collecting(async {
            stage_task_replay(&meta, alice, &stored);
            staged_summaries()
        })
        .await;
        let mut expected = vec![summary("alpha", "read", Some(0))];
        if seam_stages {
            expected.push(summary("", &identity, None));
        }
        assert_eq!(staged, expected, "targets: {targets:?}");
    }
}

/// G4: a stored entry with no replay-store entry (a restart, an
/// eviction, detection off at delivery) stages nothing and is no
/// error — both stagings simply return — and each lookup is counted
/// `reason=absent`.
/// Mutant killed: error or panic on a missing entry (the staging
/// calls below would not return), or rebuild from the stored answer
/// when absent (a receipt would stage).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g4_an_absent_store_entry_stages_nothing() {
    let (meta, _fw) = relay_meta();
    let stored = completed(&[("alpha", "read"), ("beta", "read")]);
    let alice = RelayKey::new("alice", true);
    let measured = collecting(async {
        stage_task_replay(&meta, alice, &stored);
        note_sync_lookup("id".to_owned(), "round".to_owned(), "op".to_owned());
        stage_plan_replay(&meta, alice);
        staged_summaries()
    });
    #[cfg(feature = "metrics")]
    let (staged, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
    #[cfg(not(feature = "metrics"))]
    let staged = measured.await;
    assert!(
        staged.is_empty(),
        "an absent store entry staged a receipt: {staged:?}"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        absent, 2,
        "the two absent lookups (task and sync) were not each counted reason=absent"
    );
}

/// A crafted nested entry, shared by G6/G40 and N2: label 1 ran two
/// inner calls (S1 `alpha:read` over [`PROSE`], S2 `beta:read` over
/// [`OTHER_PROSE`]); the entry also holds a seam over the nested
/// calls' sources and a seam lying entirely outside the nested
/// label, over the plain steps `delta`/`epsilon`. Built by hand —
/// no production path nests (see the module docs).
fn nested_rig() -> (Arc<MetaMcp>, Arc<Firewall>, CommittedTask) {
    let (meta, fw) = relay_meta();
    let stored = completed(&[
        ("alpha", "read"),
        ("beta", "read"),
        ("delta", "read"),
        ("epsilon", "read"),
    ]);
    let alpha_inner = digest_for(&fw, "alpha", "read", PROSE);
    let beta_inner = digest_for(&fw, "beta", "read", OTHER_PROSE);
    let nested_names = ["alpha:read", "beta:read"];
    let outside_names = ["delta:read", "epsilon:read"];
    let nested_seam = seam_digest(&nested_names);
    let outside_seam = seam_digest(&outside_names);
    let nested_id = seam_identity(&nested_names);
    let outside_id = seam_identity(&outside_names);
    store_entry(
        &fw,
        &stored,
        &[
            (&alpha_inner, Some(1), "alpha", "read"),
            (&beta_inner, Some(1), "beta", "read"),
            (&nested_seam, None, "", nested_id.as_str()),
            (&outside_seam, None, "", outside_id.as_str()),
        ],
        vec![
            (Some(1), "alpha".to_owned(), "read".to_owned()),
            (Some(1), "beta".to_owned(), "read".to_owned()),
            (Some(0), "delta".to_owned(), "read".to_owned()),
            (Some(2), "epsilon".to_owned(), "read".to_owned()),
        ],
    );
    (meta, fw, stored)
}

/// G6 / G40, rewritten per d4 H4: a nested label's inner receipts
/// stage under their own sources (and their shared label), while
/// EVERY seam receipt of the entry is dropped, counted
/// `reason=nested_seam` — including the seam over `delta`/`epsilon`,
/// which lies entirely outside the nested label.
/// Mutants killed: stage the seams (a seam summary would appear);
/// drop only seams touching the nested label (the outside seam
/// would appear); skip the nested label's receipts (an inner
/// summary would be missing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g6_g40_a_nested_label_stages_its_inner_receipts_and_no_seam() {
    let (meta, _fw, stored) = nested_rig();
    let measured = collecting(async {
        stage_task_replay(&meta, RelayKey::new("alice", true), &stored);
        staged_summaries()
    });
    #[cfg(feature = "metrics")]
    let (staged, dropped) = crate::gateway::count_plan_replay_skipped("nested_seam", measured);
    #[cfg(not(feature = "metrics"))]
    let staged = measured.await;
    assert_eq!(
        staged,
        vec![
            summary("alpha", "read", Some(1)),
            summary("beta", "read", Some(1)),
        ],
        "the inner receipts stage under their own sources and no seam stages"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        dropped, 2,
        "both dropped seams were not counted exactly once each reason=nested_seam"
    );
}

/// N2 (MIK-8409.NESTED.2): in the crafted nested replay, each inner
/// call's staged receipt holds fingerprints of its own text only.
/// Read through recording: staging both inner receipts, keeping
/// only S2's (`beta`) and committing, makes bob's relay of S2's
/// text refusable and leaves S1's text unrefused — S2's receipt
/// holds no fingerprint of S1's text. The S1 half is the mirror.
/// Mutant killed: stage the label's whole text under each inner
/// call (the kept receipt would also refuse the other text).
#[tokio::test]
async fn n2_an_inner_receipt_holds_no_fingerprint_of_the_other_inner_text() {
    for (kept, own, other) in [("alpha", PROSE, OTHER_PROSE), ("beta", OTHER_PROSE, PROSE)] {
        let (meta, fw, stored) = nested_rig();
        assert!(
            !relayed_by_bob(&fw, own) && !relayed_by_bob(&fw, other),
            "premise: nothing is recorded yet for {kept}"
        );
        collecting(async {
            stage_task_replay(&meta, RelayKey::new("alice", true), &stored);
            let kept_only = RELAY_RECEIPTS.try_with(|receipts| {
                receipts.borrow_mut().retain(|r| r.server == kept);
            });
            assert!(kept_only.is_ok(), "premise: inside a collector");
            commit_with(&fw, true);
        })
        .await;
        assert!(
            relayed_by_bob(&fw, own),
            "control: {kept}'s own text is receipted by its inner receipt"
        );
        assert!(
            !relayed_by_bob(&fw, other),
            "{kept}'s staged receipt holds a fingerprint of the other inner call's text"
        );
    }
}

/// G10: the replay store holds an entry for the task, but the stored
/// multi-target row is `InputRequired` or `Failed`: a read stages
/// nothing from it — only the `Completed` arm reaches
/// `stage_task_replay` (the control below).
/// Mutant killed: route the non-completed multi-target reads into
/// the task staging (the stored entry would renew and bob would be
/// refused).
#[tokio::test]
async fn g10_a_non_completed_multi_target_read_stages_nothing() {
    let targets = [("alpha", "read"), ("beta", "read")];
    for (name, stored, renews) in [
        (
            "input_required",
            stored_task(&targets, |task| {
                task.transition(
                    crate::protocol::tasks::TaskTransition::RequireInput(
                        crate::protocol::mrtr::InputRequired {
                            requests: vec![(
                                "confirm".to_owned(),
                                json!({"method": "elicitation/create", "params": {}}),
                            )],
                            request_state: None,
                        },
                    ),
                    at(1),
                )
                .expect("a live task takes an input round: fixture");
            }),
            false,
        ),
        (
            "failed",
            stored_task(&targets, |task| {
                task.fail(&crate::protocol::JsonRpcError {
                    code: -32042,
                    message: "the backend failed".to_owned(),
                    data: None,
                })
                .expect("a live task takes its outcome: fixture");
            }),
            false,
        ),
        ("completed", completed(&targets), true),
    ] {
        let (meta, fw) = relay_meta();
        let digest = digest_for(&fw, "alpha", "read", PROSE);
        store_entry(
            &fw,
            &stored,
            &[(&digest, Some(0), "alpha", "read")],
            vec![(Some(0), "alpha".to_owned(), "read".to_owned())],
        );
        assert!(
            fw.replay_digests(&StoredKey::Task {
                id: stored.task.id().to_owned(),
                revision: stored.revision,
            })
            .is_some(),
            "premise ({name}): a store entry is present for the key"
        );
        let ((), staged) = meta
            .collecting_staged(async {
                meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
            })
            .await;
        staged.commit(true);
        assert_eq!(
            relayed_by_bob(&fw, PROSE),
            renews,
            "{name}: a non-completed multi-target read renewed the receipt"
        );
    }
}

/// G13 (test-plan §4, in stage 2's names): `stage_task_replay`
/// called inside `plan_step(Some(7))` — a replay delivered as one
/// step of a live outer plan — stages its receipts under the outer
/// label 7, as a plan receipt of the outer plan, and notes no plan
/// members; outside any live step the same staging keeps each
/// snapshot's own label (3 and 4 below), not 7.
/// Mutant killed: the staging overwriting the inherited label with
/// a scope of its own (the inside-step receipts would carry 3/4,
/// so the outer plan's final pass would keep them against members
/// they do not own), or noting members for a replayed answer.
#[tokio::test]
async fn g13_a_replay_inside_a_live_step_takes_the_outer_label() {
    let (meta, fw) = relay_meta();
    let stored = completed(&[("alpha", "read"), ("beta", "read")]);
    let first = digest_for(&fw, "alpha", "read", PROSE);
    let second = digest_for(&fw, "beta", "read", OTHER_PROSE);
    store_entry(
        &fw,
        &stored,
        &[
            (&first, Some(3), "alpha", "read"),
            (&second, Some(4), "beta", "read"),
        ],
        vec![
            (Some(3), "alpha".to_owned(), "read".to_owned()),
            (Some(4), "beta".to_owned(), "read".to_owned()),
        ],
    );
    let alice = RelayKey::new("alice", true);
    let outside = collecting(async {
        stage_task_replay(&meta, alice, &stored);
        staged_summaries()
    })
    .await;
    assert_eq!(
        outside,
        vec![
            summary("alpha", "read", Some(3)),
            summary("beta", "read", Some(4)),
        ],
        "outside a live step each receipt keeps its own snapshot label"
    );
    let (inside, members) = noting_plan_members(RELAY_RECEIPTS.scope(
        RefCell::new(Vec::new()),
        plan_step(Some(7), async {
            stage_task_replay(&meta, alice, &stored);
            staged_summaries()
        }),
    ))
    .await;
    assert_eq!(
        inside,
        vec![
            ("alpha".to_owned(), "read".to_owned(), Some(7), true, true),
            ("beta".to_owned(), "read".to_owned(), Some(7), true, true),
        ],
        "inside a live step the receipts take the outer label, as plan receipts"
    );
    assert!(
        members.is_empty(),
        "staging a replay noted plan members: {members:?}"
    );
}

/// G44: the noting site at the dispatch tail (`invoke_tool_with_source`
/// beside `dispatch_log::note_completed`). A response-cache hit
/// inside `plan_step(Some(1))` — the second identical invoke, which
/// dispatches nothing — still notes `(1, alpha, read)` into this
/// delivery's `calls`, because the cache returns run inside that
/// future. A `Forbidden` outcome (bob's relay refused before
/// dispatch) notes nothing.
/// Mutant killed: note only on a live dispatch (the cache hit would
/// note nothing), or note on every outcome (the refused call would
/// be noted, crediting a step that never ran).
#[tokio::test]
async fn g44_a_cache_hit_notes_its_step_and_a_forbidden_outcome_notes_nothing() {
    use crate::gateway::authz::AllowAll;
    use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
    use std::sync::atomic::Ordering;

    let allow = AllowAll;
    // Cache hit: prime once, then repeat inside the labelled step.
    let (registry, dispatched) = counted_backend("alpha");
    let cached = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let args = invoke_args("alpha", "read");
    let caller = ctx(&allow);
    let primed = cached.invoke_tool(&args, None, &caller).await;
    assert!(
        primed.is_ok(),
        "premise: the priming call succeeds: {primed:?}"
    );
    assert_eq!(dispatched.load(Ordering::SeqCst), 1, "premise: primed once");
    let calls = collecting(async {
        let hit = plan_step(Some(1), cached.invoke_tool(&args, None, &caller)).await;
        assert!(hit.is_ok(), "premise: the cache hit succeeds: {hit:?}");
        take_capture().1
    })
    .await;
    assert_eq!(
        dispatched.load(Ordering::SeqCst),
        1,
        "premise: the repeat was a cache hit, nothing dispatched"
    );
    assert_eq!(
        calls,
        vec![(Some(1), "alpha".to_owned(), "read".to_owned())],
        "the cache hit noted no step"
    );

    // Forbidden: bob relays alice's delivered text, refused pre-dispatch.
    let (registry, dispatched) = counted_backend("alpha");
    let (_meta, fw) = relay_meta();
    let mut guarded = MetaMcp::new(registry);
    guarded.set_firewall(Some(Arc::clone(&fw)));
    guarded.share_keyring_with_for_test(&fw);
    fw.record_delivery(
        RelayCaller::Keyed("alice"),
        "alpha",
        "read",
        &text_result(PROSE),
    );
    let bob = crate::gateway::meta_mcp::MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&allow)
    };
    let relaying = json!({"server": "alpha", "tool": "read", "arguments": {"text": PROSE}});
    let (outcome, calls) = collecting(async {
        let outcome = plan_step(Some(1), guarded.invoke_tool(&relaying, None, &bob)).await;
        (outcome, take_capture().1)
    })
    .await;
    assert!(
        matches!(outcome, Err(crate::Error::Forbidden { .. })),
        "premise: the relay is refused as Forbidden: {outcome:?}"
    );
    assert_eq!(
        dispatched.load(Ordering::SeqCst),
        0,
        "premise: the refused call never dispatched"
    );
    assert!(
        calls.is_empty(),
        "a Forbidden outcome noted a step call: {calls:?}"
    );
}

/// G48 (d4 H1/H4): no record version change for a plan task row. A
/// plan task (two recorded targets) created through the task
/// service's create path — the path a settled plan's replay entry
/// is keyed by `(task id, revision)` over — is written at record
/// version 9, spelled literally so the number cannot drift with a
/// constant, and a reopened store loads it (a row above
/// `MAX_LOADABLE_VERSION` would be sealed, not read back).
/// Mutant killed: bump the record version for plan rows (the
/// literal 9 on disk fails; an unraised loader would also seal it).
#[tokio::test]
async fn g48_a_plan_task_row_is_written_at_version_9_and_loads() {
    use crate::gateway::task_service::{CreateOutcome, StoreLimits, TaskService};
    use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};

    let dir = tempfile::tempdir().expect("a private task-store directory: fixture");
    let store_dir = dir.path().join("tasks");
    let operation = json!({"name": "gateway_execute", "chain": ["alpha:read", "beta:read"]});
    let representation = json!({"full": false});
    let task = crate::gateway::task_service::Task::create_at(
        "gateway_execute",
        at(0),
        crate::protocol::tasks::TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let id = task.id().to_owned();
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = TaskService::open(&store_dir, StoreLimits::default(), admission)
        .await
        .expect("a fresh directory opens: fixture");
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let created = service
        .create_targeted(
            Request {
                principal: "alice",
                key: "g48-plan",
                operation: &operation,
                representation: &representation,
                mode: Mode::Task,
            },
            &task,
            (
                "gateway_execute",
                vec![
                    Target {
                        server: "alpha".to_owned(),
                        tool: "read".to_owned(),
                    },
                    Target {
                        server: "beta".to_owned(),
                        tool: "read".to_owned(),
                    },
                ],
            ),
            move || workers.try_acquire_owned().ok(),
        )
        .await;
    let CreateOutcome::Created { task: row, .. } = created else {
        panic!("premise: a fresh keyed plan task is Created");
    };
    assert_eq!(row.task.id(), id.as_str(), "premise: the created row");
    assert_eq!(row.targets.len(), 2, "premise: a plan row, two targets");
    service.close().await.expect("the store closes: fixture");

    let bytes = std::fs::read(store_dir.join(format!("{id}.json")))
        .expect("the created row is on disk: fixture");
    let on_disk: Value = serde_json::from_slice(&bytes).expect("the created row parses: fixture");
    assert_eq!(
        on_disk["version"],
        json!(9),
        "a plan task row must stay at record version 9: {on_disk}"
    );

    let reopened = TaskService::open(
        &store_dir,
        StoreLimits::default(),
        ExecutionAdmission::new(Arc::new(|| 1_000)),
    )
    .await
    .expect("the store reopens over the row: fixture");
    let loaded = reopened.get("alice", &id);
    assert!(
        loaded.is_ok(),
        "the version-9 plan row loads under MAX_LOADABLE_VERSION: {loaded:?}"
    );
    reopened
        .close()
        .await
        .expect("the reopened store closes: fixture");
}

#[path = "relay_replay_capture_tests.rs"]
mod capture;

#[path = "relay_replay_key_tests.rs"]
mod key;
