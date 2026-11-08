// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498 VISIBLE characterisation: what every memo accessor answers today,
//! inside a request scope and outside one. Written before the accessors share
//! one keyed map, and unchanged by it. `Carried` is pinned by its users'
//! rows (`stored_proof_tests`, `caller_verdict_outcome_tests`), which need a live
//! resolution to build one.

use super::{
    AccountOutcome, DescriptorId, Visibility, Withholding, account_binding, account_outcome,
    account_transient, denial_code, has_resolution_error, note_denial_code, record_absent,
    record_account_binding, record_account_outcome, record_account_refusal,
    record_account_transient, record_resolution_error, record_visibility, recorded_visibility,
    take_account_refusal, take_account_transient, take_any_account_transient,
    take_resolution_error, with_visibility_memo,
};

const SCHEMA: Visibility = Visibility::Withheld(Withholding::Schema);
const ABSENT: Visibility = Visibility::Withheld(Withholding::Absent);

fn account(name: &str) -> DescriptorId {
    DescriptorId(name.to_owned())
}

fn error(code: i32, text: &str) -> crate::Error {
    crate::Error::JsonRpc {
        code,
        message: text.to_owned(),
        data: Some(serde_json::json!({ "case": text })),
    }
}

/// The whole error, variant and fields, not only its message.
fn shape(error: Option<crate::Error>) -> Option<String> {
    error.map(|error| format!("{error:?}"))
}

#[tokio::test]
async fn first_wins_maps_keep_the_first_answer_and_reads_do_not_consume() {
    with_visibility_memo(async {
        assert_eq!(record_visibility("s", "t", SCHEMA), SCHEMA);
        assert_eq!(record_visibility("s", "t", Visibility::Visible), SCHEMA);
        // The other order too: first wins, not "withheld wins".
        assert_eq!(
            record_visibility("s", "v", Visibility::Visible),
            Visibility::Visible
        );
        assert_eq!(record_visibility("s", "v", SCHEMA), Visibility::Visible);
        assert_eq!(recorded_visibility("s", "v"), Some(Visibility::Visible));
        assert_eq!(recorded_visibility("s", "t"), Some(SCHEMA));
        assert_eq!(
            recorded_visibility("s", "t"),
            Some(SCHEMA),
            "a read keeps it"
        );
        note_denial_code("s", "t", -32003, None);
        note_denial_code("s", "t", -32601, None);
        assert_eq!(denial_code("s", "t"), Some(-32003));
        assert_eq!(denial_code("s", "t"), Some(-32003), "a read keeps it");
        record_account_outcome("s", &account("a"), AccountOutcome::NoView);
        record_account_outcome("s", &account("a"), AccountOutcome::Live);
        for _ in 0..2 {
            assert_eq!(
                account_outcome("s", &account("a")),
                Some(AccountOutcome::NoView)
            );
        }
    })
    .await;
}

#[tokio::test]
async fn overwrite_maps_keep_the_last_answer_and_takes_consume_once() {
    with_visibility_memo(async {
        record_account_binding("s", &account("a"), "one");
        record_account_binding("s", &account("a"), "two");
        for _ in 0..2 {
            assert_eq!(account_binding("s", &account("a")).as_deref(), Some("two"));
        }
        record_account_refusal("s", &account("a"), error(-32001, "first"));
        record_account_refusal("s", &account("a"), error(-32002, "second"));
        assert_eq!(
            shape(take_account_refusal("s", &account("a"))),
            shape(Some(error(-32002, "second")))
        );
        assert!(take_account_refusal("s", &account("a")).is_none());
        record_account_transient("s", "t", "one".to_owned());
        record_account_transient("s", "t", "two".to_owned());
        for _ in 0..2 {
            assert_eq!(account_transient("s", "t").as_deref(), Some("two"));
        }
        assert_eq!(take_account_transient("s", "t").as_deref(), Some("two"));
        assert!(take_account_transient("s", "t").is_none());
        record_resolution_error("s", "t", error(-32001, "first"));
        record_resolution_error("s", "t", error(-32002, "second"));
        assert!(has_resolution_error("s", "t"));
        assert!(has_resolution_error("s", "t"), "a check keeps it");
        assert_eq!(
            shape(take_resolution_error("s", "t")),
            shape(Some(error(-32002, "second")))
        );
        assert!(!has_resolution_error("s", "t"));
        assert!(take_resolution_error("s", "t").is_none());
    })
    .await;
}

#[tokio::test]
async fn take_any_transient_takes_each_held_one_once() {
    with_visibility_memo(async {
        record_account_transient("s", "t1", "one".to_owned());
        record_account_transient("s", "t2", "two".to_owned());
        // HashMap order is arbitrary today: which one comes first is not pinned.
        let mut taken = [take_any_account_transient(), take_any_account_transient()];
        taken.sort();
        assert_eq!(taken, [Some("one".to_owned()), Some("two".to_owned())]);
        assert!(take_any_account_transient().is_none());
    })
    .await;
}

/// MIK-8387: an absence only ever upgrades. Empty and `Visible` become
/// `Absent`; another withholding keeps its reason; a later `Visible`
/// judgement does not undo it.
#[tokio::test]
async fn an_absence_only_upgrades() {
    with_visibility_memo(async {
        record_absent("s", "empty");
        assert_eq!(recorded_visibility("s", "empty"), Some(ABSENT));
        record_visibility("s", "visible", Visibility::Visible);
        record_absent("s", "visible");
        assert_eq!(recorded_visibility("s", "visible"), Some(ABSENT));
        record_visibility("s", "schema", SCHEMA);
        record_absent("s", "schema");
        assert_eq!(recorded_visibility("s", "schema"), Some(SCHEMA));
        assert_eq!(record_visibility("s", "empty", Visibility::Visible), ABSENT);
        assert_eq!(recorded_visibility("s", "empty"), Some(ABSENT));
    })
    .await;
}

/// Every map is keyed by its whole key: an entry under (s1, t1) or
/// (s1, a1) is invisible under a key that differs in one part, and is still
/// there afterwards.
#[tokio::test]
async fn keys_are_isolated_by_server_tool_and_account() {
    with_visibility_memo(async {
        let (a1, a2) = (account("a1"), account("a2"));
        record_visibility("s1", "t1", SCHEMA);
        note_denial_code("s1", "t1", -32003, None);
        record_account_transient("s1", "t1", "busy".to_owned());
        record_resolution_error("s1", "t1", error(-32001, "down"));
        record_account_outcome("s1", &a1, AccountOutcome::NoView);
        record_account_binding("s1", &a1, "bound");
        record_account_refusal("s1", &a1, error(-32002, "refused"));
        for (server, tool) in [("s1", "t2"), ("s2", "t1")] {
            assert_eq!(recorded_visibility(server, tool), None);
            assert_eq!(denial_code(server, tool), None);
            assert_eq!(account_transient(server, tool), None);
            assert_eq!(take_account_transient(server, tool), None);
            assert!(!has_resolution_error(server, tool));
            assert!(take_resolution_error(server, tool).is_none());
        }
        for (server, key) in [("s1", &a2), ("s2", &a1)] {
            assert_eq!(account_outcome(server, key), None);
            assert_eq!(account_binding(server, key), None);
            assert!(take_account_refusal(server, key).is_none());
        }
        assert_eq!(recorded_visibility("s1", "t1"), Some(SCHEMA));
        assert_eq!(denial_code("s1", "t1"), Some(-32003));
        assert_eq!(account_transient("s1", "t1").as_deref(), Some("busy"));
        assert!(has_resolution_error("s1", "t1"));
        assert_eq!(account_outcome("s1", &a1), Some(AccountOutcome::NoView));
        assert_eq!(account_binding("s1", &a1).as_deref(), Some("bound"));
        assert_eq!(
            shape(take_account_refusal("s1", &a1)),
            shape(Some(error(-32002, "refused")))
        );
    })
    .await;
}

/// Outside a request scope nothing is kept: every record is a no-op, every
/// read answers its empty value, and a scope opened afterwards sees none of it.
#[tokio::test]
async fn outside_a_memo_every_accessor_is_inert() {
    assert_eq!(
        record_visibility("s", "t", SCHEMA),
        SCHEMA,
        "returns its argument"
    );
    assert_eq!(recorded_visibility("s", "t"), None);
    record_absent("s", "t");
    assert_eq!(recorded_visibility("s", "t"), None);
    note_denial_code("s", "t", -32003, None);
    assert_eq!(denial_code("s", "t"), None);
    record_account_outcome("s", &account("a"), AccountOutcome::Live);
    assert_eq!(account_outcome("s", &account("a")), None);
    record_account_binding("s", &account("a"), "bound");
    assert_eq!(account_binding("s", &account("a")), None);
    record_account_refusal("s", &account("a"), error(-32002, "refused"));
    assert!(take_account_refusal("s", &account("a")).is_none());
    record_account_transient("s", "t", "busy".to_owned());
    assert_eq!(account_transient("s", "t"), None);
    assert_eq!(take_account_transient("s", "t"), None);
    assert_eq!(take_any_account_transient(), None);
    record_resolution_error("s", "t", error(-32001, "down"));
    assert!(!has_resolution_error("s", "t"));
    assert!(take_resolution_error("s", "t").is_none());
    assert_eq!(
        super::judged_playbook(),
        None,
        "no request and no worker judgement"
    );
    with_visibility_memo(async {
        assert_eq!(recorded_visibility("s", "t"), None);
        assert_eq!(denial_code("s", "t"), None);
        assert_eq!(account_outcome("s", &account("a")), None);
        assert_eq!(account_binding("s", &account("a")), None);
        assert!(take_account_refusal("s", &account("a")).is_none());
        assert_eq!(account_transient("s", "t"), None);
        assert!(!has_resolution_error("s", "t"));
    })
    .await;
}

/// A task worker runs its dispatch inside `with_judged`, and that dispatch
/// opens its own, empty, request memo: the worker's judgement answers.
/// Once the request records its own, the request's wins.
#[tokio::test]
async fn judged_falls_back_to_the_worker_and_the_request_wins() {
    let worker = with_visibility_memo(async {
        super::record_judged_playbook("worker".to_owned());
        super::judged()
    })
    .await;
    super::with_judged(worker.clone(), async {
        assert_eq!(super::judged_playbook().as_deref(), Some("worker"));
    })
    .await;
    super::with_judged(
        worker,
        with_visibility_memo(async {
            assert_eq!(super::judged_playbook().as_deref(), Some("worker"));
            super::record_judged_playbook("request".to_owned());
            assert_eq!(super::judged_playbook().as_deref(), Some("request"));
        }),
    )
    .await;
}

/// MIK-8498 VISIBLE.1a: which judgement `changed_instance` reads. The
/// request's own wins wherever it names the backend; a request that judged
/// nothing for the name defers to the task worker's; neither means unchanged.
#[tokio::test]
async fn changed_instance_prefers_the_request_and_falls_back_to_the_worker() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    let instance = || {
        std::sync::Arc::new(Backend::new(
            "b",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(300),
        ))
    };
    let (a, b) = (instance(), instance());
    assert_eq!(super::changed_instance(&a), None, "no judgement: unchanged");
    let worker_on_b = with_visibility_memo(async {
        super::record_exempt_instances(&[std::sync::Arc::clone(&b)]);
        super::judged()
    })
    .await;
    super::with_judged(
        worker_on_b,
        with_visibility_memo(async {
            assert!(super::changed_instance(&a).is_some(), "the worker judged b");
            assert_eq!(super::changed_instance(&b), None);
            super::record_exempt_instances(&[std::sync::Arc::clone(&a)]);
            assert_eq!(
                super::changed_instance(&a),
                None,
                "the request judged a: its own judgement wins over the worker's b"
            );
            assert!(super::changed_instance(&b).is_some());
        }),
    )
    .await;
}

/// MIK-8498 VISIBLE.1: `recorded_in_scope` tells "no memo" apart from "a
/// memo with nothing recorded", the distinction `tool_visible_to`'s three
/// branches read.
#[tokio::test]
async fn recorded_in_scope_tells_no_memo_from_an_empty_one() {
    use super::{Scoped, recorded_in_scope};
    assert!(matches!(recorded_in_scope("s", "t"), Scoped::NoMemo));
    with_visibility_memo(async {
        assert!(matches!(recorded_in_scope("s", "t"), Scoped::InMemo(None)));
        record_visibility("s", "t", SCHEMA);
        assert!(matches!(
            recorded_in_scope("s", "t"),
            Scoped::InMemo(Some(SCHEMA))
        ));
        assert!(matches!(recorded_in_scope("s", "u"), Scoped::InMemo(None)));
    })
    .await;
}

/// An empty inner `with_judged` keeps the enclosing judgement instead of
/// clearing it: the outer backend instance and playbook digest still answer.
/// The inner wrapper is built before the outer scope exists and awaited
/// inside it, so the enclosing judgement is read when it runs.
#[tokio::test]
async fn an_empty_inner_judgement_keeps_the_outer_backend_guard() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    let instance = || {
        std::sync::Arc::new(Backend::new(
            "b",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(300),
        ))
    };
    let (a, b) = (instance(), instance());
    let outer = with_visibility_memo(async {
        super::record_judged_playbook("outer".to_owned());
        super::record_exempt_instances(&[std::sync::Arc::clone(&b)]);
        super::judged()
    })
    .await;
    let probe = std::sync::Arc::clone(&a);
    let inner = super::with_judged(super::Judged::default(), async move {
        (super::changed_instance(&probe), super::judged_playbook())
    });
    let (changed, playbook) = super::with_judged(outer, inner).await;
    assert!(
        changed.is_some(),
        "the inner empty judgement cleared the outer backend guard"
    );
    assert_eq!(
        playbook.as_deref(),
        Some("outer"),
        "the inner empty judgement cleared the outer playbook digest"
    );
}

/// The boundary of that inheritance: an inner judgement that names anything
/// replaces the enclosing one whole, with no field taken from the outer. A
/// playbook-only inner judgement leaves no backend instance to compare.
#[tokio::test]
async fn a_partial_inner_judgement_replaces_the_outer_one_whole() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    let instance = || {
        std::sync::Arc::new(Backend::new(
            "b",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(300),
        ))
    };
    let (a, b) = (instance(), instance());
    let outer = with_visibility_memo(async {
        super::record_judged_playbook("outer".to_owned());
        super::record_exempt_instances(&[std::sync::Arc::clone(&b)]);
        super::judged()
    })
    .await;
    let inner = with_visibility_memo(async {
        super::record_judged_playbook("inner".to_owned());
        super::judged()
    })
    .await;
    let (changed, playbook) = super::with_judged(
        outer,
        super::with_judged(inner, async {
            (super::changed_instance(&a), super::judged_playbook())
        }),
    )
    .await;
    assert_eq!(
        playbook.as_deref(),
        Some("inner"),
        "the inner digest answers"
    );
    assert_eq!(
        changed, None,
        "an outer instance survived a partial inner judgement"
    );
}
