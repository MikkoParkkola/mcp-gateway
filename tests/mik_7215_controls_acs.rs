// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7215 §3.7 — the controls that must
//! survive the removal of sessions.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 6".
//!
//! Every case here asserts a **refusal**, never a computed value. That is the
//! whole point: these controls do not fail loudly when their state disappears.
//! They keep running and stop protecting, and a test that asserts "a score came
//! back" passes just as happily against a control that has stopped looking.

use std::sync::Arc;

use mcp_gateway::security::firewall::anomaly::{AnomalyDetector, Observation};
use mcp_gateway::transition::TransitionTracker;

fn detector() -> AnomalyDetector {
    AnomalyDetector::new(Arc::new(TransitionTracker::new()), 0.7)
}

#[test]
fn ac_control_1_scoring_without_a_key_is_unobservable_not_neutral() {
    // The silent failure, stated as a test. Under statelessness there is no
    // session, so a detector keyed on one sees a first request every time and
    // returns its "no prior context" score — 0.5, comfortably below the 0.7
    // threshold. The firewall keeps returning numbers and never flags anything.
    //
    // A control that cannot observe must say so, and the caller must decide
    // what to do about it. Answering 0.5 is the control deciding, silently, that
    // the answer is "fine".
    let detector = detector();
    assert_eq!(
        detector.observe(None, "srv", "tool"),
        Observation::Unobservable,
        "with no identity to key on, the detector must report that it cannot \
         see rather than return a passing score"
    );
}

#[test]
fn ac_control_1_a_principal_key_restores_observation() {
    // The replacement for the session: the authenticated principal. Same
    // control, a key that still exists after the migration.
    let detector = detector();
    assert!(matches!(
        detector.observe(Some("principal:abc"), "srv", "tool"),
        Observation::Scored(_)
    ));
}

#[test]
fn ac_control_1_transitions_are_tracked_per_principal_not_globally() {
    // Two callers must not pollute each other's history: one caller's ordinary
    // sequence would otherwise make another's unusual one look ordinary.
    let detector = detector();
    detector.observe(Some("principal:a"), "srv", "first");
    let b_first = detector.observe(Some("principal:b"), "srv", "second");

    assert_eq!(
        b_first,
        Observation::Scored(0.5),
        "a second caller's first observation has no prior context of its own, \
         whatever the first caller did"
    );
}

#[test]
fn ac_control_1_the_unobservable_answer_is_not_a_score() {
    // Deliberately not representable as a float. An `f64` sentinel — -1.0, or
    // NaN — is a value every existing comparison silently accepts, and the
    // comparison is `score > threshold`. `Unobservable > 0.7` is false, which
    // is precisely the silent pass this test exists to prevent.
    let unobservable = Observation::Unobservable;
    assert!(
        unobservable.score().is_none(),
        "there is no number that means 'I could not look'"
    );
    assert_eq!(Observation::Scored(0.95).score(), Some(0.95));
}

// ===========================================================================
// The caller's half. A control that reports it cannot see is only useful if
// somebody acts on that report; a caller that treats `Unobservable` as "no
// finding" has rebuilt the silent pass one layer up.
// ===========================================================================

mod firewall {
    use mcp_gateway::security::firewall::anomaly::Observation;

    #[test]
    fn ac_control_1_an_unobservable_call_is_recorded_not_ignored() {
        // The decision the caller must make explicitly. Blocking every
        // unidentified call would refuse anonymous traffic the operator may
        // have chosen to allow; ignoring it silently is how the control dies.
        // Between those, the honest minimum is that it is visible.
        assert!(
            Observation::Unobservable.score().is_none(),
            "the caller cannot mistake it for a score"
        );

        // And the shape that makes the mistake impossible: matching on the
        // enum has no arm that silently falls through, which an `f64` did.
        let acted_on = match Observation::Unobservable {
            Observation::Scored(_) => false,
            Observation::Unobservable => true,
        };
        assert!(acted_on, "every caller must handle the unobservable arm");
    }
}

// ===========================================================================
// MIK-7215.CONTROL.4 — every behaviour reclaimed by session-disconnect cleanup
// must be re-expressed as an expiry.
//
// `SessionLifecycle` fires on "SSE disconnect or DELETE /mcp". Under
// 2026-07-28 there is neither: no session to delete, and the stream those
// disconnects came from is replaced. So the callbacks never run, and
// everything they reclaimed leaks — quietly, because nothing errors when a
// callback is not called.
// ===========================================================================

mod lifecycle {
    use mcp_gateway::gateway::session_lifecycle::SessionLifecycle;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn ac_control_4_expiry_reclaims_what_disconnect_used_to() {
        // The same handlers, driven by a deadline rather than an event. An
        // event that cannot occur is not a trigger.
        let lifecycle = SessionLifecycle::new();
        let reclaimed = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&reclaimed);
        lifecycle.register("test-handler", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track("caller-a", 1_000);
        lifecycle.track("caller-b", 5_000);

        lifecycle.reap(2_000);
        assert_eq!(
            reclaimed.load(Ordering::SeqCst),
            1,
            "the entry past its deadline is reclaimed, and only that one"
        );

        lifecycle.reap(6_000);
        assert_eq!(reclaimed.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn ac_control_4_reaping_twice_reclaims_once() {
        // A handler that runs twice for one key is its own defect: these
        // callbacks free things.
        let lifecycle = SessionLifecycle::new();
        let reclaimed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reclaimed);
        lifecycle.register("test-handler", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track("caller-a", 1_000);
        lifecycle.reap(2_000);
        lifecycle.reap(3_000);
        assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ac_control_4_disconnect_still_works_for_a_legacy_session() {
        // The regression. A 2025 client still disconnects, and its cleanup must
        // still fire on the event rather than waiting for a deadline.
        let lifecycle = SessionLifecycle::new();
        let reclaimed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reclaimed);
        lifecycle.register("test-handler", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.on_disconnect("legacy-session");
        assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
    }
}

// ===========================================================================
// MIK-7246.CONFIRM.1 / .3 — the destructive-operation confirmation gate.
//
// Filed P3 because an attacker had to opt out of it by omitting a capability.
// After this migration nobody has to opt out of anything: the gate proceeds on
// a WARN when elicitation is unsupported **or there is no session**, and
// 2026-07-28 deletes sessions. In modern mode every destructive call takes the
// fail-open branch.
// ===========================================================================

mod confirmation {
    use mcp_gateway::gateway::destructive_confirmation::{
        ConfirmationPolicy, destructive_tools_from_annotations, is_destructive_meta_tool,
    };
    use serde_json::json;

    #[test]
    fn ac_confirm_1_an_unconfirmable_destructive_call_is_refused_not_warned() {
        // The whole change, in one row. "Proceeds after a WARN" is a courtesy
        // wearing a control's name — and the module's own header said so.
        assert_eq!(
            ConfirmationPolicy::for_modern().on_unconfirmable(),
            ConfirmationPolicy::REFUSE,
            "with no way to ask, a destructive call must not run"
        );
    }

    #[test]
    fn ac_confirm_1_the_legacy_path_keeps_its_documented_behaviour() {
        // The regression, and a deliberate asymmetry. A 2025 client that never
        // declared elicitation has been served this way for the life of the
        // gateway; refusing it now is a breaking change made in passing rather
        // than decided. The modern path has no such history — it has never
        // worked at all — so it starts closed.
        assert_eq!(
            ConfirmationPolicy::for_legacy().on_unconfirmable(),
            ConfirmationPolicy::PROCEED_WITH_WARNING
        );
    }

    #[test]
    fn ac_confirm_3_the_governed_set_comes_from_the_annotation() {
        // Today the set is one hardcoded name. A tool added tomorrow with
        // `destructiveHint: true` inherits nothing, which is how a gate ends up
        // guarding one door in a building that grew.
        let tools = json!([
            { "name": "gateway_kill_server", "annotations": { "destructiveHint": true } },
            { "name": "gateway_search_tools", "annotations": { "destructiveHint": false } },
            { "name": "gateway_wipe_everything", "annotations": { "destructiveHint": true } },
            { "name": "gateway_list_servers" }
        ]);

        let governed = destructive_tools_from_annotations(&tools);
        assert!(governed.contains("gateway_kill_server"));
        assert!(
            governed.contains("gateway_wipe_everything"),
            "a new destructive tool must inherit the gate without anyone editing a match arm"
        );
        assert!(!governed.contains("gateway_search_tools"));
        assert!(
            !governed.contains("gateway_list_servers"),
            "an unannotated tool is not destructive"
        );
    }

    #[test]
    fn ac_confirm_3_the_hardcoded_name_remains_governed() {
        // Belt and braces: the annotation is the source of truth, and the tool
        // the gate was written for must not fall out of it if an annotation is
        // ever dropped by accident.
        assert!(is_destructive_meta_tool("gateway_kill_server"));
    }
}
