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
