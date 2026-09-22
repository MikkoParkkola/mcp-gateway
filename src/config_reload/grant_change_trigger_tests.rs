// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The grant-change trigger that drives identity-slot eviction.
//!
//! Split out of `tests.rs` rather than appended to it: that file is already
//! over the 800-line ceiling and the ratchet refuses further growth.

use super::changed_grant_subjects;
use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};

// -------------------------------------------------------------------------
// MIK-7334.CATALOGUE.1 — the "changes" conjunct of the grant trigger
// -------------------------------------------------------------------------

/// Build a grant whose body can be varied without touching its identity.
fn changed_subjects_grant(grant_id: &str, subject: &str, capability: &str) -> IdentityGrant {
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
        reason: "changed-grant-subjects cell".to_string(),
    }
}

fn subject_names(subjects: &[GrantSubject]) -> Vec<String> {
    subjects.iter().map(|s| s.subject.clone()).collect()
}

/// One transition of the grant store, and the subject set it owes the evictor.
struct Case {
    label: &'static str,
    before: Vec<IdentityGrant>,
    after: Vec<IdentityGrant>,
    owed: Vec<&'static str>,
}

/// Every transition the eviction trigger must enumerate, and the exact subject
/// set each one owes.
///
/// This cell exists because `MIK-7334.CATALOGUE.1` requires isolation "including
/// **changes** and revocation", and changes are the half that had no guard. The
/// revocation half is covered by the `None` arm and by the slot-eviction cells;
/// a ROTATION — the same `grant_id` carrying different content — reaches a
/// different arm, and until this cell that arm could be deleted with the whole
/// suite staying green.
///
/// Rotation is not a cosmetic variant of revocation on the shipped default
/// path. `identity_propagation::cache_binding(subject_key, audience)` takes no
/// grant input, and `subject_key` is `stable_actor_id()` — stable across a
/// rotation by design. So the pool key does not change when a grant rotates,
/// and eviction is the only thing that invalidates the predecessor's slot.
///
/// The table is exhaustive over the transitions the function can see, and each
/// row is chosen to kill a specific way of getting the arm wrong:
///
/// | row | kills |
/// |---|---|
/// | revoked | dropping the `None` arm |
/// | rotated body | dropping the `Some(new) if new != old` arm |
/// | rotated subject | pushing only the predecessor, or only the successor |
/// | added | dropping the trailing added-grant loop |
/// | unchanged | pushing unconditionally |
///
/// The **rotated subject** row is the load-bearing one. On a body-only rotation
/// `old.subject == new.subject`, and `push` de-duplicates, so "pushes both" and
/// "pushes one" are indistinguishable there — a cell built only on a body
/// rotation would pass a half-broken arm. Reassigning the subject separates
/// them, and the assertion pins **both** subjects because a slot exists under
/// the predecessor and the successor must not inherit it.
#[test]
fn changed_grant_subjects_enumerates_every_transition_the_evictor_owes() {
    let alice = changed_subjects_grant("g1", "alice", "cal");
    let alice_other_capability = changed_subjects_grant("g1", "alice", "mail");
    let bob_same_id = changed_subjects_grant("g1", "bob", "cal");
    let bob_new_id = changed_subjects_grant("g2", "bob", "cal");

    // PREMISE, asserted in this cell's own body: the rows that must differ do
    // differ. Without it, a fixture whose "rotation" is accidentally identical
    // would make the rotation rows vacuous and they would pass against an arm
    // that does nothing.
    assert_ne!(
        alice, alice_other_capability,
        "premise: a body rotation must be a change, or the rotation rows are vacuous"
    );
    assert_ne!(
        alice, bob_same_id,
        "premise: a subject reassignment must be a change"
    );

    let cases = vec![
        Case {
            label: "revoked: the grant is gone, so its subject's slot must go",
            before: vec![alice.clone()],
            after: vec![],
            owed: vec!["alice"],
        },
        Case {
            label: "rotated body: same grant_id, different capability",
            before: vec![alice.clone()],
            after: vec![alice_other_capability.clone()],
            owed: vec!["alice"],
        },
        Case {
            label: "rotated subject: same grant_id, reassigned — BOTH subjects owed",
            before: vec![alice.clone()],
            after: vec![bob_same_id.clone()],
            owed: vec!["alice", "bob"],
        },
        Case {
            label: "added: a grant that did not exist before",
            before: vec![],
            after: vec![bob_new_id.clone()],
            owed: vec!["bob"],
        },
        Case {
            label: "unchanged: nothing moved, so nothing may be evicted",
            before: vec![alice.clone()],
            after: vec![alice.clone()],
            owed: vec![],
        },
    ];

    for Case {
        label,
        before,
        after,
        owed,
    } in cases
    {
        let got = subject_names(&changed_grant_subjects(&before, &after));
        let mut got_sorted = got.clone();
        let mut want_sorted: Vec<String> = owed.iter().map(|s| (*s).to_string()).collect();
        got_sorted.sort();
        want_sorted.sort();
        assert_eq!(
            got_sorted, want_sorted,
            "{label}: expected exactly {want_sorted:?}, got {got:?}"
        );
    }
}
