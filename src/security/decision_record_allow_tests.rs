// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rank merge of noted allows: the lowest rank names the call's decider
//! whatever order the checks ran in, two notes of one rank keep the earlier,
//! and a refusal still wins over any allow.

use super::{Allow, AllowRank, Decided, Decision, DecisionKind, Noted, Refused};
use crate::security::rule_id::{RuleId, RuleKey};

/// A distinct keyed id per `(kind, name)`, as a compiled rule carries.
fn id(kind: &str, name: &str) -> RuleId {
    RuleId::of(kind, &RuleKey::from_derived([7; 32]), name.as_bytes())
}

fn grant() -> Allow {
    Allow {
        rank: AllowRank::Grant,
        rule_id: Some(id("grant", "g-m")),
        grant_id: Some("g-m".to_owned()),
    }
}

/// One allow of every rank but the grant's and the softener's.
fn weaker() -> [Allow; 3] {
    [
        Allow::by(AllowRank::Mtls, Some(id("mtls", "agent-a"))),
        Allow::by(AllowRank::ToolPolicy, Some(id("tool_policy", "alpha:read"))),
        Allow::by(AllowRank::FirewallAllow, Some(id("firewall", "warn"))),
    ]
}

/// Every order of `items`.
fn orders(items: &[Allow]) -> Vec<Vec<Allow>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut all = Vec::new();
    for (i, first) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(i);
        for mut tail in orders(&rest) {
            tail.insert(0, first.clone());
            all.push(tail);
        }
    }
    all
}

/// The allowed call's decision after noting `allows` in order.
fn decided(allows: &[Allow]) -> Decision {
    let mut noted = Noted::default();
    for allow in allows {
        noted.allowed(allow.clone());
    }
    noted.decision(Decided::Fresh, Refused::No, None)
}

/// What a record names: kind, rule id and grant id.
fn named(d: &Decision) -> (DecisionKind, Option<String>, Option<String>) {
    (d.kind, d.rule_id.clone(), d.grant_id.clone())
}

fn expected(allow: &Allow) -> (DecisionKind, Option<String>, Option<String>) {
    (
        allow.rank.kind(),
        allow.rule_id.as_ref().map(|r| r.as_str().to_owned()),
        allow.grant_id.clone(),
    )
}

/// R17 (ATTR.1). Every order of a grant, an mTLS rule, an allow-list entry
/// and a warn-to-allow firewall rule names the grant, its id and its grant
/// id. Kills M1 (first note kept) and M3 (grant and firewall-allow ranks
/// swapped).
#[test]
fn rank_merge_permutations_name_the_grant() {
    let mut all = vec![grant()];
    all.extend(weaker());
    let orders = orders(&all);
    assert_eq!(orders.len(), 24, "premise: every order of four allows");
    for order in orders {
        let ranks: Vec<AllowRank> = order.iter().map(|a| a.rank).collect();
        assert_eq!(
            named(&decided(&order)),
            expected(&grant()),
            "order {ranks:?}"
        );
    }
}

/// R17 (ATTR.1). Two firewall-allow notes of one rank keep the earlier.
/// Kills M2 (a tie keeps the later note).
#[test]
fn rank_merge_ties_keep_the_earlier_note() {
    let first = Allow::by(AllowRank::FirewallAllow, Some(id("firewall", "first")));
    let second = Allow::by(AllowRank::FirewallAllow, Some(id("firewall", "second")));
    assert_eq!(named(&decided(&[first.clone(), second])), expected(&first));
}

/// R17 (ATTR.1, ATTR.2). A softened block noted after a grant wins over it:
/// the firewall kind, the softener's id and no grant id. The ladder's top
/// rung, which no HTTP row can pair with a root finding (grants apply only
/// to capability backends, which the root check refuses). Kills M1.
#[test]
fn a_softened_block_noted_late_beats_a_grant() {
    let softener = Allow::by(
        AllowRank::FirewallSoftenedBlock,
        Some(id("firewall", "softener")),
    );
    let got = decided(&[grant(), softener.clone()]);
    assert_eq!(named(&got), expected(&softener));
    assert_eq!(got.kind, DecisionKind::Firewall);
    assert!(got.grant_id.is_none(), "{got:?}");
}

/// R17 (ATTR.1). A call answered without deciding again ranks below every
/// check's allow: an mTLS allow noted after it wins. Kills M1.
#[test]
fn not_redecided_loses_to_any_check() {
    let mtls = weaker()[0].clone();
    let mut noted = Noted::not_redecided();
    noted.allowed(mtls.clone());
    let got = noted.decision(Decided::Fresh, Refused::No, None);
    assert_eq!(named(&got), expected(&mtls));
}

/// R17 (ATTR.1). A refusal noted after the strongest allow still wins: the
/// record names the refusing check and no grant id. A pin today.
#[test]
fn a_refusal_wins_over_any_allow() {
    let mut noted = Noted::default();
    noted.allowed(grant());
    noted.refused(DecisionKind::ToolPolicy, Some(id("tool_policy", "deny")));
    let got = noted.decision(
        Decided::Fresh,
        Refused::of(crate::security::audit::AuditOutcome::Denied(-32600)),
        None,
    );
    assert_eq!(
        named(&got),
        (
            DecisionKind::ToolPolicy,
            Some(id("tool_policy", "deny").as_str().to_owned()),
            None
        )
    );
}

/// R30 (ATTR.1). A cache hit is not decided again: whatever its admission
/// noted, a grant included, its record names `not_redecided` with no rule
/// or grant id. A pin today.
#[test]
fn a_cache_hit_names_no_check_and_no_grant() {
    let mut noted = Noted::default();
    noted.allowed(grant());
    let got = noted
        .as_not_redecided()
        .decision(Decided::CacheHitNotRedecided, Refused::No, None);
    assert_eq!(named(&got), (DecisionKind::NotRedecided, None, None));
}
