// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which firewall rule let a call through, for its allow record only (D9),
//! ranked apart from enforcement.

use super::{Finding, Firewall, FirewallAction, FirewallPolicy, decide_firewall_action, verdict};
use crate::security::response_policy::RuleTarget;

impl Firewall {
    /// The firewall rule that let a finding through, for the allow record
    /// only, kept apart from enforcement: a rule letting through a finding
    /// whose default blocks ranks first, any other letting-through rule
    /// last; the lowest rank wins, then the first. Content findings are
    /// ranked from the rule that decides them, root findings (`roots`) from
    /// the action and rule they arrive decided with.
    pub(super) fn allow_provenance(
        policy: &FirewallPolicy,
        target: RuleTarget<'_>,
        findings: &[Finding],
        roots: &[(
            Finding,
            FirewallAction,
            Option<crate::security::rule_id::RuleId>,
        )],
    ) -> Option<crate::security::decision_record::Allow> {
        use crate::security::decision_record::{Allow, AllowRank};
        // The rank of a rule acting `action` on a finding whose own default
        // is `default`: letting a blocking finding through ranks first;
        // allowing any other finding, or warning on a blocking one, last.
        let rank = |action: FirewallAction, default: FirewallAction| match (action, default) {
            (FirewallAction::Allow, FirewallAction::Block) => {
                Some(AllowRank::FirewallSoftenedBlock)
            }
            (FirewallAction::Allow, _) | (FirewallAction::Warn, FirewallAction::Block) => {
                Some(AllowRank::FirewallAllow)
            }
            _ => None,
        };
        let content = verdict::candidate_keys(&policy.rules, target)
            .into_iter()
            .flat_map(|key| {
                findings.iter().filter_map(move |finding| {
                    let rule = verdict::first_matching_rule(
                        &policy.rules,
                        target,
                        key,
                        finding.scan_type,
                    )?;
                    let default = decide_firewall_action(None, Some(finding.severity));
                    rank(rule.action, default).map(|r| Allow::by(r, rule.id.clone()))
                })
            });
        // A root finding defaults to blocking: an allow softens it, a warn
        // lets it through at the last rank. A path inside a root raises none.
        let rooted = roots.iter().filter_map(|(_, action, id)| {
            let id = id.as_ref()?;
            rank(*action, FirewallAction::Block).map(|r| Allow::by(r, Some(id.clone())))
        });
        content
            .chain(rooted)
            .fold(None, |kept: Option<Allow>, next| match kept {
                Some(held) if held.rank <= next.rank => Some(held),
                _ => Some(next),
            })
    }
}
