// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each compiled mTLS rule carries a keyed id: the same rule under the same
//! key always has the same id, another key or an edited rule another one, and
//! evaluation names the rule that matched, not the first or the last.

use super::MtlsPolicy;
use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
use crate::mtls::identity::{CertFields, CertIdentity};
use crate::security::rule_id::{RuleId, RuleKey};

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|n| (*n).to_string()).collect()
}

pub(crate) fn rule(cn: &str, allow_tools: &[&str], deny_tools: &[&str]) -> PolicyRuleConfig {
    PolicyRuleConfig {
        match_criteria: CertMatchConfig {
            cn: Some(cn.to_string()),
            ..CertMatchConfig::default()
        },
        allow: ToolScopeConfig {
            backends: names(&["*"]),
            tools: names(allow_tools),
        },
        deny: ToolScopeConfig {
            backends: Vec::new(),
            tools: names(deny_tools),
        },
    }
}

/// Rules A, B and C: only B matches `agent-1`, and B denies `write`. A is
/// before it and C after, so naming the first or last rule is told apart.
pub(crate) fn deny_write_rules() -> Vec<PolicyRuleConfig> {
    vec![
        rule("other-*", &["*"], &[]),
        rule("agent-1", &["*"], &["write"]),
        rule("spare-*", &["*"], &[]),
    ]
}

/// [`deny_write_rules`] with B allowing only `read`, so `write` is refused
/// by leaving it out of the allow list.
pub(crate) fn read_only_rules() -> Vec<PolicyRuleConfig> {
    let mut rules = deny_write_rules();
    rules[1] = rule("agent-1", &["read"], &[]);
    rules
}

/// The id the policy is expected to give `rule` under `key`.
pub(crate) fn mtls_id(key: &RuleKey, rule: &PolicyRuleConfig) -> RuleId {
    RuleId::of("mtls", key, &serde_json::to_vec(rule).expect("serialises"))
}

fn cert(cn: &str) -> CertIdentity {
    CertIdentity::for_test(CertFields {
        common_name: Some(cn.to_string()),
        display_name: cn.to_string(),
        ..CertFields::default()
    })
}

fn keyed(rules: Vec<PolicyRuleConfig>, key: &RuleKey) -> MtlsPolicy {
    let config = MtlsConfig {
        enabled: true,
        policies: rules,
        ..MtlsConfig::default()
    };
    MtlsPolicy::from_config_keyed(&config, key)
}

/// The id each of A, B and C is named by, read through evaluation with a
/// certificate only that rule matches.
fn ids(policy: &MtlsPolicy) -> Vec<Option<RuleId>> {
    ["other-x", "agent-1", "spare-x"]
        .iter()
        .map(|cn| {
            policy
                .evaluate_explained(Some(&cert(cn)), "alpha", "write")
                .1
                .cloned()
        })
        .collect()
}

fn expected(key: &RuleKey, rules: &[PolicyRuleConfig]) -> Vec<Option<RuleId>> {
    rules.iter().map(|r| Some(mtls_id(key, r))).collect()
}

#[test]
fn mtls_rule_ids_are_keyed_and_stable() {
    let (one, two) = (
        RuleKey::from_derived([1; 32]),
        RuleKey::from_derived([2; 32]),
    );
    let rules = deny_write_rules();
    let want = expected(&one, &rules);
    let other = expected(&two, &rules);
    assert_ne!(want, other, "premise: the two keys give different ids");
    for load in ["first load", "second load"] {
        let got = ids(&keyed(rules.clone(), &one));
        assert_eq!(got, want, "{load}: expected rule_ids {want:?}, got {got:?}");
    }
    let got = ids(&keyed(rules.clone(), &two));
    assert_eq!(
        got, other,
        "another key: expected rule_ids {other:?}, got {got:?}"
    );
    // Editing B's allow list changes B's id and no other.
    let edited = read_only_rules();
    let want_edited = expected(&one, &edited);
    assert!(
        want_edited[0] == want[0] && want_edited[2] == want[2] && want_edited[1] != want[1],
        "premise: only B's expected id moves"
    );
    let got = ids(&keyed(edited, &one));
    assert_eq!(
        got, want_edited,
        "edited B: expected rule_ids {want_edited:?}, got {got:?}"
    );
}

/// Computed once from `RuleId::of` on Spark and pasted: a change to the rule's serde
/// form (a field added without `skip_serializing_if`, a rename) breaks this,
/// because it rotates every configured rule's id.
const GOLDEN_FORM: &str = "{\"match\":{\"cn\":\"agent-1\",\"ou\":null,\"san_uri\":null,\"san_dns\":null,\"any\":null},\"allow\":{\"backends\":[\"*\"],\"tools\":[\"*\"]},\"deny\":{\"backends\":[],\"tools\":[\"write\"]}}";
const GOLDEN_ID: &str = "mtls:33b399957189fd71800e528a230b8f079f89d17bf169c65984f8be16c92e6e36";

#[test]
fn mtls_rule_id_hashes_the_configured_rule() {
    let key = RuleKey::from_derived([7; 32]);
    let deciding = deny_write_rules().remove(1);
    let form = String::from_utf8(serde_json::to_vec(&deciding).expect("serialises"));
    assert_eq!(form.as_deref(), Ok(GOLDEN_FORM), "the rule's serde form");
    let id = mtls_id(&key, &deciding);
    assert_eq!(id.as_str(), GOLDEN_ID, "the rule's id");
    let policy = keyed(vec![deciding], &key);
    let got = policy
        .evaluate_explained(Some(&cert("agent-1")), "alpha", "write")
        .1;
    assert_eq!(
        got.map(RuleId::as_str),
        Some(GOLDEN_ID),
        "expected rule_id {GOLDEN_ID}, got {got:?}"
    );
}
