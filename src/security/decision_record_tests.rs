// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the decision object's wire shape.

use super::{Decided, Decision, DecisionKind, Effect};

fn decision(kind: DecisionKind, rule_id: Option<&str>) -> Decision {
    Decision {
        v: 1,
        config_revision: Some("hmac-sha256:00aa".to_owned()),
        running_revision: None,
        pending_restart: Vec::new(),
        kind,
        rule_id: rule_id.map(str::to_owned),
        grant_id: None,
        findings: Some(Vec::new()),
        findings_truncated: false,
        effect: Some(Effect::Undeclared),
        decided: Decided::Fresh,
    }
}

#[test]
fn the_wire_names_are_the_agreed_ones() {
    let mut d = decision(DecisionKind::NotRedecided, None);
    d.decided = Decided::CacheHitNotRedecided;
    d.effect = Some(Effect::MayWrite);
    let v = serde_json::to_value(&d).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["kind"], "not_redecided");
    assert_eq!(v["decided"], "cache_hit_not_redecided");
    assert_eq!(v["effect"], "may_write");
    assert!(v.get("rule_id").is_none(), "absent, not null");
    assert!(v.get("audit_required").is_none() && v.get("rollback_applies").is_none());
}
