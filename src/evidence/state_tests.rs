//! Tests for [`EvidenceState`] accessors and the [`EvidenceClass`] taxonomy.

use super::*;

#[test]
fn source_accessor_returns_id_for_every_variant() {
    let s = SourceId::new("src");
    let variants = [
        EvidenceState::CheckedHit {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::CheckedNoHit {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::Failed {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::Timeout {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::NotConfigured {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::NotAuthorized {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::Stale {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::SkippedNotApplicable {
            source: s.clone(),
            detail: None,
        },
    ];
    for v in &variants {
        assert_eq!(v.source(), &s);
    }
}

#[test]
fn detail_accessor_round_trips() {
    let with = EvidenceState::CheckedHit {
        source: SourceId::new("s"),
        detail: Some("matched row 7".to_string()),
    };
    assert_eq!(with.detail(), Some("matched row 7"));

    let without = EvidenceState::CheckedHit {
        source: SourceId::new("s"),
        detail: None,
    };
    assert_eq!(without.detail(), None);
}

#[test]
fn class_taxonomy_is_correct() {
    let s = SourceId::new("s");
    assert_eq!(
        EvidenceState::CheckedHit {
            source: s.clone(),
            detail: None
        }
        .class(),
        EvidenceClass::ConclusivePositive
    );
    assert_eq!(
        EvidenceState::CheckedNoHit {
            source: s.clone(),
            detail: None
        }
        .class(),
        EvidenceClass::ConclusiveNegative
    );
    for cnc in [
        EvidenceState::Failed {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::Timeout {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::NotConfigured {
            source: s.clone(),
            detail: None,
        },
        EvidenceState::NotAuthorized {
            source: s.clone(),
            detail: None,
        },
    ] {
        assert_eq!(cnc.class(), EvidenceClass::CouldNotCheck);
    }
    assert_eq!(
        EvidenceState::Stale {
            source: s.clone(),
            detail: None
        }
        .class(),
        EvidenceClass::Stale
    );
    assert_eq!(
        EvidenceState::SkippedNotApplicable {
            source: s,
            detail: None
        }
        .class(),
        EvidenceClass::NotApplicable
    );
}

#[test]
fn source_id_display_and_as_str_agree() {
    let id = SourceId::new("registry-v2");
    assert_eq!(id.as_str(), "registry-v2");
    assert_eq!(id.to_string(), "registry-v2");
}
