// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the gateway did to an answer, as an Activity row says it (API2.10): the call's delivery record joined to the call by trace, and the
//! closed set of values a row may show for it.

use serde_json::{Map, Value};

/// Said on every call row, and at response scope on the list page and the
/// signed export manifest: the list and export check each record's own
/// signature, not the chain between records.
pub(super) const SCOPE_LABEL: &str = "record signature checked, chain not walked";
/// The receipt's label when its scan walked the whole delivery window.
pub(super) const CHAIN_CHECKED: &str = "chain checked across the delivery window";
/// The receipt's label when a line cap or a missing segment stopped it first.
pub(super) const CHAIN_UNFINISHED: &str = "scan limit reached before the window ended";

/// The bytes of a call's log after its line that every reader searches.
pub(super) const DELIVERY_WINDOW: u64 = 256 << 10;
/// What a page reads above its cursor to find deliveries already scanned.
pub(super) const LOOK_ABOVE: u64 = DELIVERY_WINDOW;
/// What a receipt reads forward from its call.
pub(super) const RECEIPT_SCAN: u64 = DELIVERY_WINDOW;
/// Deliveries held per read.
pub(super) const MAX_PENDING: usize = 256;
/// Tombstones held per read.
pub(super) const MAX_EVICTED: usize = 4_096;

pub(super) const NOT_SCANNED: &str = "answer not scanned";
pub(super) const NOT_RECORDED: &str = "findings not recorded for this answer";
pub(super) const INCOMPLETE: &str = "not stated: the join was incomplete";
pub(super) const NO_RECORD: &str = "no delivery record found";

/// The effect a row states; also the `effect=` filter's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Effect {
    Delivered,
    Annotated,
    Rewritten,
    Refused,
    Unknown,
    NoRecord,
}

/// The `effect=` values the list supports.
pub(super) const SUPPORTED_EFFECTS: [&str; 6] = [
    "delivered",
    "annotated",
    "rewritten",
    "refused",
    "unknown",
    "no_record",
];

impl Effect {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Annotated => "annotated",
            Self::Rewritten => "rewritten",
            Self::Refused => "refused",
            Self::Unknown => "unknown",
            Self::NoRecord => "no_record",
        }
    }

    pub(super) fn parse(text: &str) -> Option<Self> {
        [
            Self::Delivered,
            Self::Annotated,
            Self::Rewritten,
            Self::Refused,
            Self::Unknown,
            Self::NoRecord,
        ]
        .into_iter()
        .find(|e| e.as_str() == text)
    }

    /// Whether `outcome=cleaned` lists a call with this effect.
    pub(super) fn is_cleaned(self) -> bool {
        matches!(self, Self::Annotated | Self::Rewritten)
    }
}

/// What a delivery record says about the answer's findings.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Findings {
    /// Scanned: the entries (at most 32) and the total when there were more.
    Scanned {
        list: Vec<Value>,
        total: Option<u64>,
    },
    /// Vouched but not scanned (`null`).
    NotScanned,
    /// The record carries no findings field.
    NotRecorded,
}

/// One delivery record's projection, bounded: the effect, at most 32 findings.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Delivery {
    pub(super) effect: Effect,
    pub(super) findings: Findings,
    /// Set when no secret is configured and the record cannot be vouched for.
    pub(super) unverifiable: bool,
}

/// Why a call's join is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Why {
    Evicted,
    Overflow,
    /// A record with this trace failed its hash or HMAC.
    Invalid,
    /// Unsigned under a configured secret.
    Unsigned,
    /// More than one `transport_finalized` record for the trace.
    Duplicate,
    /// The receipt's window broke the chain after a record was found: the
    /// record cannot be vouched for.
    Chain,
}

impl Why {
    /// The `answer_integrity` value, for the reasons that are integrity ones.
    pub(super) fn integrity(self) -> Option<&'static str> {
        match self {
            Self::Invalid => Some("invalid"),
            Self::Unsigned => Some("unsigned"),
            Self::Duplicate => Some("duplicate"),
            Self::Evicted | Self::Overflow | Self::Chain => None,
        }
    }
}

/// Why a call reads `no_record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Searched {
    /// Not a call: nothing is joined.
    NotACall,
    /// A stream frame: the delivery is written after the call.
    AppendTime,
    /// The call has no trace.
    NoTrace,
    /// A search that did not finish its window.
    Unfinished,
    /// A finished search that found nothing.
    Finished,
}

/// A call's join.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Joined {
    Found(Delivery),
    NoRecord(Searched),
    Incomplete(Why),
}

impl Joined {
    pub(super) fn effect(&self) -> Effect {
        match self {
            Self::Found(d) => d.effect,
            Self::NoRecord(_) => Effect::NoRecord,
            Self::Incomplete(_) => Effect::Unknown,
        }
    }

    /// Writes `effect`, `answer_findings`, `answer_findings_total`,
    /// `answer_integrity` and the scope label onto a call row.
    pub(super) fn write_into(&self, row: &mut Map<String, Value>) {
        row.insert("effect".into(), self.effect().as_str().into());
        row.insert("answer_integrity_scope".into(), SCOPE_LABEL.into());
        let findings: Value = match self {
            Self::Found(d) => match &d.findings {
                Findings::Scanned { list, total } => {
                    if let Some(t) = total {
                        row.insert("answer_findings_total".into(), (*t).into());
                    }
                    Value::Array(list.clone())
                }
                Findings::NotScanned => NOT_SCANNED.into(),
                Findings::NotRecorded => NOT_RECORDED.into(),
            },
            Self::NoRecord(_) => NO_RECORD.into(),
            Self::Incomplete(_) => INCOMPLETE.into(),
        };
        row.insert("answer_findings".into(), findings);
        match self {
            Self::Found(d) if d.unverifiable => {
                row.insert("answer_integrity".into(), "unverifiable".into());
            }
            Self::Incomplete(why) => {
                if let Some(i) = why.integrity() {
                    row.insert("answer_integrity".into(), i.into());
                }
            }
            _ => {}
        }
    }
}
