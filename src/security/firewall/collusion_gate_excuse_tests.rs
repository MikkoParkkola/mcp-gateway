// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066.EXCUSE.1`: a caller whose own delivery was cut before it was
//! fingerprinted (the receipt keeps only the head and tail of a long
//! answer) is excused for the text it was delivered from that source, so a
//! legitimate holder is never refused for relaying what it received.

use serde_json::json;

use super::{CollusionAction, CollusionConfig, RelayCaller};
use crate::security::firewall::{Firewall, FirewallConfig, ScanType};

/// The paragraph carol and alice were both delivered from `alpha:read`.
const P: &str = "Minutes of the harbour committee: the dredging contract moves to the \
    spring tender, the ferry timetable keeps its Sunday gap, and the pilot boat needs a new \
    engine mount before the first autumn gale, at a cost the treasurer will table next month.";

/// Every k-gram kept, so each row checks the fingerprints its text holds.
fn firewall() -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Observe,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None).keeping_every_kgram()
}

/// Distinct filler prose of about `chars` characters.
fn filler(seed: u64, chars: usize) -> String {
    let mut out = String::new();
    let mut i = seed;
    while out.len() < chars {
        i = i
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push_str(&format!("row{:x} ", i >> 40));
    }
    out
}

fn deliver(fw: &Firewall, who: &str, tool: &str, text: &str) {
    let result = json!({"content": [{"type": "text", "text": text}]});
    fw.record_delivery(RelayCaller::Keyed(who), "alpha", tool, &result);
}

fn relays(fw: &Firewall, who: &str, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "beta",
        "send",
        &params,
        ("direct:beta", who),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}

/// Alice's answer from `alpha:read`: P in the middle of about 20 KiB, so
/// the receipt's head and tail leave P out.
fn long_answer() -> String {
    format!("{} {P} {}", filler(1, 10_000), filler(2, 10_000))
}

/// `MIK-8066.EXCUSE.1`: carol holds P whole; alice was delivered P inside a
/// long answer from the same source. Alice relaying P is not a relay; bob,
/// who got nothing, relaying it is.
#[test]
fn a_holder_whose_copy_was_cut_is_excused_for_it() {
    let fw = firewall();
    deliver(&fw, "carol", "read", P);
    deliver(&fw, "alice", "read", &long_answer());
    assert!(
        relays(&fw, "bob", P),
        "control: bob without a copy is a relay"
    );
    assert!(
        !relays(&fw, "alice", P),
        "alice was refused for text she was delivered"
    );
}

/// `MIK-8066.EXCUSE.1` (control): the excuse is per source. Alice's long
/// answer came from another source, so relaying carol's P is still a relay.
#[test]
fn a_cut_copy_from_another_source_excuses_nothing() {
    let fw = firewall();
    deliver(&fw, "carol", "read", P);
    deliver(&fw, "alice", "other", &long_answer());
    assert!(
        relays(&fw, "alice", P),
        "a cut copy from another source excused carol's text"
    );
}

/// `MIK-8066.EXCUSE.1`: a receipt cut by its fingerprint count, not its
/// text, still excuses its holder: alice's answer is short enough to keep
/// whole, but its fingerprints past the per-delivery cap are dropped, with
/// P at the end.
#[test]
fn a_holder_whose_fingerprints_were_truncated_is_excused() {
    let fw = firewall();
    deliver(&fw, "carol", "read", P);
    let answer = format!("{} {P}", filler(3, 5_500));
    deliver(&fw, "alice", "read", &answer);
    assert!(
        relays(&fw, "bob", P),
        "control: bob without a copy is a relay"
    );
    assert!(
        !relays(&fw, "alice", P),
        "alice was refused for text whose fingerprints were truncated"
    );
}

/// `MIK-8066.EXCUSE.1`: a sketch only ever excuses its holder; it is never
/// evidence. Only alice was delivered P, inside a cut answer: bob relaying
/// it is not a finding (nothing recorded it as held).
#[test]
fn a_sketch_is_never_evidence() {
    let fw = firewall();
    deliver(&fw, "alice", "read", &long_answer());
    assert!(!relays(&fw, "bob", P), "a sketch was used as evidence");
}
