// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each judge entry point opens with the `judging` gate, and the frame-level
//! check asks the same gate, so the verdict decides whether to judge in one
//! place. That only the judge reaches the read history is pinned by the
//! production-node scan in `meta_mcp::boundary_pins::read_history_access`.

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const JUDGE: &str = "gateway/outbound/judge.rs";

#[test]
fn every_judge_entry_opens_with_the_judging_gate() {
    let judge = std::fs::read_to_string(format!("{SRC}/{JUDGE}")).expect("read judge");
    for entry in ["delivered", "admit", "admit_stream_item"] {
        let start = judge
            .find(&format!("pub(crate) fn {entry}("))
            .unwrap_or_else(|| panic!("premise: {entry} is in the judge"));
        let body = &judge[start..];
        let open = body.find(") -> ").expect("a return type");
        let first = body[open..]
            .lines()
            .nth(1)
            .expect("a first statement")
            .trim();
        assert_eq!(
            first, "let Some((guard, mode)) = judging(firewall) else {",
            "{entry} opens with the judging gate"
        );
    }
    let outbound =
        std::fs::read_to_string(format!("{SRC}/gateway/outbound/mod.rs")).expect("read outbound");
    let start = outbound
        .find("pub(crate) fn judges(")
        .expect("premise: judges is in outbound");
    let end = outbound[start..].find("\n}\n").expect("judges ends") + start;
    assert!(
        outbound[start..end].contains("judge::judging("),
        "outbound::judges asks judge::judging"
    );
}
