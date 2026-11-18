// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::Target;

#[test]
fn pairs_keep_the_recorded_order_and_names() {
    let target = |server: &str, tool: &str| Target {
        server: server.to_owned(),
        tool: tool.to_owned(),
    };
    let targets = [target("b", "two"), target("a", "one"), target("b", "two")];
    assert_eq!(
        Target::pairs(&targets),
        [("b", "two"), ("a", "one"), ("b", "two")]
    );
    assert!(Target::pairs(&[]).is_empty());
}
