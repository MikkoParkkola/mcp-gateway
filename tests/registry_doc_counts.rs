// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-REG.DOC.1: the server counts the docs state are the registry's own.
//! README said 48 while the registry held 46, and 30 of those did not exist;
//! a count nobody recomputes reads as evidence while being a memory.

use mcp_gateway::registry::server_registry;

const README: &str = include_str!("../README.md");
const QUICKSTART: &str = include_str!("../docs/QUICKSTART.md");

/// The number written immediately before `claim` in `text`, once per line
/// that carries the claim.
fn stated_counts(text: &str, claim: &str) -> Vec<usize> {
    text.lines()
        .filter_map(|line| {
            let before = &line[..line.find(claim)?];
            let digits: String = before
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            digits.parse().ok()
        })
        .collect()
}

#[test]
fn documented_server_counts_match_the_registry() {
    let actual = server_registry::all().len();
    for (doc, text, claim) in [
        (
            "README.md",
            README,
            " popular MCP servers are pre-registered",
        ),
        (
            "docs/QUICKSTART.md",
            QUICKSTART,
            " servers in the built-in registry",
        ),
    ] {
        let stated = stated_counts(text, claim);
        assert!(
            !stated.is_empty(),
            "{doc} no longer states the count as \"N{claim}\"; update this test with the new wording"
        );
        assert!(
            stated.iter().all(|&n| n == actual),
            "{doc} states {stated:?}{claim}, the registry has {actual}"
        );
    }
}

#[test]
fn the_count_reader_reads_the_number_before_the_claim() {
    assert_eq!(
        stated_counts(
            "x 35 servers in the built-in registry",
            " servers in the built-in registry"
        ),
        [35]
    );
    assert_eq!(
        stated_counts(
            "(48 servers in the built-in registry)",
            " servers in the built-in registry"
        ),
        [48]
    );
    assert!(
        stated_counts(
            "servers in the built-in registry",
            " servers in the built-in registry"
        )
        .is_empty()
    );
}
