// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The 4.0.0 breaking-change notice, pinned.
//!
//! Its own file because the notice is shipped operator guidance rather than
//! behaviour, and because it is the one thing in this module that goes stale
//! when the PRODUCT changes rather than when this module does: item 1 said 3.x
//! tokens were not migrated, which was true until MIK-6744.STORE.1 shipped a
//! command that migrates them.

use super::NOTICE_4_0_0_ITEMS;

/// GH475.MIG.4 — the notice carries all thirty items, each named by the
/// action or removal it announces. Pinned so a later edit cannot quietly
/// drop one: an operator reads this once.
#[test]
fn notice_4_0_0_carries_all_thirty_items() {
    assert_eq!(NOTICE_4_0_0_ITEMS.len(), 30);
    let all = NOTICE_4_0_0_ITEMS.join(" ").to_ascii_lowercase();
    for expected in [
        "re-authenticate",
        "fails startup",
        "2024-10-07",
        "429",
        "mcp-protocol-version",
        "notify: true",
        "logging/setlevel",
        "tools/list_changed",
        "409",
        "http 401",
        "source: jwt",
        "gateway_attestation_mode",
        "input_schema_enforcement",
        "backends: [\"*\"]",
        "server.metrics_token",
        "server.ws_port",
        "server.replicas",
        "server.request_timeout",
        "server.max_body_size",
        "security.transparency_log",
        "fails to start",
        "ws_url",
        "circuit breaker is open",
        "audit_segment_expired",
        "minted by the gateway",
        "without the `requeststate`",
        "-32022",
        "proven principal",
        "expose_stats_tool",
        "refuses (403)",
    ] {
        assert!(
            all.contains(expected),
            "the 4.0.0 notice no longer mentions {expected}: {all}"
        );
    }
}

/// MIK-6744.STORE.1 — item 1 must tell the reader what the upgrade LEAVES
/// BEHIND and what can be done about it, not only what it stops reading.
///
/// REWRITTEN when the migration shipped. Before it, item 1 said 3.x tokens
/// "are not migrated" and that the stranded files "still hold usable
/// refresh tokens" — both true then and both false now, the second one
/// quietly so. It reads as incidental detail rather than as a promise,
/// which is exactly why an edit that fixed only the first sentence would
/// have swapped one false statement for another.
///
/// The three things pinned here are the three the reader has to act on:
/// where the files are, that a migration exists and how it is spelled, and
/// that keeping the old file is safe only until the migrated grant is
/// actually used.
#[test]
fn notice_4_0_0_discloses_the_3_x_files_the_migration_and_its_one_way_door() {
    let item_1 = NOTICE_4_0_0_ITEMS[0].to_ascii_lowercase();
    for expected in [
        // Where they are, and that nothing touched them.
        "~/.mcp-gateway/oauth/",
        "0600",
        "untouched",
        // That there is a way to keep a credential, spelled exactly as it
        // must be typed. A notice naming a command that does not exist is
        // worse than one naming none.
        "accounts migrate-credentials",
        "--config",
        "--descriptor-id",
        "--legacy-issuer",
        // And the one-way door: the old file stops being a fallback the
        // moment a migrated grant refreshes against a rotating provider.
        "rotates refresh tokens",
    ] {
        assert!(
            item_1.contains(expected),
            "notice item 1 no longer tells the reader about {expected}: {item_1}"
        );
    }
}

/// The command item 1 names must be one the binary actually accepts.
///
/// A notice is shipped guidance. Naming a subcommand that does not parse
/// would be a documented instruction that fails the moment anyone follows
/// it, and nothing else in this file would catch the drift.
#[test]
fn the_migration_command_named_in_the_notice_is_one_the_cli_accepts() {
    use clap::Parser as _;
    let parsed = mcp_gateway::cli::Cli::try_parse_from([
        "mcp-gateway",
        "accounts",
        "migrate-credentials",
        "--config",
        "/etc/mcp-gateway/gateway.yaml",
        "--descriptor-id",
        "workspace-personal",
        "--legacy-issuer",
        "https://auth.example.test",
    ]);
    assert!(
        parsed.is_ok(),
        "the notice names a command the CLI rejects: {:?}",
        parsed.err()
    );
}

/// Each notice item, in printed order, with the `docs/UPGRADING-4.0.md` item it
/// announces and a phrase that identifies it in the notice text.
const NOTICE_ITEM_SECTIONS: &[(u32, &str)] = &[
    (1, "re-authenticate"),
    (2, "env_files"),
    (3, "2024-10-07"),
    (4, "429"),
    (6, "mcp-protocol-version"),
    (11, "notify"),
    (23, "logging/setlevel"),
    (24, "tools/list_changed"),
    (25, "409"),
    (26, "subscriptions/listen"),
    (27, "exact: <id>"),
    (30, "gateway_attestation_mode"),
    (31, "input_schema_enforcement"),
    (32, "no `backends`"),
    (33, "server.metrics_token"),
    (34, "server.ws_port"),
    (37, "server.replicas"),
    (39, "server.request_timeout"),
    (43, "security.transparency_log"),
    (48, "fails to start"),
    (47, "ws_url"),
    (45, "circuit breaker is open"),
    (49, "audit_segment_expired"),
    (58, "minted by the gateway"),
    (55, "without the `requeststate`"),
    (59, "lists the backend"),
    (90, "-32022"),
    (91, "proven principal"),
    (92, "expose_stats_tool"),
    (93, "refuses (403)"),
];

/// The item numbers the guide says the first start prints: every section whose
/// startup marker, the first non-blank line after its heading, begins with
/// `**Startup:** prints a notice`.
///
/// Line endings are normalised first: a Windows checkout reads the guide with
/// CRLF.
fn guide_notice_items(doc: &str) -> std::collections::BTreeSet<u32> {
    let doc = doc.replace("\r\n", "\n");
    let mut items = std::collections::BTreeSet::new();
    for section in doc.split("\n## ").skip(1) {
        let Some((number, rest)) = section.split_once(". ") else {
            continue;
        };
        let Ok(n) = number.parse::<u32>() else {
            continue;
        };
        let marker = rest.lines().skip(1).find(|l| !l.trim().is_empty());
        if marker.is_some_and(|l| l.starts_with("**Startup:** prints a notice")) {
            items.insert(n);
        }
    }
    items
}

/// A CRLF checkout (Windows) reads the same markers as an LF one.
#[test]
fn guide_notice_items_reads_crlf() {
    let doc = "Intro.\r\n\r\n## 1. One\r\n\r\n**Startup:** prints a notice\r\n\r\nBody.\r\n\r\n\
               ## 2. Two\r\n\r\n**Startup:** no notice\r\n\r\n\
               ## 6. Six\r\n\r\n**Startup:** prints a notice; refuses to start\r\n";
    assert_eq!(
        guide_notice_items(doc),
        std::collections::BTreeSet::from([1, 6])
    );
}

/// The guide's list of notice items matches the notice. A notice item the list
/// omits is a startup message the upgrade guide does not tell an operator to
/// expect; a listed item the notice does not print is a promise it breaks.
#[test]
fn upgrading_guide_lists_exactly_the_items_the_notice_prints() {
    assert_eq!(
        NOTICE_ITEM_SECTIONS.len(),
        NOTICE_4_0_0_ITEMS.len(),
        "a notice item was added or removed: pair it with its UPGRADING-4.0 item here"
    );
    for (i, ((n, phrase), text)) in NOTICE_ITEM_SECTIONS
        .iter()
        .zip(NOTICE_4_0_0_ITEMS)
        .enumerate()
    {
        assert!(
            text.to_ascii_lowercase().contains(phrase),
            "notice item {} is paired with UPGRADING item {n} but lacks {phrase:?}: {text}",
            i + 1
        );
    }
    let printed: std::collections::BTreeSet<u32> =
        NOTICE_ITEM_SECTIONS.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        printed.len(),
        NOTICE_ITEM_SECTIONS.len(),
        "two notice items are paired with the same UPGRADING-4.0 item"
    );
    let listed = guide_notice_items(include_str!("../../docs/UPGRADING-4.0.md"));
    assert_eq!(
        listed, printed,
        "docs/UPGRADING-4.0.md marks items {listed:?} as printing a notice; the notice prints {printed:?}"
    );
}
