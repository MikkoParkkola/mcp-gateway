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

/// GH475.MIG.4 — the notice carries all twenty-one items, each named by the
/// action or removal it announces. Pinned so a later edit cannot quietly
/// drop one: an operator reads this once.
#[test]
fn notice_4_0_0_carries_all_twenty_one_items() {
    assert_eq!(NOTICE_4_0_0_ITEMS.len(), 21);
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
