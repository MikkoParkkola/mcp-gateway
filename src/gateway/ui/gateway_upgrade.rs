// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `upgrade` block of `GET /ui/api/gateway`: the version change this start
//! recorded and, when it crossed from 3.x into 4.0, the breaking-change items
//! `mcp-gateway upgrade` prints.
//!
//! The items and the version order are the CLI's own files, compiled into the
//! library a second time (as `clock.rs` is compiled into the binary), so the
//! page cannot drift from the notice and no second copy of either exists.

use serde_json::{Value, json};

use crate::counters::VersionChange;

#[path = "../../commands/upgrade_backend_grant_notice.rs"]
#[allow(dead_code, reason = "compiled for its `ITEM`; the CLI uses the rest")]
mod backend_grant_notice;
#[path = "../../commands/upgrade_notice_items.rs"]
#[allow(dead_code, reason = "compiled for its item list; the CLI prints it")]
mod notice_items;
#[path = "../../commands/upgrade_semver.rs"]
#[allow(dead_code, reason = "compiled for its ordering; the CLI uses the rest")]
mod stamp_version;
#[path = "../../commands/upgrade_webhook_notice.rs"]
#[allow(dead_code, reason = "compiled for its `ITEM`; the CLI uses the rest")]
mod webhook_notice;

use notice_items::NOTICE_4_0_0_ITEMS;
use stamp_version::SemVer;

/// Characters kept of an item's headline.
const HEADLINE_CAP: usize = 200;

/// The block: `null` when this start recorded no version change.
pub(super) fn upgrade_block(change: Option<&VersionChange>) -> Value {
    let Some(change) = change else {
        return Value::Null;
    };
    let items: Vec<String> = if crosses_4_0_0(&change.from, &change.to) {
        NOTICE_4_0_0_ITEMS
            .iter()
            .filter_map(|item| headline(item))
            .collect()
    } else {
        Vec::new()
    };
    json!({ "from": change.from, "to": change.to, "items": items })
}

/// Whether `from` is below 4.0.0 and `to` at or above it, by semver
/// precedence: the move the 4.0.0 notice is addressed to. A version that does
/// not parse crosses nothing.
fn crosses_4_0_0(from: &str, to: &str) -> bool {
    match (
        SemVer::parse(from),
        SemVer::parse(to),
        SemVer::parse("4.0.0"),
    ) {
        (Some(from), Some(to), Some(gate)) => from < gate && gate <= to,
        _ => false,
    }
}

/// An item's first sentence, as display text: the notice items are paragraphs,
/// and the page lists their headlines.
fn headline(item: &str) -> Option<String> {
    let end = item
        .match_indices('.')
        .find(|(at, _)| item[at + 1..].starts_with(char::is_whitespace))
        .map_or(item.len(), |(at, _)| at + 1);
    crate::cli_support::display_text(&item[..end], HEADLINE_CAP).map(|(text, _cut)| text)
}

#[cfg(test)]
#[path = "gateway_upgrade_tests.rs"]
mod tests;
