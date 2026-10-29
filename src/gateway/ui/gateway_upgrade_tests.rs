// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `upgrade` block: null, 4.0 items when crossing from 3.x, and none for a
//! change inside 4.x.

use super::{NOTICE_4_0_0_ITEMS, upgrade_block};
use crate::counters::VersionChange;

fn change(from: &str, to: &str) -> VersionChange {
    VersionChange {
        from: from.to_owned(),
        to: to.to_owned(),
    }
}

#[test]
fn no_recorded_change_is_null() {
    assert!(upgrade_block(None).is_null());
}

#[test]
fn crossing_from_3x_lists_one_headline_per_item() {
    let block = upgrade_block(Some(&change("3.5.1", "4.0.0")));
    assert_eq!(block["from"], "3.5.1");
    assert_eq!(block["to"], "4.0.0");
    let items = block["items"].as_array().expect("items");
    assert_eq!(items.len(), NOTICE_4_0_0_ITEMS.len());
    assert!(
        items
            .iter()
            .all(|i| i.as_str().is_some_and(|t| !t.is_empty()))
    );
}

#[test]
fn a_change_inside_4x_has_empty_items() {
    let block = upgrade_block(Some(&change("4.0.0", "4.0.1")));
    assert_eq!(block["items"], serde_json::json!([]));
    assert_eq!(block["to"], "4.0.1");
}

#[test]
fn an_unparsable_version_crosses_nothing() {
    let block = upgrade_block(Some(&change("garbage", "4.0.0")));
    assert_eq!(block["items"], serde_json::json!([]));
}
