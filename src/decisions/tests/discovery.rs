// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The discovery source: adopt items for unmanaged client finds, an item per
//! unreadable client config file, and the source's own health (R2, R3, R9,
//! R11).

use serde_json::{Value, json};

use super::super::{AdoptFind, UnreadableFile, UnreadableReason};
use super::*;
use crate::discovery::DiscoverySource;
use crate::discovery::shadow::ShadowRiskSeverity;

fn find(id: &str, name: &str) -> AdoptFind {
    AdoptFind {
        find_id: id.to_string(),
        name: name.to_string(),
        source: DiscoverySource::ClaudeDesktop,
        config_file: Some("claude_desktop_config.json".to_string()),
        transport: "http",
        command: None,
        url: Some("https://mcp.remote.internal".to_string()),
        severity: ShadowRiskSeverity::High,
    }
}

fn unreadable(digest: &str, reason: UnreadableReason) -> UnreadableFile {
    UnreadableFile {
        source: DiscoverySource::VsCode,
        file: "settings.json".to_string(),
        path_digest: digest.to_string(),
        reason,
    }
}

fn items(set: &DecisionSet) -> Vec<Value> {
    set.view().expect("all sources ready").decisions
}

fn of_kind<'a>(items: &'a [Value], kind: &str) -> Vec<&'a Value> {
    items.iter().filter(|item| item["kind"] == kind).collect()
}

fn keys(item: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = item
        .as_object()
        .expect("an item is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// R2: one adopt item per eligible find, with exactly the shown fields; the
/// list names no missing kind.
#[test]
fn an_eligible_find_is_one_adopt_item_with_exactly_its_shown_fields() {
    let mut set = ready();
    set.set_discovery(vec![find("f1", "remote-docs")], Vec::new(), 1, at(1));
    let items = items(&set);
    let adopt = of_kind(&items, "adopt");
    assert_eq!(adopt.len(), 1, "{items:?}");
    let item = adopt[0];
    assert_eq!(
        keys(item),
        [
            "id",
            "kind",
            "observed_at",
            "server",
            "severity",
            "waits_on"
        ]
    );
    assert_eq!(
        item["server"],
        json!({
            "name": "remote-docs",
            "source": "ClaudeDesktop",
            "config_file": "claude_desktop_config.json",
            "transport": "http",
            "command": null,
            "url": "https://mcp.remote.internal",
        })
    );
    assert_eq!(item["severity"], "high");
    assert_eq!(item["waits_on"], json!([]));
    let view = set.view().expect("ready");
    assert!(view.missing_kinds.is_empty(), "{:?}", view.missing_kinds);
    assert_eq!(view.partial_kinds, ["capability_changed"]);
}

/// R3: the count waits for the discovery source's first listing, and is
/// unavailable again when a scan timed out with nothing cached.
#[test]
fn the_count_waits_for_discovery_and_names_it_while_down() {
    let mut set = DecisionSet::with_key(KEY);
    for source in [Source::Access, Source::ControlPlane, Source::Capability] {
        set.set_health(source, Health::Ready);
    }
    assert_eq!(set.snapshot(), None, "no listing yet");
    assert!(
        set.unavailable().contains(&("discovery", "replaying")),
        "{:?}",
        set.unavailable()
    );
    set.set_discovery(Vec::new(), Vec::new(), 1, at(1));
    assert_eq!(set.snapshot().map(|s| s.0), Some(0));
    set.discovery_down();
    assert_eq!(set.snapshot(), None, "a scan timed out, nothing cached");
    assert!(
        set.unavailable().contains(&("discovery", "unreadable")),
        "{:?}",
        set.unavailable()
    );
}

/// R9: each unreadable client file is its own item, with its reason class
/// and file name only; two files with one name and source stay two; each
/// closes on its own.
#[test]
fn each_unreadable_file_is_its_own_item_and_closes_alone() {
    let mut set = ready();
    let files = vec![
        unreadable("d-vscode", UnreadableReason::DidNotParse),
        unreadable("d-cursor", UnreadableReason::NoPermission),
    ];
    set.set_discovery(Vec::new(), files, 1, at(1));
    let listed = items(&set);
    let shown = of_kind(&listed, "client_config_unreadable");
    assert_eq!(shown.len(), 2, "{listed:?}");
    assert_ne!(shown[0]["id"], shown[1]["id"]);
    for item in &shown {
        assert_eq!(
            keys(item),
            ["file", "id", "kind", "observed_at", "reason", "source"]
        );
        assert_eq!(item["file"], "settings.json");
    }
    let reasons: Vec<&Value> = shown.iter().map(|item| &item["reason"]).collect();
    assert!(reasons.contains(&&json!("did_not_parse")), "{reasons:?}");
    assert!(reasons.contains(&&json!("no_permission")), "{reasons:?}");
    assert_eq!(count(&set), 2, "the count includes them");

    let kept = vec![unreadable("d-cursor", UnreadableReason::NoPermission)];
    set.set_discovery(Vec::new(), kept, 2, at(2));
    let after = items(&set);
    assert_eq!(of_kind(&after, "client_config_unreadable").len(), 1);
}

/// R11: an unchanged listing keeps every item's `observed_at`, the order and
/// the revision; adopt items come before unreadable files, newest first and
/// by id on a tie.
#[test]
fn an_unchanged_listing_keeps_observed_at_order_and_revision() {
    let mut set = ready();
    set.set_discovery(vec![find("f1", "one")], Vec::new(), 1, at(1));
    let finds = vec![find("f1", "one"), find("f2", "two"), find("f3", "three")];
    let files = vec![
        unreadable("d1", UnreadableReason::DidNotParse),
        unreadable("d2", UnreadableReason::NotAReadableFile),
    ];
    set.set_discovery(finds.clone(), files.clone(), 2, at(2));
    let before = items(&set);
    let revision = set.view().expect("ready").revision;
    let kinds: Vec<&Value> = before.iter().map(|item| &item["kind"]).collect();
    assert_eq!(
        kinds,
        [
            "adopt",
            "adopt",
            "adopt",
            "client_config_unreadable",
            "client_config_unreadable"
        ],
        "{before:?}"
    );
    // f2 and f3 were first seen at minute 2, f1 at minute 1: newest first,
    // then by id on the tie.
    let first_seen: Vec<&Value> = before.iter().map(|item| &item["observed_at"]).collect();
    assert_eq!(first_seen[2], &json!(at(1).to_rfc3339()), "{before:?}");
    assert!(before[0]["id"].as_str() < before[1]["id"].as_str());

    set.set_discovery(finds, files, 3, at(3));
    set.expire(at(4));
    assert_eq!(items(&set), before, "an unchanged rescan and a tick");
    assert_eq!(set.view().expect("ready").revision, revision);
}

/// A reader that took a listing before a newer one landed (the tick, reading
/// gateway.yaml) cannot put the older one back; the same generation again
/// still applies, so eligibility is re-judged.
#[test]
fn an_older_listing_never_replaces_a_newer_one() {
    let mut set = ready();
    set.set_discovery(vec![find("f2", "newer")], Vec::new(), 2, at(2));
    set.set_discovery(vec![find("f1", "older")], Vec::new(), 1, at(3));
    let names = |set: &DecisionSet| -> Vec<Value> {
        of_kind(&items(set), "adopt")
            .iter()
            .map(|item| item["server"]["name"].clone())
            .collect()
    };
    assert_eq!(names(&set), [json!("newer")], "the older listing landed");
    set.set_discovery(Vec::new(), Vec::new(), 2, at(4));
    assert!(
        names(&set).is_empty(),
        "the same generation re-judged nothing"
    );
}
