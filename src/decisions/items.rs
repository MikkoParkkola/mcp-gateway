// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The items the set shows, rebuilt from its state after every change.
//!
//! A changed capability comes before every access request that waits on it;
//! within a kind, the newest first, then by id.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{AccessKey, DecisionSet, display};
use crate::identity_grants::GrantScope;

/// An opaque id: a keyed digest of the kind and its identifying tuple, in
/// the canonical JSON array form the discovery entry digest uses.
fn id(key: &[u8; 32], kind: &str, tuple: &Value) -> String {
    let digest = crate::hashing::canonical_json_sha256(&json!([kind, tuple]));
    crate::hashing::hmac_sha256_hex(key, digest.as_bytes())
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339()
}

/// Newest first, then by id: the order within one kind.
fn sort(items: &mut [(DateTime<Utc>, Value)]) {
    items.sort_by(|(a_at, a), (b_at, b)| {
        b_at.cmp(a_at)
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
}

/// An item and the time it sorts by.
type Dated = (DateTime<Utc>, Value);

/// Which changed-capability ids each trusted name blocks.
type Blocks = BTreeMap<String, Vec<String>>;

pub(super) fn build(set: &mut DecisionSet) -> Vec<Value> {
    let mut live = Vec::new();
    let (mut changed, blocks) = changed_capabilities(set, &mut live);
    let mut requests = access_requests(set, &blocks);
    let mut adopt = adopt_items(set, &mut live);
    let mut unreadable = unreadable_files(set, &mut live);
    // Pruned once, over every kind's ids: a kind pruning alone would drop the
    // first-seen time of every other kind (R11).
    set.first_seen.retain(|seen, _| live.contains(seen));
    for kind in [&mut changed, &mut requests, &mut adopt, &mut unreadable] {
        sort(kind);
    }
    changed
        .into_iter()
        .chain(requests)
        .chain(adopt)
        .chain(unreadable)
        .map(|(_, item)| item)
        .collect()
}

/// The time `item_id` was first shown, recorded now if this is its first.
fn first_seen(set: &mut DecisionSet, item_id: &str, live: &mut Vec<String>) -> DateTime<Utc> {
    let now = set.now.unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    live.push(item_id.to_string());
    *set.first_seen.entry(item_id.to_string()).or_insert(now)
}

/// One adopt decision per unmanaged client find; an adopt waits on nothing.
fn adopt_items(set: &mut DecisionSet, live: &mut Vec<String>) -> Vec<Dated> {
    let key = set.key;
    let finds = set.adopt.clone();
    finds
        .iter()
        .map(|find| {
            let item_id = id(&key, "adopt", &json!([find.find_id]));
            let observed = first_seen(set, &item_id, live);
            (
                observed,
                json!({
                    "id": item_id,
                    "kind": "adopt",
                    "server": {
                        "name": display::name(&key, &find.name),
                        "source": find.source,
                        "config_file": find.config_file,
                        "transport": find.transport,
                        "command": find.command,
                        "url": find.url,
                    },
                    "severity": find.severity,
                    "observed_at": time(observed),
                    "waits_on": [],
                }),
            )
        })
        .collect()
}

/// One decision per client config file that could not be read: its file name
/// and reason class, never its path or contents.
fn unreadable_files(set: &mut DecisionSet, live: &mut Vec<String>) -> Vec<Dated> {
    let key = set.key;
    let files = set.unreadable.clone();
    files
        .iter()
        .map(|file| {
            let item_id = id(
                &key,
                "client_config_unreadable",
                &json!([file.source, file.path_digest]),
            );
            let observed = first_seen(set, &item_id, live);
            (
                observed,
                json!({
                    "id": item_id,
                    "kind": "client_config_unreadable",
                    "source": file.source,
                    "file": file.file,
                    "reason": file.reason.as_str(),
                    "observed_at": time(observed),
                }),
            )
        })
        .collect()
}

/// The changed capabilities, and which trusted name each one blocks.
fn changed_capabilities(set: &mut DecisionSet, live: &mut Vec<String>) -> (Vec<Dated>, Blocks) {
    let key = set.key;
    let now = set.now.unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut changed: Vec<Dated> = Vec::new();
    let mut live_ids = Vec::new();
    for ((backend, file), change) in &set.changes {
        let item_id = id(
            &key,
            "capability_changed",
            &json!([backend, file, change.actual]),
        );
        let observed = *set.first_seen.entry(item_id.clone()).or_insert(now);
        live_ids.push(item_id.clone());
        if let Some(trusted) = &change.loaded_as {
            blocks
                .entry(trusted.clone())
                .or_default()
                .push(item_id.clone());
        }
        // The trust card's own inference, over the changed bytes parsed
        // without their pin check; only its class is kept.
        let scan = crate::capability::parse_capability(&change.content)
            .ok()
            .map(|capability| {
                crate::trust::generator::trust_card_from_capability(&capability)
                    .server
                    .risk_class
            });
        let tool = change.loaded_as.as_deref().map_or_else(
            || display::label(&key, file),
            |trusted| display::name(&key, trusted),
        );
        changed.push((
            observed,
            json!({
                "id": item_id,
                "kind": "capability_changed",
                "backend": display::name(&key, backend),
                "tool": tool,
                "trusted_name": change.loaded_as.is_some(),
                "after": display::summary(&change.content),
                "before": null,
                "before_reason": "no_history",
                "scan": scan,
                "scan_basis": "inferred",
                "scan_reason": scan.is_none().then_some("unparsed"),
                "tools_off": 1,
                "off_since": time(observed),
                "observed_at": time(observed),
                "refused_calls": null,
                "refused_calls_reason": "not_linked",
                "waits_on": [],
            }),
        ));
    }
    live.extend(live_ids);
    (changed, blocks)
}

/// One access request being gathered from its open capabilities.
struct Open<'a> {
    scope: Vec<Value>,
    capabilities: Vec<&'a str>,
    refused: usize,
    first: DateTime<Utc>,
    newest: DateTime<Utc>,
}

/// The open access requests, one per subject and agent, each waiting on the
/// changed capabilities its scope names.
fn access_requests(set: &DecisionSet, blocks: &Blocks) -> Vec<Dated> {
    let key = set.key;
    let mut open: BTreeMap<&AccessKey, Open<'_>> = BTreeMap::new();
    for ((access, capability), requested) in &set.requested {
        let pending: Vec<DateTime<Utc>> = requested.pending(set.edge).copied().collect();
        let (Some(first), Some(newest)) = (pending.iter().min(), pending.iter().max()) else {
            continue;
        };
        if set.covered(access, capability, requested) {
            continue;
        }
        let entry = open.entry(access).or_insert_with(|| Open {
            scope: Vec::new(),
            capabilities: Vec::new(),
            refused: 0,
            first: *first,
            newest: *newest,
        });
        entry.scope.push(json!({
            "capability": display::name(&key, capability),
            "tool": requested.tool.as_deref().map(|tool| display::name(&key, tool)),
            "grant_scope": requested.scope,
            "read_only": requested.scope == Some(GrantScope::Read),
        }));
        entry.capabilities.push(capability);
        entry.refused += pending.len();
        entry.first = entry.first.min(*first);
        entry.newest = entry.newest.max(*newest);
    }
    let mut requests = Vec::new();
    for (access, request) in open {
        let waits_on: Vec<&String> = request
            .capabilities
            .iter()
            .filter_map(|capability| blocks.get(*capability))
            .flatten()
            .collect();
        let tuple = json!([access.authority, access.subject, access.agent]);
        requests.push((
            request.newest,
            json!({
                "id": id(&key, "access_request", &tuple),
                "kind": "access_request",
                "subject": {
                    "authority": display::authority(&key, &access.authority),
                    "id": display::name(&key, &access.subject),
                },
                "agent": display::agent(&key, &access.agent),
                "scope": request.scope,
                "server_tools_total": null,
                "server_tools_total_reason": "not_tracked",
                "refused_calls": request.refused,
                "first": time(request.first),
                "observed_at": time(request.newest),
                "waits_on": waits_on,
                "note": null,
                "note_reason": "not_recorded",
                "policy": null,
                "policy_reason": "not_recorded",
                "severity": null,
                "severity_reason": "not_rated",
            }),
        ));
    }

    requests
}
