// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8113`: the seam receipts of a plan's final answer.
//!
//! Bounds: one walk of the answer, one tagged pass per form in the detector,
//! at most one receipt per contributing source and [`COMPOSITES`] composite
//! receipts, past which the remaining seams are grouped by flow policy. Each
//! seam fingerprint is recorded under exactly one receipt per delivery.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

use crate::security::firewall::{DeliveryDigest, Firewall};

use super::super::Receipt;
use super::PLAN_MEMBERS;

/// Composite receipts per delivery, by contributing-source set; the rest are
/// grouped by policy (sensitivity and the contributors' flow masks).
const COMPOSITES: usize = 16;

/// The seam fingerprints of one set of contributing sources, and whether
/// any contributing step was delivered sensitive.
#[derive(Default)]
struct Group {
    sensitive: bool,
    fps: Vec<u64>,
}

/// Rebuild the seam receipts of `receipts`, the delivery's plan step
/// receipts already kept to `answer`, the plan's decoded final answer.
pub(in super::super) fn add_seams(fw: &Firewall, receipts: &mut Vec<Receipt>, answer: &Value) {
    receipts.retain(|r| !r.seam);
    let members = PLAN_MEMBERS
        .try_with(|m| m.borrow().clone())
        .unwrap_or_default();
    if members.is_empty() {
        return;
    }
    let notes: HashMap<&str, u32> = members.iter().map(|(p, l)| (p.as_str(), *l)).collect();
    let mut parts = Vec::new();
    match answer {
        Value::Object(map) => {
            for (k, v) in map
                .iter()
                .filter(|(k, _)| k.as_str() != "_context_integrity")
            {
                let mut at = format!("/{}", super::pointer_token(k));
                let label = notes.get(at.as_str()).copied();
                walk(v, &mut at, label, &notes, &mut parts);
            }
        }
        _ => walk(answer, &mut String::new(), None, &notes, &mut parts),
    }
    // A leaf is its step's only while the step's receipt keeps it whole: text
    // a rewrite changed, or an equal string from elsewhere, is no step's.
    let owned = |(text, label): (&str, Option<u32>)| {
        label.filter(|l| {
            receipts
                .iter()
                .any(|r| r.in_plan && r.step == Some(*l) && r.digest.keeps_whole_value(text))
        })
    };
    let parts: Vec<(&str, Option<u32>)> = parts.into_iter().map(|p| (p.0, owned(p))).collect();
    if parts
        .iter()
        .filter_map(|p| p.1)
        .collect::<BTreeSet<_>>()
        .len()
        < 2
    {
        return;
    }
    let seams = fw.seam_fingerprints(&parts);
    let Some(caller) = receipts.iter().find(|r| r.in_plan) else {
        return;
    };
    let (key, keyed) = (caller.key.clone(), caller.keyed);
    let mut groups: BTreeMap<BTreeSet<(String, String)>, Group> = BTreeMap::new();
    for (fp, labels) in seams {
        let contributors = receipts
            .iter()
            .filter(|r| r.in_plan && r.step.is_some_and(|s| labels.contains(&s)));
        let mut sources = BTreeSet::new();
        let mut sensitive = false;
        for r in contributors {
            sources.insert((r.server.clone(), r.tool.clone()));
            sensitive |= r.digest.is_sensitive();
        }
        if sources.is_empty() {
            continue;
        }
        let group = groups.entry(sources).or_default();
        group.sensitive |= sensitive;
        group.fps.push(fp);
    }
    let seam = |server: String, tool: String, digest: DeliveryDigest| Receipt {
        key: key.clone(),
        keyed,
        server,
        tool,
        digest,
        in_plan: false,
        pending_retain: false,
        step: None,
        seam: true,
    };
    let mut composites = 0;
    let mut overflow: BTreeMap<(bool, Vec<u64>), (BTreeSet<String>, Vec<u64>)> = BTreeMap::new();
    for (sources, group) in groups {
        if let [(server, tool)] = sources.iter().collect::<Vec<_>>().as_slice() {
            let digest = DeliveryDigest::of_seam(group.fps, group.sensitive, None);
            receipts.push(seam(server.clone(), tool.clone(), digest));
            continue;
        }
        let names: BTreeSet<String> = sources.iter().map(|(s, t)| format!("{s}:{t}")).collect();
        if composites < COMPOSITES {
            composites += 1;
            receipts.push(composite(&seam, names, group));
            continue;
        }
        let list: Vec<String> = names.iter().cloned().collect();
        let mut masks = fw.source_masks(&list);
        masks.sort_unstable();
        masks.dedup();
        let slot = overflow.entry((group.sensitive, masks)).or_default();
        slot.0.extend(names);
        slot.1.extend(group.fps);
    }
    for ((sensitive, _), (names, fps)) in overflow {
        receipts.push(composite(&seam, names, Group { sensitive, fps }));
    }
}

/// The composite receipt of a seam joining `names`: its identity names
/// every contributing source, under an empty server, which no backend can
/// be named (`:` is refused in backend names), so it never aliases one.
fn composite(
    seam: &dyn Fn(String, String, DeliveryDigest) -> Receipt,
    names: BTreeSet<String>,
    group: Group,
) -> Receipt {
    let names: Vec<String> = names.into_iter().collect();
    let identity = format!("seam{}", serde_json::to_string(&names).unwrap_or_default());
    let sources = Some(names.into_boxed_slice());
    let digest = DeliveryDigest::of_seam(group.fps, group.sensitive, sources);
    seam(String::new(), identity, digest)
}

/// Push `value`'s string leaves, in the order a delivery walk reads them,
/// each with the label of the step whose noted member holds it.
fn walk<'v>(
    value: &'v Value,
    at: &mut String,
    label: Option<u32>,
    notes: &HashMap<&str, u32>,
    parts: &mut Vec<(&'v str, Option<u32>)>,
) {
    let len = at.len();
    match value {
        Value::String(s) => parts.push((s, label)),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                at.push('/');
                at.push_str(&i.to_string());
                let inner = notes.get(at.as_str()).copied().or(label);
                walk(item, at, inner, notes, parts);
                at.truncate(len);
            }
        }
        Value::Object(map) => {
            for (k, item) in map {
                at.push('/');
                at.push_str(&super::pointer_token(k));
                let inner = notes.get(at.as_str()).copied().or(label);
                walk(item, at, inner, notes, parts);
                at.truncate(len);
            }
        }
        _ => {}
    }
}
