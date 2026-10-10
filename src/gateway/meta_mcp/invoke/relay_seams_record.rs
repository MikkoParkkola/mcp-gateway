// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8113`: the seam receipts of a plan's final answer.
//!
//! Bounds: one walk of the answer, one tagged pass per form in the detector,
//! at most one receipt per contributing source and [`COMPOSITES`] composite
//! receipts, past which the remaining seams are grouped by flow policy. Each
//! seam fingerprint is recorded under exactly one receipt per delivery.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::security::firewall::{DeliveryDigest, Firewall};

use super::super::{Kind, Receipt};
use super::PLAN_MEMBERS;

/// Contributing sources, as (server, tool).
type Sources = BTreeSet<(String, String)>;

/// A seam's flow policy: its sensitivity and its distinct flow masks.
type Policy = (bool, Vec<u64>);

/// Composite receipts per delivery, by contributing-source set; the rest are
/// grouped by policy (sensitivity and the contributors' flow masks).
const COMPOSITES: usize = 16;

/// One plan step's kept whole values, its sources and whether any of its
/// receipts was delivered sensitive.
#[derive(Default)]
struct Step<'r> {
    whole: HashSet<&'r str>,
    sources: BTreeSet<(String, String)>,
    sensitive: bool,
}

/// The seam fingerprints of one set of contributing sources, and whether
/// any contributing step was delivered sensitive.
struct Group {
    sensitive: bool,
    fps: Vec<u64>,
}

/// Rebuild the seam receipts of `receipts`, the delivery's plan step
/// receipts already kept to `answer`, the plan's decoded final answer.
pub(in super::super) fn add_seams(fw: &Firewall, receipts: &mut Vec<Receipt>, answer: &Value) {
    receipts.retain(|r| r.kind != Kind::Seam);
    let Some(parts) = answer_parts(answer) else {
        return;
    };
    // Each step's whole kept values, sources and sensitivity, read once.
    let mut steps: HashMap<u32, Step<'_>> = HashMap::new();
    for r in receipts.iter().filter(|r| r.in_plan) {
        let Some(label) = r.step else { continue };
        let step = steps.entry(label).or_default();
        step.whole.extend(r.digest.whole_values());
        step.sources.insert((r.server.clone(), r.tool.clone()));
        step.sensitive |= r.digest.is_sensitive();
    }
    // A leaf is its step's only while the step's receipt keeps it whole: text
    // a rewrite changed, or an equal string from elsewhere, is no step's.
    let parts: Vec<(&str, Option<u32>)> = parts
        .into_iter()
        .map(|(text, label)| {
            let owned = label.filter(|l| steps.get(l).is_some_and(|s| s.whole.contains(text)));
            (text, owned)
        })
        .collect();
    if parts
        .iter()
        .filter_map(|p| p.1)
        .collect::<BTreeSet<_>>()
        .len()
        < 2
    {
        return;
    }
    let seams = seam_fingerprints(fw, &parts, answer);
    let Some(caller) = receipts.iter().find(|r| r.in_plan) else {
        return;
    };
    let (key, keyed) = (caller.key.clone(), caller.keyed);
    // Grouped by contributing sources AND sensitivity, so a fingerprint is
    // sensitive only when its own contributors are.
    let mut groups: BTreeMap<(Sources, bool), Vec<u64>> = BTreeMap::new();
    for (fp, labels) in seams {
        let mut sources = BTreeSet::new();
        let mut sensitive = false;
        for step in labels.iter().filter_map(|l| steps.get(l)) {
            sources.extend(step.sources.iter().cloned());
            sensitive |= step.sensitive;
        }
        if !sources.is_empty() {
            groups.entry((sources, sensitive)).or_default().push(fp);
        }
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
        kind: Kind::Seam,
    };
    let mut composites = 0;
    let mut overflow: BTreeMap<Policy, (BTreeSet<String>, Vec<u64>)> = BTreeMap::new();
    for ((sources, sensitive), fps) in groups {
        let group = Group { sensitive, fps };
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

/// The seam fingerprints of `parts`, the answer's leaves with their owning
/// steps, and (`MIK-8209` K6) of each key-path join whose pieces several
/// steps produced, read run together as delivered. A piece's step is the one
/// the leaf pass gave that same leaf, by identity, so ownership never differs.
fn seam_fingerprints(
    fw: &Firewall,
    parts: &[(&str, Option<u32>)],
    answer: &Value,
) -> Vec<(u64, Vec<u32>)> {
    let mut seams = fw.seam_fingerprints(parts);
    let owner: HashMap<*const u8, u32> = parts
        .iter()
        .filter_map(|(text, label)| Some((text.as_ptr(), (*label)?)))
        .collect();
    seams.extend(fw.join_seam_fingerprints(answer, &|piece| owner.get(&piece.as_ptr()).copied()));
    seams
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

/// `answer`'s string leaves in the order a delivery walk reads them (the
/// value leaves [`crate::security::firewall`]'s `delivery_parts` returns, in
/// its order), each with the plan step whose noted member holds it, a
/// parent's note inherited by the strings under it. `None` outside a plan.
/// One walk serves the seam pass and retention's labels (`MIK-8209` K7).
pub(in super::super) fn answer_parts(answer: &Value) -> Option<Vec<(&str, Option<u32>)>> {
    let members = PLAN_MEMBERS
        .try_with(|m| m.borrow().clone())
        .unwrap_or_default();
    if members.is_empty() {
        return None;
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
    Some(parts)
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

/// `MIK-8205` (S4): attach the subset-forward seams of `answer`'s
/// single-receipt runs to the receipt that produced each run, so
/// `record_digest` stores them under that receipt's source for the plan's
/// caller. A piece belongs to a receipt only when exactly one receipt of its
/// step keeps it whole: one step can hold several receipts of different
/// sources (a nested plan), and a run is attributed only when one receipt
/// owns every piece. A run spanning receipts gets none, so no window is
/// excused under a source that did not produce all of it.
pub(in super::super) fn add_subset_seams(fw: &Firewall, receipts: &mut [Receipt], answer: &Value) {
    let Some(parts) = answer_parts(answer) else {
        return;
    };
    let owner: HashMap<*const u8, u32> = {
        let whole: Vec<(usize, u32, HashSet<&str>)> = receipts
            .iter()
            .enumerate()
            .filter(|(_, r)| r.in_plan)
            .filter_map(|(i, r)| Some((i, r.step?, r.digest.whole_values().collect())))
            .collect();
        parts
            .iter()
            .filter_map(|(text, label)| {
                let label = (*label)?;
                let mut holders = whole
                    .iter()
                    .filter(|(_, step, w)| *step == label && w.contains(text))
                    .map(|(i, _, _)| *i);
                let only = holders.next()?;
                holders
                    .next()
                    .is_none()
                    .then_some((text.as_ptr(), u32::try_from(only).ok()?))
            })
            .collect()
    };
    for (receipt, fps) in
        fw.single_step_subset_seams(answer, &|piece| owner.get(&piece.as_ptr()).copied())
    {
        if let Some(r) = receipts.get_mut(receipt as usize) {
            r.digest.add_seam_excuses(&fps);
        }
    }
}
