// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The reviewed list of inbound parse sites read into rows, and how a scan differs from it.

use super::{BTreeMap, Func, Guard, Sites};

const CLASSES: [&str; 5] = [
    "scrubbed",
    "scrubbed-by",
    "post-transport",
    "not-backend-data",
    "no-injected-values",
];

/// The only files a `no-injected-values` row may name: the class rests on
/// the preview Target pin in the parent module, which covers these alone.
const NO_INJECTED_FILES: [&str; 1] = ["src/transport/preview_pipe.rs"];

struct Row {
    count: usize,
    class: String,
    reason: String,
}

/// The table's rows by (file, function, kind).
type Rows = BTreeMap<(String, String, String), Row>;

fn listed(text: &str) -> (Rows, Vec<String>) {
    let mut rows = BTreeMap::new();
    let mut bad = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split('\t').collect();
        let [file, func, kind, n, class, reason] = cols[..] else {
            bad.push(format!("not six columns: {line}"));
            continue;
        };
        if !CLASSES.contains(&class) || reason.trim().is_empty() {
            bad.push(format!("no class or no reason: {line}"));
        }
        let Ok(count) = n.parse::<usize>() else {
            bad.push(format!("count is not a number: {line}"));
            continue;
        };
        let previous = rows.insert(
            (file.to_owned(), func.to_owned(), kind.to_owned()),
            Row {
                count,
                class: class.to_owned(),
                reason: reason.to_owned(),
            },
        );
        if previous.is_some() {
            bad.push(format!("duplicate row: {line}"));
        }
    }
    (rows, bad)
}

fn func_of(named: &str) -> Option<Func> {
    let (file, func) = named.rsplit_once("::")?;
    Some((file.to_owned(), func.to_owned()))
}

/// What a `scrubbed-by` reason names: `by <file>::<function>:`, or
/// `by <file>::<function> via <file>::<function>:` when the result crosses
/// a channel and the scrubber reaches the receiving function instead.
fn named_scrubber(reason: &str) -> Option<(Func, Option<Func>)> {
    // Up to the first ": ", so the `::` inside the name is kept.
    let (named, _) = reason.strip_prefix("by ")?.split_once(": ")?;
    match named.split_once(" via ") {
        Some((by, via)) => Some((func_of(by)?, Some(func_of(via)?))),
        None => Some((func_of(named)?, None)),
    }
}

/// What is wrong with the scan against the table `text`.
pub(super) fn differences(sites: &Sites, text: &str) -> Vec<String> {
    let (want, mut wrong) = listed(text);
    for (key, n) in &sites.counts {
        match want.get(key) {
            Some(row) if row.count == *n => {}
            Some(row) => wrong.push(format!(
                "count {} -> {n}: {}\t{}\t{}",
                row.count, key.0, key.1, key.2
            )),
            None => wrong.push(format!(
                "unlisted: {}\t{}\t{}\t{n}\t<class>\t<reason>",
                key.0, key.1, key.2
            )),
        }
    }
    for (key, row) in &want {
        if !sites.counts.contains_key(key) {
            wrong.push(format!("stale: {}\t{}\t{}", key.0, key.1, key.2));
        }
        let at = (key.0.clone(), key.1.clone());
        match row.class.as_str() {
            "scrubbed" => match sites.guards.get(&at) {
                Some(Guard::Guarded) => {}
                Some(Guard::BranchOnly) => {
                    wrong.push(format!("scrubs only in a branch: {}\t{}", key.0, key.1));
                }
                Some(Guard::Late) => {
                    wrong.push(format!("scrubs after a send: {}\t{}", key.0, key.1));
                }
                None => wrong.push(format!("lost its scrub call: {}\t{}", key.0, key.1)),
            },
            "scrubbed-by" => match named_scrubber(&row.reason) {
                Some((by, _)) if !sites.scrubbing.contains(&by) => wrong.push(format!(
                    "{}\t{}: {}::{} does not scrub",
                    key.0, key.1, by.0, by.1
                )),
                Some((by, via)) => {
                    let target = via.unwrap_or_else(|| at.clone());
                    if !sites.connected(&by, &target) {
                        wrong.push(format!(
                            "{}\t{}: {}::{} does not reach {}::{}",
                            key.0, key.1, by.0, by.1, target.0, target.1
                        ));
                    }
                }
                None => wrong.push(format!(
                    "{}\t{}: reason must start `by <file>::<function>:`",
                    key.0, key.1
                )),
            },
            "no-injected-values" if !NO_INJECTED_FILES.contains(&key.0.as_str()) => {
                wrong.push(format!(
                    "no-injected-values outside the preview pipe: {}\t{}",
                    key.0, key.1
                ));
            }
            _ => {}
        }
    }
    wrong
}
