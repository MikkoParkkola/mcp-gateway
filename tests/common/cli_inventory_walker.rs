// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The CLI surface as clap itself reports it (MIK-8170).
//!
//! Membership of the `## Surface: cli` table in docs/design/surface-4.0.md
//! is decided here, from clap's built `Command`, instead of by regex over
//! the derive source: an attribute nobody modelled can no longer hide a flag.

use std::collections::BTreeMap;

use clap::{Arg, Command};

/// Item ids in the doc's spelling, each with the id it aliases (if any).
#[derive(Default)]
pub struct Walk {
    pub items: BTreeMap<String, Option<String>>,
    origins: BTreeMap<String, String>,
    pub errors: Vec<String>,
}

impl Walk {
    fn add(&mut self, id: String, alias_of: Option<String>, origin: String) {
        match self.origins.get(&id) {
            Some(prev) if *prev != origin => self.errors.push(format!(
                "collision: `{id}` comes from both {prev} and {origin}"
            )),
            Some(_) => {}
            None => {
                self.origins.insert(id.clone(), origin);
                self.items.insert(id, alias_of);
            }
        }
    }
}

/// Walk `unbuilt` and the same command after `build()`.
#[must_use]
pub fn walk(unbuilt: &Command) -> Walk {
    let mut built = unbuilt.clone();
    built.build();
    let mut w = Walk::default();
    let root = unbuilt.get_name().to_string();
    w.add(root.clone(), None, format!("command {root}"));
    visit(&mut w, &built, unbuilt, &root, &[]);
    w
}

fn flag_forms(a: &Arg) -> (Option<String>, Option<char>, Vec<String>, Vec<char>) {
    let mut aliases: Vec<String> = a
        .get_all_aliases()
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect();
    aliases.sort();
    let mut shorts = a.get_all_short_aliases().unwrap_or_default();
    shorts.sort_unstable();
    (
        a.get_long().map(str::to_owned),
        a.get_short(),
        aliases,
        shorts,
    )
}

fn visit(w: &mut Walk, b: &Command, u: &Command, path: &str, ancestors: &[&Command]) {
    for arg in b.get_arguments() {
        let id = arg.get_id().as_str();
        let local = u.get_arguments().any(|a| a.get_id() == id);
        let generated = matches!(id, "help" | "version");
        if local || generated {
            emit_arg(w, path, arg);
            continue;
        }
        let inherited = arg.is_global_set()
            && ancestors
                .iter()
                .rev()
                .find_map(|c| c.get_arguments().find(|a| a.get_id() == id))
                .is_some_and(|def| flag_forms(def) == flag_forms(arg));
        if !inherited {
            w.errors.push(format!(
                "built arg `{id}` on `{path}` is neither local, generated nor propagated unchanged"
            ));
        }
    }
    if b.is_allow_external_subcommands_set() {
        w.add(
            format!("{path} <external>"),
            None,
            format!("external {path}"),
        );
    }
    let mut chain = ancestors.to_vec();
    chain.push(u);
    for sc in b.get_subcommands() {
        let name = sc.get_name();
        let sub = format!("{path} {name}");
        let Some(us) = u.find_subcommand(name) else {
            if name == "help" {
                // Generated; its subtree is a clone of the whole tree.
                w.add(sub.clone(), None, format!("command {sub}"));
            } else {
                w.errors.push(format!(
                    "built subcommand `{sub}` has no unbuilt definition"
                ));
            }
            continue;
        };
        w.add(sub.clone(), None, format!("command {sub}"));
        for alias in sc.get_all_aliases() {
            w.add(
                format!("{path} {alias}"),
                Some(sub.clone()),
                format!("command alias {sub}"),
            );
        }
        let shorts = sc
            .get_short_flag()
            .into_iter()
            .chain(sc.get_all_short_flag_aliases());
        for c in shorts {
            w.add(
                format!("{path} -{c}"),
                Some(sub.clone()),
                format!("command flag {sub}"),
            );
        }
        let longs = sc
            .get_long_flag()
            .into_iter()
            .chain(sc.get_all_long_flag_aliases());
        for l in longs {
            w.add(
                format!("{path} --{l}"),
                Some(sub.clone()),
                format!("command flag {sub}"),
            );
        }
        visit(w, sc, us, &sub, &chain);
    }
}

fn emit_arg(w: &mut Walk, path: &str, a: &Arg) {
    let origin = format!("arg {} on {path}", a.get_id());
    if a.is_positional() {
        let name = a
            .get_value_names()
            .and_then(|n| n.first())
            .map_or_else(|| a.get_id().to_string(), ToString::to_string);
        w.add(format!("{path} <{name}>"), None, origin);
        return;
    }
    let canonical = match (a.get_long(), a.get_short()) {
        (Some(l), _) => format!("{path} --{l}"),
        (None, Some(s)) => format!("{path} -{s}"),
        (None, None) => return,
    };
    w.add(canonical.clone(), None, origin.clone());
    if a.get_long().is_some()
        && let Some(s) = a.get_short()
    {
        w.add(
            format!("{path} -{s}"),
            Some(canonical.clone()),
            origin.clone(),
        );
    }
    for l in a.get_all_aliases().unwrap_or_default() {
        w.add(
            format!("{path} --{l}"),
            Some(canonical.clone()),
            origin.clone(),
        );
    }
    for s in a.get_all_short_aliases().unwrap_or_default() {
        w.add(
            format!("{path} -{s}"),
            Some(canonical.clone()),
            origin.clone(),
        );
    }
}

/// `Item -> Class` for every row of the doc's `## Surface: cli` table.
#[must_use]
pub fn doc_rows(md: &str) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    let mut header: Option<Vec<String>> = None;
    let mut inside = false;
    for line in md.lines() {
        if line.starts_with("## ") {
            inside = line.trim() == "## Surface: cli";
            header = None;
            continue;
        }
        if !inside || !line.trim_start().starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect();
        let Some(h) = &header else {
            header = Some(cells.iter().map(|c| c.to_lowercase()).collect());
            continue;
        };
        if cells
            .iter()
            .all(|c| c.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
        {
            continue;
        }
        let col = |name: &str| {
            h.iter()
                .position(|c| c == name)
                .and_then(|i| cells.get(i))
                .cloned()
                .unwrap_or_default()
        };
        let item = col("item");
        let item = item
            .strip_prefix('`')
            .and_then(|s| s.strip_suffix('`'))
            .unwrap_or(&item)
            .to_owned();
        rows.insert(item, col("class"));
    }
    rows
}

/// Every disagreement between clap and the doc, one line each.
#[must_use]
pub fn compare(w: &Walk, rows: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = w.errors.clone();
    for (id, target) in &w.items {
        match rows.get(id) {
            None => out.push(format!("missing row: `{id}`")),
            Some(class) => {
                if let Some(t) = target
                    && let Some(tc) = rows.get(t)
                    && tc != class
                {
                    out.push(format!("alias `{id}` is {class}, its target `{t}` is {tc}"));
                }
            }
        }
    }
    for id in rows.keys() {
        if !w.items.contains_key(id) {
            out.push(format!("stale row: `{id}` is not in the CLI"));
        }
    }
    out
}
