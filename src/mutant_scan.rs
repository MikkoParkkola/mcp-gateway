// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The mutant-site scan (SCH.3, SCH.6): every `mutant!` call in the
//! repository, read lexically from the token stream and recursive into every
//! group, so a call nested inside another macro's tokens is found and one
//! inside a comment or a string is not. The scan row and the mutant runner's
//! site list both read it, so the two cannot disagree.

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// One `mutant!` call: the ID it names (its first token, when that is a
/// string literal) and its 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    pub(crate) id: Option<String>,
    pub(crate) line: usize,
}

/// Every `mutant!` call in `text`.
///
/// # Errors
///
/// The text does not tokenize (an unbalanced delimiter or a bad literal).
pub(crate) fn sites(text: &str) -> Result<Vec<Site>, String> {
    let stream: TokenStream = text.parse().map_err(|e| format!("{e}"))?;
    let mut found = Vec::new();
    walk(stream, &mut found);
    Ok(found)
}

/// An identifier `mutant`, then `!`, then a delimited group, at any depth.
fn walk(stream: TokenStream, found: &mut Vec<Site>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    for (i, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident) if is_named(ident, "mutant") => {
                let bang =
                    matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                if let (true, Some(TokenTree::Group(args))) = (bang, tokens.get(i + 2))
                    && args.delimiter() != Delimiter::None
                {
                    found.push(Site {
                        id: first_string(args.stream()),
                        line: ident.span().start().line,
                    });
                }
            }
            TokenTree::Group(group) => walk(group.stream(), found),
            _ => {}
        }
    }
}

/// Whether `ident` names `name`, written plainly or as a raw identifier
/// (`r#mutant` is the same macro to the compiler).
fn is_named(ident: &proc_macro2::Ident, name: &str) -> bool {
    let text = ident.to_string();
    text.strip_prefix("r#").unwrap_or(&text) == name
}

/// The ID a site names: its first token, when that is a string literal whose
/// value is its spelling (a plain or raw string with no escapes). Anything
/// else, an escaped or computed ID, is `None`: the runner then refuses the
/// site rather than guess its value.
fn first_string(stream: TokenStream) -> Option<String> {
    let Some(TokenTree::Literal(lit)) = stream.into_iter().next() else {
        return None;
    };
    let text = lit.to_string();
    let raw = text.strip_prefix('r').map(|t| t.trim_matches('#'));
    let body = raw
        .unwrap_or(&text)
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))?;
    (raw.is_some() || !body.contains('\\')).then(|| body.to_owned())
}

/// Every git-tracked `.rs` file under `root`, as repository-relative paths.
///
/// # Errors
///
/// `git ls-files` could not run or failed.
pub(crate) fn tracked_rs_files(root: &std::path::Path) -> Result<Vec<String>, String> {
    // A copy of the tree with no git metadata (the remote build mirror ships
    // the working tree without .git): every .rs file on disk instead, a
    // superset of the tracked ones, so the scan can only find more.
    if !root.join(".git").exists() {
        let mut found = Vec::new();
        walk_rs(root, root, &mut found)?;
        found.sort();
        return Ok(found);
    }
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!("git ls-files failed: {out:?}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Every `.rs` file under `dir`, relative to `root`, skipping build output
/// (`target`) and symbolic links.
fn walk_rs(
    root: &std::path::Path,
    dir: &std::path::Path,
    found: &mut Vec<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if dir != root || entry.file_name() != "target" {
                walk_rs(root, &path, found)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path.strip_prefix(root).map_err(|e| format!("{e}"))?;
            found.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

/// Every `mutant!` call in the repository at `root`, with its file. A
/// tracked file deleted from the working tree is skipped, and named.
///
/// # Errors
///
/// The file list could not be read, or a file could not be read or
/// tokenized: the scan fails rather than skip what it cannot see.
pub(crate) fn repo_sites(root: &std::path::Path) -> Result<Vec<(String, Site)>, String> {
    scan_repo(root, sites)
}

/// The 1-based line of every `macro_rules! mutant` definition in `text`, at
/// any depth: a definition nested in a module or another macro would shadow
/// the crate's own.
///
/// # Errors
///
/// As [`sites`].
pub(crate) fn definitions(text: &str) -> Result<Vec<usize>, String> {
    fn walk_defs(stream: TokenStream, found: &mut Vec<usize>) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            match token {
                TokenTree::Ident(ident) if is_named(ident, "macro_rules") => {
                    let bang = matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                    if let (true, Some(TokenTree::Ident(name))) = (bang, tokens.get(i + 2))
                        && is_named(name, "mutant")
                    {
                        found.push(name.span().start().line);
                    }
                }
                TokenTree::Group(group) => walk_defs(group.stream(), found),
                _ => {}
            }
        }
    }
    let stream: TokenStream = text.parse().map_err(|e| format!("{e}"))?;
    let mut found = Vec::new();
    walk_defs(stream, &mut found);
    Ok(found)
}

/// Every `macro_rules! mutant` definition in the repository at `root`.
///
/// # Errors
///
/// As [`repo_sites`].
pub(crate) fn repo_definitions(root: &std::path::Path) -> Result<Vec<(String, usize)>, String> {
    scan_repo(root, definitions)
}

/// `per_file` over every tracked `.rs` file, with its path.
fn scan_repo<T>(
    root: &std::path::Path,
    per_file: fn(&str) -> Result<Vec<T>, String>,
) -> Result<Vec<(String, T)>, String> {
    let mut found = Vec::new();
    for path in tracked_rs_files(root)? {
        let text = match std::fs::read_to_string(root.join(&path)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("mutant scan: {path} is tracked but absent; skipped");
                continue;
            }
            Err(e) => return Err(format!("{path}: {e}")),
        };
        for item in per_file(&text).map_err(|e| format!("{path}: {e}"))? {
            found.push((path.clone(), item));
        }
    }
    Ok(found)
}

#[cfg(test)]
#[path = "mutant_scan_tests.rs"]
mod tests;
