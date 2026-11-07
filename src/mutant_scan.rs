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
            TokenTree::Ident(ident) if ident == "mutant" => {
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

/// The value of the stream's first token when it is a plain string literal.
fn first_string(stream: TokenStream) -> Option<String> {
    let Some(TokenTree::Literal(lit)) = stream.into_iter().next() else {
        return None;
    };
    let text = lit.to_string();
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .map(str::to_owned)
}

/// Every git-tracked `.rs` file under `root`, as repository-relative paths.
///
/// # Errors
///
/// `git ls-files` could not run or failed.
pub(crate) fn tracked_rs_files(root: &std::path::Path) -> Result<Vec<String>, String> {
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

/// Every `mutant!` call in the repository at `root`, with its file. A
/// tracked file deleted from the working tree is skipped, and named.
///
/// # Errors
///
/// The file list could not be read, or a file could not be read or
/// tokenized: the scan fails rather than skip what it cannot see.
pub(crate) fn repo_sites(root: &std::path::Path) -> Result<Vec<(String, Site)>, String> {
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
        for site in sites(&text).map_err(|e| format!("{path}: {e}"))? {
            found.push((path.clone(), site));
        }
    }
    Ok(found)
}

#[cfg(test)]
#[path = "mutant_scan_tests.rs"]
mod tests;
