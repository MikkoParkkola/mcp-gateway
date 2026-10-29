// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The production part of a Rust source file, for the tests that scan the
//! source tree: each `#[cfg(test)]` item is removed by its own extent, so code
//! after an early test module or test-only item is still scanned. Shared by
//! the library's tests and, through `#[path]`, by the binary's tests and the
//! integration tests.

/// `text` with every `#[cfg(test)]` item removed: an item with a block (an
/// inline module, a function, an impl) up to the brace that closes it, any
/// other item (a `mod x;`, a `use`, a constant) up to its `;`. Braces are
/// counted plainly; an item whose block never closes leaves the whole file,
/// so a scan sees more, never less.
pub(crate) fn production_text(text: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        let item = &rest[at..];
        let Some(end) = item_end(item) else {
            return text.to_string();
        };
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// Where the item starting at `item` (its `#[cfg(test)]` line) ends: after
/// its block's closing brace, or after its `;` when that comes first.
fn item_end(item: &str) -> Option<usize> {
    let semi = item.find(';');
    let open = item.find('{');
    match (open, semi) {
        (Some(open), Some(semi)) if semi < open => Some(semi + 1),
        (None, Some(semi)) => Some(semi + 1),
        (Some(open), _) => {
            let mut depth = 0_usize;
            for (at, c) in item[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(open + at + 1);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        (None, None) => None,
    }
}
