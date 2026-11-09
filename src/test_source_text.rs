// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The production part of a Rust source file, for the tests that scan the
//! source tree: each item compiled only under test is blanked by its own
//! extent, so code after an early test module or test-only item is still
//! scanned. Also the one shared judgement of what compiles only under test
//! ([`eval`], [`test_only`]; MIK-9387.TCFG.1). Shared by the library's tests
//! and, through `#[path]`, by the binary's tests and the integration tests, so
//! nothing here names a `crate::` item.

/// A cfg predicate's value with `test` false and every other atom unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cfg {
    True,
    False,
    Unknown,
}

/// Evaluate one cfg predicate (`test`, `not(..)`, `all(..)`, `any(..)`, or
/// any other atom). `all()` is true and `any()` false, as Rust defines them.
/// Operands that do not parse leave the predicate unknown: read as an empty
/// `any()` they would make it false, and the item test-only.
pub(crate) fn eval(meta: &syn::Meta) -> Cfg {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Cfg::False,
        syn::Meta::List(list) => {
            let Ok(args) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return Cfg::Unknown;
            };
            let values: Vec<Cfg> = args.iter().map(eval).collect();
            if list.path.is_ident("not") {
                match values.as_slice() {
                    [Cfg::True] => Cfg::False,
                    [Cfg::False] => Cfg::True,
                    _ => Cfg::Unknown,
                }
            } else if list.path.is_ident("all") {
                if values.contains(&Cfg::False) {
                    Cfg::False
                } else if values.iter().all(|v| *v == Cfg::True) {
                    Cfg::True
                } else {
                    Cfg::Unknown
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Cfg::True) {
                    Cfg::True
                } else if values.iter().all(|v| *v == Cfg::False) {
                    Cfg::False
                } else {
                    Cfg::Unknown
                }
            } else {
                Cfg::Unknown
            }
        }
        _ => Cfg::Unknown,
    }
}

/// Whether `attrs` carry a `#[cfg(..)]` that is definitely false outside
/// tests: the node exists only in test builds.
#[allow(
    dead_code,
    reason = "the binary's and integration tests' copies use only production_text"
)]
pub(crate) fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| eval(&meta) == Cfg::False)
    })
}

/// `text` with every item compiled only under test blanked: spaces in place
/// of its bytes, newlines kept, so positions and line numbers still match
/// `text` and literals outside test items survive. An item is test-only when
/// its `#[cfg(..)]` evaluates false ([`eval`]): `all(test, ..)` is, while
/// `any(test, unix)` and a predicate that does not parse are not. An inner
/// `#![cfg(..)]` counts only in the leading attribute run of the file (the
/// whole text is blanked) or of an inline module (its block is); anywhere
/// else, such as inside a macro's tokens, it marks nothing. Only attributes
/// in code count: one in a comment or a string is not an attribute. An item
/// whose extent cannot be found is left in place (a scan sees more, never
/// less); the others are still blanked.
pub(crate) fn production_text(text: &str) -> String {
    let code = sanitize(text);
    let (c, t) = (code.as_bytes(), text.as_bytes());
    let mut out = t.to_vec();
    let mut from = 0;
    while let Some(at) = code[from..].find('#').map(|p| p + from) {
        let Some(attr) = cfg_attribute(c, at) else {
            from = at + 1;
            continue;
        };
        // The predicate is parsed from the original text, so quoted values
        // survive; the sanitized code only located it.
        let only_under_test = syn::parse_str::<syn::Meta>(&text[attr.open + 1..attr.close])
            .is_ok_and(|meta| eval(&meta) == Cfg::False);
        from = attr.end;
        if !only_under_test {
            continue;
        }
        if !attr.inner {
            if let Some(end) = item_end(c, t, attr.end) {
                blank(&mut out, at, end);
                from = end;
            }
            continue;
        }
        match leading_scope(c, at) {
            Some(Scope::File) => {
                blank(&mut out, 0, t.len());
                break;
            }
            Some(Scope::Module(open)) => {
                if let Some(close) = block_close(c, open) {
                    blank(&mut out, open + 1, close);
                    from = close;
                }
            }
            None => {}
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// A `#[cfg(..)]` or `#![cfg(..)]` in sanitized code: whether it is inner,
/// its predicate's parentheses, and the offset just past its `]`.
struct CfgAttribute {
    inner: bool,
    open: usize,
    close: usize,
    end: usize,
}

fn cfg_attribute(code: &[u8], at: usize) -> Option<CfgAttribute> {
    let skip = |mut i: usize| {
        while code.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        i
    };
    let mut i = at + 1;
    let inner = code.get(i) == Some(&b'!');
    if inner {
        i += 1;
    }
    i = skip(i);
    if code.get(i) != Some(&b'[') {
        return None;
    }
    i = skip(i + 1);
    let ident = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
    if !code[i..].starts_with(b"cfg") || code.get(i + 3).is_some_and(ident) {
        return None;
    }
    let open = skip(i + 3);
    if code.get(open) != Some(&b'(') {
        return None;
    }
    let close = matching(code, open)?;
    let end = skip(close + 1);
    (code.get(end) == Some(&b']')).then_some(CfgAttribute {
        inner,
        open,
        close,
        end: end + 1,
    })
}

/// The bracket closing the one opened at `open`, any of `()[]{}` nesting.
fn matching(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    (open..code.len()).find(|&j| {
        match code[j] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => return false,
        }
        depth == 0
    })
}

/// The `}` closing the block opened at `open`.
fn block_close(code: &[u8], open: usize) -> Option<usize> {
    matching(code, open)
}

/// The scope an inner attribute leads when it sits in a leading run of inner
/// attributes: the file's, or an inline `mod name {` block's.
enum Scope {
    File,
    Module(usize),
}

fn leading_scope(code: &[u8], at: usize) -> Option<Scope> {
    let back = |mut i: usize| {
        while i > 0 && code[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        i
    };
    let mut i = back(at);
    loop {
        // A shebang line opens no scope of its own.
        let shebang =
            code.starts_with(b"#!") && !code.starts_with(b"#![") && !code[..i].contains(&b'\n');
        if i == 0 || shebang {
            return Some(Scope::File);
        }
        match code[i - 1] {
            b']' => {
                // Step back over an earlier inner attribute of the same run.
                let mut depth = 0_usize;
                let open = (0..i).rev().find(|&j| {
                    match code[j] {
                        b']' | b')' | b'}' => depth += 1,
                        b'[' | b'(' | b'{' => depth = depth.saturating_sub(1),
                        _ => return false,
                    }
                    depth == 0
                })?;
                let k = back(open);
                if k < 2 || &code[k - 2..k] != b"#!" {
                    return None;
                }
                i = back(k - 2);
            }
            b'{' if module_header(&code[..i - 1]) && !in_macro_tokens(code, i - 1) => {
                return Some(Scope::Module(i - 1));
            }
            _ => return None,
        }
    }
}

/// Whether offset `at` sits inside a macro's tokens: a `name!(..)`, `name![..]`
/// or `name!{..}` call, or a `macro_rules! name {..}` body. A `mod` written
/// there is input the macro may drop or rewrite, so its inner attributes mark
/// nothing.
fn in_macro_tokens(code: &[u8], at: usize) -> bool {
    // An identifier byte: ASCII word characters, or any byte of a non-ASCII
    // character (Rust identifiers may be Unicode). `#` covers a raw `r#name`.
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'#' || !c.is_ascii();
    let space = |c: u8| c.is_ascii_whitespace();
    let mut i = 0;
    while i < at {
        // `name!`, also `name !` (comments are already blanked to spaces).
        let mut k = i;
        while k > 0 && space(code[k - 1]) {
            k -= 1;
        }
        let named = code[i] == b'!' && k > 0 && ident(code[k - 1]) && code[k - 1] != b'#';
        if named {
            let mut j = i + 1;
            while code.get(j).copied().is_some_and(space) {
                j += 1;
            }
            // `macro_rules! name {`: step over the name.
            while code.get(j).copied().is_some_and(ident) {
                j += 1;
            }
            while code.get(j).copied().is_some_and(space) {
                j += 1;
            }
            if matches!(code.get(j), Some(b'(' | b'[' | b'{')) {
                match matching(code, j) {
                    Some(close) if j < at && at < close => return true,
                    Some(close) => {
                        i = close;
                        continue;
                    }
                    None => return j < at,
                }
            }
        }
        i += 1;
    }
    false
}

/// Whether `before` ends with `mod name` (so the `{` after it opens an inline
/// module).
fn module_header(before: &[u8]) -> bool {
    let text = String::from_utf8_lossy(before);
    let mut words = text.split_whitespace().rev();
    let name = words.next().unwrap_or("");
    let name = name.strip_prefix("r#").unwrap_or(name);
    !name.is_empty()
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && words.next() == Some("mod")
}

/// Where the item after an attribute ends, in `code` (comments and literals
/// already blanked): at a `;` or `,` at its own level (a declaration, a field,
/// a variant, an arm), after a block at its own level that nothing continues
/// (`else`, a method call, `?`), or just before the bracket that closes the
/// item's parent (a last field with no comma). `None` when the text ends first.
/// `text` is the original, to tell a masked literal or comment after a block
/// (which ends the item) from plain whitespace.
///
/// A `,` in a generic header or a `where` clause ends an item early. That is
/// safe here only because [`production_text`] then keeps the item's remainder,
/// so a scan sees more; a reuse that classifies test code would miss it.
fn item_end(code: &[u8], text: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0_usize;
    let mut i = start;
    while i < code.len() {
        match code[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return Some(i),
            b')' | b']' => depth -= 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let next = code[i + 1..].iter().position(|c| !c.is_ascii_whitespace());
                    let gap = &text[i + 1..next.map_or(code.len(), |n| i + 1 + n)];
                    if gap.iter().any(|c| !c.is_ascii_whitespace()) {
                        return Some(i + 1);
                    }
                    let rest = next.map_or(&[][..], |n| &code[i + 1 + n..]);
                    match rest.first() {
                        Some(b';' | b',') => return Some(i + 1 + next.unwrap_or(0) + 1),
                        // `..` after a block starts a range, the next item.
                        Some(b'.') if rest.get(1) != Some(&b'.') => {}
                        Some(b'?') => {}
                        _ if continues_with_else(rest) => {}
                        _ => return Some(i + 1),
                    }
                }
            }
            b';' | b',' if depth == 0 => return Some(i + 1),
            _ => {}
        }
        i += 1;
    }
    None
}

fn continues_with_else(rest: &[u8]) -> bool {
    rest.starts_with(b"else")
        && !rest
            .get(4)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || !c.is_ascii())
}

fn blank(out: &mut [u8], from: usize, to: usize) {
    for c in &mut out[from..to] {
        if *c != b'\n' {
            *c = b' ';
        }
    }
}

/// `src` with comments, string literals and char literals replaced by spaces,
/// newlines kept so positions stay meaningful.
pub(crate) fn sanitize(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            while i < b.len() {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if b[i] == b'r' && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#')) {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                i += 1;
                continue;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            i += 2 + hashes;
            while i < b.len() && !b[i..].starts_with(&close) {
                i += 1;
            }
            i = (i + close.len()).min(b.len());
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else if b[i] == b'\'' && (b.get(i + 1) == Some(&b'\\') || b.get(i + 2) == Some(&b'\'')) {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else {
            i += 1;
            continue;
        }
        blank(&mut out, start, i.min(b.len()));
    }
    String::from_utf8_lossy(&out).into_owned()
}
