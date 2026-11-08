// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production reader of a caller's admin standing, inventoried: the
//! raw `admin` flag, the role mapping's admin answers and the
//! `CallerStanding` constructors. A gateway-wide power reads `Gateway`; admin
//! breadth inside a backend scope reads `InScope` too. A new reader fails the
//! scan until it is listed here with the standing it reads.

/// The key for a struct pattern that binds an `admin` field, with or without a
/// rest (`..`): the name is kept from the text finder, so the inventory reads
/// as before.
const DESTRUCTURED: &str = "{ admin, .. }";

/// Whether `path`, relative to the crate, is test-only source.
fn test_only(path: &std::path::Path) -> bool {
    path.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        let stem = part.strip_suffix(".rs").unwrap_or(&part);
        stem == "tests"
            || stem.ends_with("_tests")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || stem.contains("fixture")
    })
}

fn production_sources(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) {
    for entry in std::fs::read_dir(dir).expect("src reads") {
        let path = entry.expect("a directory entry").path();
        if test_only(path.strip_prefix(root).expect("under the crate")) {
            continue;
        }
        if path.is_dir() {
            production_sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

// ─── The finder: readers by syntax, not text ───────────────────────────────

/// A monitored name, as the inventory keys it, and the shape that reads it.
#[derive(Clone, Copy)]
enum Shape {
    /// A path ending in these segments, wherever it appears (expression,
    /// pattern, function reference): `is_gateway_admin`, `admin_standing`,
    /// `CallerStanding::Admin`.
    Path(&'static [&'static str]),
    /// A call of a path ending in these segments, or a method call of the
    /// last one: `is_admin(`, `resolve_role(`, `CallerStanding::of(`.
    Call(&'static [&'static str]),
    /// A call of a path of at least two segments ending in this one: `::for_ui(`.
    QualifiedCall(&'static str),
    /// A method call with no arguments: `is_gateway()`.
    NullaryMethod(&'static str),
}

const SHAPES: &[(&str, Shape)] = &[
    ("resolve_role(", Shape::Call(&["resolve_role"])),
    ("grants_admin(", Shape::Call(&["grants_admin"])),
    (
        "CallerStanding::of(",
        Shape::Call(&["CallerStanding", "of"]),
    ),
    (
        "CallerStanding::of_client(",
        Shape::Call(&["CallerStanding", "of_client"]),
    ),
    (
        "CallerStanding::Admin",
        Shape::Path(&["CallerStanding", "Admin"]),
    ),
    ("is_gateway_admin", Shape::Path(&["is_gateway_admin"])),
    ("admin_standing", Shape::Path(&["admin_standing"])),
    ("is_gateway()", Shape::NullaryMethod("is_gateway")),
    // No production reader since the one predicate replaced `ui::is_admin`;
    // kept, so a new private `is_admin` is a reader the inventory must list.
    ("is_admin(", Shape::Call(&["is_admin"])),
    ("::for_ui(", Shape::QualifiedCall("for_ui")),
];

/// An identifier as written, with any `r#` removed: `r#admin` is `admin`.
fn plain(ident: &syn::Ident) -> String {
    use syn::ext::IdentExt;
    ident.unraw().to_string()
}

/// The file's `use` bindings: each local name with every full path it may
/// stand for, the paths globbed into scope, and the free functions the file
/// defines. File-wide: a binding in one module is applied everywhere in the
/// file, which can only add matches.
#[derive(Default)]
struct Aliases {
    named: std::collections::BTreeMap<String, Vec<Vec<String>>>,
    globs: Vec<Vec<String>>,
    fns: std::collections::BTreeSet<String>,
    /// Set when [`Aliases::readings`] stopped at its cap: the file fails named.
    capped: std::cell::Cell<bool>,
}

impl Aliases {
    fn of(file: &syn::File) -> Self {
        struct Uses(
            Vec<(Vec<String>, Option<String>)>,
            std::collections::BTreeSet<String>,
        );
        impl<'ast> syn::visit::Visit<'ast> for Uses {
            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                crate::gateway::syn_scan_support::bindings(
                    &item.tree,
                    &mut Vec::new(),
                    &mut self.0,
                );
            }
            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                self.1.insert(plain(&item.sig.ident));
                syn::visit::visit_item_fn(self, item);
            }
        }
        let mut uses = Uses(Vec::new(), std::collections::BTreeSet::new());
        syn::visit::Visit::visit_file(&mut uses, file);
        let unraw = |s: &str| s.strip_prefix("r#").unwrap_or(s).to_owned();
        let mut aliases = Self {
            fns: std::mem::take(&mut uses.1),
            ..Self::default()
        };
        for (full, local) in uses.0 {
            let full: Vec<String> = full.iter().map(|s| unraw(s)).collect();
            match local {
                Some(local) => aliases.named.entry(unraw(&local)).or_default().push(full),
                None => aliases.globs.push(full),
            }
        }
        aliases
    }

    /// Every reading of `segments`: as written, for a single bare name as a
    /// member of each glob, and through each binding of a reading's first
    /// segment, repeated, so a rename of a rename (`use S::Admin as E;` after
    /// `use CallerStanding as S;`) reaches the full path, but never through
    /// the same name twice on one chain. Capped as a backstop; a file that
    /// reaches the cap fails named.
    fn readings(&self, segments: &[String]) -> Vec<Vec<String>> {
        const CAP: usize = 64;
        // Each reading with the names already expanded to reach it: a name is
        // never expanded twice on one chain, so `use guard::guard;` gives
        // `guard::guard` once, and a cycle of renames ends.
        let mut out: Vec<(Vec<String>, std::collections::BTreeSet<String>)> =
            vec![(segments.to_vec(), std::collections::BTreeSet::new())];
        if let [only] = segments {
            for glob in &self.globs {
                let reading = glob.iter().chain(std::iter::once(only)).cloned().collect();
                out.push((reading, std::collections::BTreeSet::new()));
            }
        }
        let mut next = 0;
        while next < out.len() {
            if out.len() >= CAP {
                self.capped.set(true);
                break;
            }
            let (current, used) = out[next].clone();
            next += 1;
            let Some((first, rest)) = current.split_first() else {
                continue;
            };
            if used.contains(first) {
                // Expanding a name twice on one chain is skipped silently only
                // for a plain self-import (`use guard::guard;`, every binding
                // starting with the name itself). Anything else (a cycle of
                // renames, one name bound in two scopes) might hide a reader,
                // so the file fails named.
                let self_import = self
                    .named
                    .get(first)
                    .is_some_and(|fulls| fulls.iter().all(|full| full.first() == Some(first)));
                if !self_import {
                    self.capped.set(true);
                }
                continue;
            }
            for full in self.named.get(first).into_iter().flatten() {
                let reading: Vec<String> = full.iter().chain(rest).cloned().collect();
                let mut used = used.clone();
                used.insert(first.clone());
                // The same reading reached by another chain is kept: that chain
                // may still expand a name this one has used.
                if !out.iter().any(|(r, u)| *r == reading && *u == used) {
                    out.push((reading, used));
                }
            }
        }
        let mut readings: Vec<Vec<String>> = Vec::new();
        for (reading, _) in out {
            if !readings.contains(&reading) {
                readings.push(reading);
            }
        }
        readings
    }
}

/// The keys a path reads through any of `readings`: a `Path` shape it ends
/// with, and a callable it names, called or taken as a value
/// (`let f = CallerStanding::of_client;`, `AdminStanding::is_gateway(s)`).
/// `paths_only` drops the callables, for a local name that is not called.
fn path_keys(readings: &[Vec<String>], paths_only: bool) -> Vec<&'static str> {
    SHAPES
        .iter()
        .filter(|(_, shape)| !paths_only || matches!(shape, Shape::Path(_)))
        .filter(|(_, shape)| match shape {
            Shape::Path(tail) | Shape::Call(tail) => readings.iter().any(|r| ends_with(r, tail)),
            Shape::QualifiedCall(last) | Shape::NullaryMethod(last) => readings
                .iter()
                .any(|r| r.len() >= 2 && r.last().is_some_and(|l| l == last)),
        })
        .map(|(key, _)| *key)
        .collect()
}

fn ends_with(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len()
        && path[path.len() - tail.len()..]
            .iter()
            .zip(tail)
            .all(|(a, b)| a == b)
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| plain(&s.ident)).collect()
}

/// Counts per inventory key in one file. `in_macro` marks syntax recovered
/// from a macro or attribute body, where a base-less struct expression may be
/// a pattern written in expression position and so counts as one.
struct Finder<'a> {
    aliases: &'a Aliases,
    counts: std::collections::BTreeMap<&'static str, usize>,
    in_macro: bool,
}

impl Finder<'_> {
    fn add(&mut self, key: &'static str) {
        *self.counts.entry(key).or_default() += 1;
    }

    /// One occurrence of a path: each key it reads through any of its
    /// readings ([`path_keys`]) counts once. A bare name that no import binds
    /// and the file defines no function by is a local (a `bool` named
    /// `is_admin`) unless it is called, so it counts for a callable only as a
    /// callee.
    fn path_occurrence(&mut self, segments: &[String], called: bool) {
        let readings = self.aliases.readings(segments);
        let local =
            segments.len() == 1 && readings.len() == 1 && !self.aliases.fns.contains(&segments[0]);
        for key in path_keys(&readings, local && !called) {
            self.add(key);
        }
    }

    /// One method call: by its name alone, as a method has no path to resolve.
    fn method_occurrence(&mut self, method: &str, nullary: bool) {
        for (key, shape) in SHAPES {
            let hit = match shape {
                Shape::Call(tail) | Shape::Path(tail) => tail.len() == 1 && tail[0] == method,
                Shape::NullaryMethod(name) => nullary && *name == method,
                Shape::QualifiedCall(_) => false,
            };
            if hit {
                self.add(key);
            }
        }
    }

    fn binds_admin<'f>(mut members: impl Iterator<Item = &'f syn::Member>) -> bool {
        members.any(|m| matches!(m, syn::Member::Named(ident) if plain(ident) == "admin"))
    }
}

impl<'ast> syn::visit::Visit<'ast> for Finder<'_> {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if matches!(&field.member, syn::Member::Named(ident) if plain(ident) == "admin") {
            self.add(".admin");
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_pat_struct(&mut self, pat: &'ast syn::PatStruct) {
        if Self::binds_admin(pat.fields.iter().map(|f| &f.member)) {
            self.add(DESTRUCTURED);
        }
        syn::visit::visit_pat_struct(self, pat);
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        // A struct literal is a write, except inside a macro body, where a
        // base-less one may be a pattern: counted, failing closed.
        if self.in_macro
            && expr.rest.is_none()
            && Self::binds_admin(expr.fields.iter().map(|f| &f.member))
        {
            self.add(DESTRUCTURED);
        }
        syn::visit::visit_expr_struct(self, expr);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.path_occurrence(&segments(path), false);
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // The callee is visited here, as called, and not again as a path.
        if let syn::Expr::Path(func) = &*call.func
            && func.qself.is_none()
        {
            for attr in call.attrs.iter().chain(&func.attrs) {
                self.visit_attribute(attr);
            }
            self.path_occurrence(&segments(&func.path), true);
            for segment in &func.path.segments {
                self.visit_path_arguments(&segment.arguments);
            }
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.method_occurrence(&plain(&call.method), call.args.is_empty());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        // A bare name in a pattern may be a variant brought in by `use`.
        if pat.subpat.is_none() && pat.by_ref.is_none() && pat.mutability.is_none() {
            let name = vec![plain(&pat.ident)];
            if self.aliases.readings(&name).len() > 1 {
                self.path_occurrence(&name, false);
            }
        }
        syn::visit::visit_pat_ident(self, pat);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.visit_path(&mac.path);
        if let Some((expr, pat, guard)) = crate::gateway::syn_scan_support::matches_parts(mac) {
            let was = std::mem::replace(&mut self.in_macro, true);
            self.visit_expr(&expr);
            self.visit_pat(&pat);
            if let Some(guard) = &guard {
                self.visit_expr(guard);
            }
            self.in_macro = was;
        } else {
            macro_body(self, Body::Mac(mac));
        }
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        match &attr.meta {
            syn::Meta::List(list) => macro_body(self, Body::List(list)),
            syn::Meta::NameValue(pair) => {
                let was = std::mem::replace(&mut self.in_macro, true);
                self.visit_expr(&pair.value);
                self.in_macro = was;
            }
            syn::Meta::Path(_) => {}
        }
    }
}

/// A macro's or an attribute's body, parsed in place, so no token-stream type
/// is named and no dependency is added.
#[derive(Clone, Copy)]
enum Body<'a> {
    Mac(&'a syn::Macro),
    List(&'a syn::MetaList),
}

impl Body<'_> {
    fn parse<T>(self, parser: impl syn::parse::Parser<Output = T>) -> syn::Result<T> {
        match self {
            Self::Mac(mac) => mac.parse_body_with(parser),
            Self::List(list) => list.parse_args_with(parser),
        }
    }
}

/// Visit whatever syntax a macro or attribute body holds, as a macro body:
/// comma-separated expressions, else comma-separated patterns, else, as a last
/// resort, a walk of its tokens.
fn macro_body(finder: &mut Finder<'_>, body: Body<'_>) {
    use syn::visit::Visit;
    let was = std::mem::replace(&mut finder.in_macro, true);
    let exprs =
        body.parse(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated);
    if let Ok(exprs) = exprs {
        for expr in &exprs {
            finder.visit_expr(expr);
        }
    } else if let Ok(pats) = body.parse(|input: syn::parse::ParseStream| {
        syn::punctuated::Punctuated::<syn::Pat, syn::Token![,]>::parse_terminated_with(
            input,
            syn::Pat::parse_multi_with_leading_vert,
        )
    }) {
        for pat in &pats {
            finder.visit_pat(pat);
        }
    } else {
        token_walk(finder, body);
    }
    finder.in_macro = was;
}

/// A token, reduced to what the walk needs, read with syn's parse API.
enum Tok {
    Ident(String),
    Punct(char),
    /// A delimited group: `true` for braces.
    Group(bool, Vec<Tok>),
    Other,
}

fn toks(input: syn::parse::ParseStream) -> syn::Result<Vec<Tok>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if input.peek(syn::token::Brace) {
            let inner;
            syn::braced!(inner in input);
            out.push(Tok::Group(true, toks(&inner)?));
        } else if input.peek(syn::token::Paren) {
            let inner;
            syn::parenthesized!(inner in input);
            out.push(Tok::Group(false, toks(&inner)?));
        } else if input.peek(syn::token::Bracket) {
            let inner;
            syn::bracketed!(inner in input);
            out.push(Tok::Group(false, toks(&inner)?));
        } else {
            out.push(input.step(|cursor| {
                if let Some((ident, rest)) = cursor.ident() {
                    return Ok((Tok::Ident(plain(&ident)), rest));
                }
                if let Some((punct, rest)) = cursor.punct() {
                    return Ok((Tok::Punct(punct.as_char()), rest));
                }
                match cursor.token_tree() {
                    Some((_, rest)) => Ok((Tok::Other, rest)),
                    None => Err(cursor.error("no token")),
                }
            })?);
        }
    }
    Ok(out)
}

/// The last resort, for a body no parser takes: `.admin`, a brace group with
/// an `admin` field (before `,`, before a single `:`, or last), and the
/// monitored names, a multi-segment one only after its own `Segment ::`. Every
/// identifier is compared after unrawing.
fn token_walk(finder: &mut Finder<'_>, body: Body<'_>) {
    if let Ok(trees) = body.parse(toks) {
        walk(finder, &trees);
    }
}

fn walk(finder: &mut Finder<'_>, trees: &[Tok]) {
    fn ident(t: Option<&Tok>) -> Option<&str> {
        match t {
            Some(Tok::Ident(i)) => Some(i.as_str()),
            _ => None,
        }
    }
    let punct = |t: Option<&Tok>, c: char| matches!(t, Some(Tok::Punct(p)) if *p == c);
    let at = |i: usize, back: usize| i.checked_sub(back).and_then(|k| trees.get(k));
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            Tok::Group(brace, inner) => {
                if *brace {
                    let binds = inner.iter().enumerate().any(|(j, t)| {
                        matches!(t, Tok::Ident(n) if n == "admin")
                            && !punct(j.checked_sub(1).and_then(|k| inner.get(k)), '.')
                            && (j + 1 == inner.len()
                                || punct(inner.get(j + 1), ',')
                                || (punct(inner.get(j + 1), ':') && !punct(inner.get(j + 2), ':')))
                    });
                    if binds {
                        finder.add(DESTRUCTURED);
                    }
                }
                walk(finder, inner);
            }
            Tok::Ident(name) => {
                let after_dot = punct(at(i, 1), '.');
                let called = matches!(trees.get(i + 1), Some(Tok::Group(false, _)));
                let empty_call =
                    matches!(trees.get(i + 1), Some(Tok::Group(false, g)) if g.is_empty());
                let qualified = punct(at(i, 1), ':') && punct(at(i, 2), ':');
                // `A :: B`: the segment before this one, if any.
                let before = if qualified { ident(at(i, 3)) } else { None };
                let tail_matches = |tail: &[&str]| match tail {
                    [last] => *last == name.as_str(),
                    [.., prev, last] => *last == name.as_str() && before == Some(*prev),
                    [] => false,
                };
                if after_dot && name == "admin" && !called {
                    finder.add(".admin");
                }
                // A callable counts called or taken as a value, as in parsed
                // syntax ([`path_keys`]): a bare name not called is a local
                // unless the file defines a function by it.
                let callable = called || qualified || finder.aliases.fns.contains(name);
                let mut keys: Vec<&'static str> = Vec::new();
                for (key, shape) in SHAPES {
                    let hit = match shape {
                        Shape::Path(tail) => tail_matches(tail),
                        Shape::Call(tail) => callable && tail_matches(tail),
                        Shape::QualifiedCall(last) => qualified && *last == name.as_str(),
                        Shape::NullaryMethod(m) => {
                            ((after_dot && empty_call) || qualified) && *m == name.as_str()
                        }
                    };
                    if hit {
                        keys.push(key);
                    }
                }
                // Also what it names through the file's imports, with the
                // segment before it; each key once per occurrence.
                if !after_dot {
                    let path: Vec<String> = before
                        .map(str::to_owned)
                        .into_iter()
                        .chain(std::iter::once(name.clone()))
                        .collect();
                    let readings = finder.aliases.readings(&path);
                    if readings.len() > 1 {
                        keys.extend(path_keys(&readings, false));
                    }
                }
                keys.sort_unstable();
                keys.dedup();
                for key in keys {
                    finder.add(key);
                }
            }
            Tok::Punct(_) | Tok::Other => {}
        }
    }
}

/// The key a file that does not parse is found under: no reader can be
/// vouched for in it, so it fails the scan, named.
const UNPARSED: &str = "<does not parse>";
/// The key a file is found under when one local name is bound to two
/// different paths and one of them is monitored.
const CONFLICT: &str = "<conflicting import>";
/// The key a file is found under when its imports are too many to resolve
/// within the cap: a reader could hide behind them, so it fails named.
const CAPPED: &str = "<import expansion capped>";

/// Whether any binding of one local name to two different paths reaches a
/// monitored name: an unrelated pair (a `cfg(unix)` and `cfg(windows)` import
/// of one trait) is not.
fn conflicting(aliases: &Aliases) -> bool {
    aliases.named.values().any(|fulls| {
        let mut distinct = fulls.clone();
        distinct.sort();
        distinct.dedup();
        distinct.len() > 1
            && distinct.iter().any(|full| {
                SHAPES.iter().any(|(_, shape)| match shape {
                    Shape::Path(tail) | Shape::Call(tail) => ends_with(full, tail),
                    Shape::QualifiedCall(last) | Shape::NullaryMethod(last) => {
                        full.last().is_some_and(|l| l == last)
                    }
                })
            })
    })
}

fn found_in(
    files: &[(String, String)],
) -> std::collections::BTreeMap<(&'static str, String), usize> {
    let mut found = std::collections::BTreeMap::new();
    for (name, text) in files {
        let Ok(file) = syn::parse_file(text) else {
            found.insert((UNPARSED, name.clone()), 1);
            continue;
        };
        let aliases = Aliases::of(&file);
        if conflicting(&aliases) {
            found.insert((CONFLICT, name.clone()), 1);
        }
        let mut finder = Finder {
            aliases: &aliases,
            counts: std::collections::BTreeMap::new(),
            in_macro: false,
        };
        syn::visit::Visit::visit_file(&mut finder, &file);
        for (key, n) in finder.counts {
            found.insert((key, name.clone()), n);
        }
        if aliases.capped.get() {
            found.insert((CAPPED, name.clone()), 1);
        }
    }
    found
}

/// The inventory of every production reader and the test that holds the crate
/// to it.
#[path = "admin_standing_scan_inventory_tests.rs"]
mod inventory;

/// The finder's own rows: each reader form it must find, and each it must not.
#[path = "admin_standing_scan_finder_tests.rs"]
mod finder_rows;
