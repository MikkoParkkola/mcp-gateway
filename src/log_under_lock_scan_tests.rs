// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOG.2: no tracing line is written while a lock guard is held. A blocked
//! log write under a guard would stall every other user of that lock.
//!
//! Guards are found by how they are taken, not by name: few bindings are
//! called `guard`. A binding is held from a `let` (or `if let`, `while let`,
//! `let ... else`) of an acquisition until the end of its block or a `drop`;
//! a guard-typed parameter is held for the whole body. An acquisition is a
//! zero-argument `lock`/`read`/`write` call (and their `try_`, `blocking_`
//! and `_owned` forms), a call to a function returning a guard type, or a
//! `DashMap` entry reference, seen through `?`, `.await`, `unwrap`, `expect`,
//! `ok`, `map_err`, `unwrap_or_else`, `timeout`/`timeout_at`, a block's
//! result, a `match` or `if` whose arm yields one, `Some(..)` and moves.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// Macros that write a tracing line.
const LOG_MACROS: &[&str] = &["trace", "debug", "info", "warn", "error", "event"];

/// Zero-argument calls that take a lock guard.
const ACQUIRE: &[&str] = &[
    "lock",
    "read",
    "write",
    "try_lock",
    "try_read",
    "try_write",
    "blocking_lock",
    "blocking_read",
    "blocking_write",
    "lock_owned",
    "read_owned",
    "write_owned",
    "try_lock_owned",
    "try_read_owned",
    "try_write_owned",
];

/// Wrappers an acquisition is seen through.
const PEEL: &[&str] = &["unwrap", "expect", "ok", "map_err", "unwrap_or_else"];

/// `DashMap` calls that return a reference holding a shard lock.
const DASHMAP_REFS: &[&str] = &["get", "get_mut", "entry", "iter", "iter_mut"];

/// Guard types from std, `parking_lot` and tokio.
const GUARD_TYPES: &[&str] = &[
    "MutexGuard",
    "RwLockReadGuard",
    "RwLockWriteGuard",
    "OwnedMutexGuard",
    "OwnedRwLockReadGuard",
    "OwnedRwLockWriteGuard",
    "MappedMutexGuard",
    "MappedRwLockReadGuard",
    "MappedRwLockWriteGuard",
    "ArcMutexGuard",
    "ArcRwLockReadGuard",
    "ArcRwLockWriteGuard",
];

/// What the scan knows across files: guard types the crate defines and the
/// functions that return a guard.
#[derive(Default)]
struct Known {
    guard_types: HashSet<String>,
    helpers: HashSet<String>,
}

/// One log macro written while a guard was held: file, function, macro.
pub(crate) type Hit = (String, String, String);

/// Every path segment named in a type: `Option<MutexGuard<'_, T>>` gives
/// `Option`, `MutexGuard` and `T`.
fn type_names(ty: &syn::Type) -> Vec<String> {
    #[derive(Default)]
    struct Names(Vec<String>);
    impl<'ast> Visit<'ast> for Names {
        fn visit_path_segment(&mut self, seg: &'ast syn::PathSegment) {
            self.0.push(seg.ident.to_string());
            syn::visit::visit_path_segment(self, seg);
        }
    }
    let mut names = Names::default();
    names.visit_type(ty);
    names.0
}

fn mentions_guard(ty: &syn::Type, known: &Known) -> bool {
    // DashMap's `Ref`/`RefMut` are named by path here (`dashmap::mapref::..`),
    // which tells them from `std::cell::Ref`.
    let names = type_names(ty);
    names.iter().any(|w| w == "mapref")
        || names
            .iter()
            .any(|w| GUARD_TYPES.contains(&w.as_str()) || known.guard_types.contains(w))
}

/// First pass: crate-defined guard aliases and newtypes, then helpers.
fn learn(files: &[syn::File]) -> Known {
    let mut known = Known::default();
    for _ in 0..2 {
        for file in files {
            for item in all_items(&file.items) {
                match item {
                    syn::Item::Type(t) if mentions_guard(&t.ty, &known) => {
                        known.guard_types.insert(t.ident.to_string());
                    }
                    syn::Item::Struct(s)
                        if s.ident.to_string().ends_with("Guard")
                            && s.fields.iter().any(|f| mentions_guard(&f.ty, &known)) =>
                    {
                        known.guard_types.insert(s.ident.to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    for file in files {
        for sig in signatures(&file.items) {
            if let syn::ReturnType::Type(_, ty) = &sig.output
                && mentions_guard(ty, &known)
            {
                known.helpers.insert(sig.ident.to_string());
            }
        }
    }
    known
}

fn all_items(items: &[syn::Item]) -> Vec<&syn::Item> {
    let mut out = Vec::new();
    for item in items {
        out.push(item);
        if let syn::Item::Mod(m) = item
            && let Some((_, inner)) = &m.content
        {
            out.extend(all_items(inner));
        }
    }
    out
}

fn signatures(items: &[syn::Item]) -> Vec<&syn::Signature> {
    let mut out = Vec::new();
    for item in all_items(items) {
        match item {
            syn::Item::Fn(f) => out.push(&f.sig),
            syn::Item::Impl(i) => out.extend(i.items.iter().filter_map(|ii| match ii {
                syn::ImplItem::Fn(f) => Some(&f.sig),
                _ => None,
            })),
            syn::Item::Trait(t) => out.extend(t.items.iter().filter_map(|ti| match ti {
                syn::TraitItem::Fn(f) => Some(&f.sig),
                _ => None,
            })),
            _ => {}
        }
    }
    out
}

/// Fields and bindings in a file whose type names `DashMap`.
fn dashmaps(file: &syn::File) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in all_items(&file.items) {
        if let syn::Item::Struct(s) = item {
            for f in &s.fields {
                if type_names(&f.ty).iter().any(|n| n == "DashMap")
                    && let Some(id) = &f.ident
                {
                    names.insert(id.to_string());
                }
            }
        }
    }
    names
}

fn last_segment(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

/// The name a receiver ends in: `self.cache` and `cache` are both `cache`.
fn receiver_name(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Field(f) => match &f.member {
            syn::Member::Named(id) => Some(id.to_string()),
            syn::Member::Unnamed(_) => None,
        },
        syn::Expr::Path(p) => Some(last_segment(&p.path)),
        syn::Expr::Paren(p) => receiver_name(&p.expr),
        syn::Expr::Reference(r) => receiver_name(&r.expr),
        _ => None,
    }
}

/// One file's scan state.
struct Scan<'k> {
    known: &'k Known,
    /// `DashMap` fields of every scanned file: a field is often declared in
    /// another file than the one that locks it.
    dashmaps: &'k HashSet<String>,
    file: String,
    func: String,
    hits: Vec<Hit>,
}

impl Scan<'_> {
    /// `for e in &self.map` over a `DashMap`: each item holds a shard lock.
    /// Only in a loop: a `let m = &self.map;` holds nothing.
    fn iterates_dashmap(&self, expr: &syn::Expr) -> bool {
        matches!(expr, syn::Expr::Reference(_))
            && receiver_name(expr).is_some_and(|n| self.dashmaps.contains(&n))
    }

    /// Whether `expr` yields a guard, given the bindings already `held`.
    fn acquires(&self, expr: &syn::Expr, held: &[String]) -> bool {
        match expr {
            syn::Expr::Try(e) => self.acquires(&e.expr, held),
            syn::Expr::Await(e) => self.acquires(&e.base, held),
            syn::Expr::Paren(e) => self.acquires(&e.expr, held),
            syn::Expr::MethodCall(m) => {
                let name = m.method.to_string();
                (m.args.is_empty() && ACQUIRE.contains(&name.as_str()))
                    || self.known.helpers.contains(&name)
                    || (DASHMAP_REFS.contains(&name.as_str())
                        && receiver_name(&m.receiver).is_some_and(|r| self.dashmaps.contains(&r)))
                    || (PEEL.contains(&name.as_str()) && self.acquires(&m.receiver, held))
            }
            syn::Expr::Call(c) => {
                let syn::Expr::Path(f) = &*c.func else {
                    return false;
                };
                let name = last_segment(&f.path);
                match name.as_str() {
                    // timeout(d, acquire) and timeout_at(t, acquire): the acquisition is last.
                    "timeout" | "timeout_at" => {
                        c.args.last().is_some_and(|a| self.acquires(a, held))
                    }
                    "Some" | "Ok" => c.args.first().is_some_and(|a| self.acquires(a, held)),
                    _ => self.known.helpers.contains(&name),
                }
            }
            // A move of a held binding hands the guard on.
            syn::Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|i| held.contains(&i.to_string())),
            syn::Expr::Block(b) => self.block_yields(&b.block, held),
            syn::Expr::Match(m) => {
                let scrutinee = self.acquires(&m.expr, held);
                m.arms.iter().any(|a| {
                    let mut inner = held.to_vec();
                    if scrutinee && !is_err_arm(&a.pat) {
                        inner.extend(bound_names(&a.pat));
                    }
                    self.acquires(&a.body, &inner)
                })
            }
            syn::Expr::If(i) => {
                self.block_yields(&i.then_branch, held)
                    || i.else_branch
                        .as_ref()
                        .is_some_and(|(_, e)| self.acquires(e, held))
            }
            _ => false,
        }
    }

    /// Whether a block's result is a guard, counting guards its own `let`s take.
    fn block_yields(&self, block: &syn::Block, held: &[String]) -> bool {
        let mut inner = held.to_vec();
        for stmt in &block.stmts {
            if let syn::Stmt::Local(l) = stmt
                && l.init
                    .as_ref()
                    .is_some_and(|i| self.acquires(&i.expr, &inner))
            {
                inner.extend(bound_names(&l.pat));
            }
        }
        matches!(block.stmts.last(), Some(syn::Stmt::Expr(e, None)) if self.acquires(e, &inner))
    }
}

/// The names a pattern binds.
fn bound_names(pat: &syn::Pat) -> Vec<String> {
    #[derive(Default)]
    struct Names(Vec<String>);
    impl<'ast> Visit<'ast> for Names {
        fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
            self.0.push(p.ident.to_string());
            syn::visit::visit_pat_ident(self, p);
        }
    }
    let mut names = Names::default();
    names.visit_pat(pat);
    names.0
}

/// A macro body's tokens with an acquisition call before a tracing macro:
/// `m . lock ()` (or another `ACQUIRE` call) and later `warn !`.
/// Whether a macro body's tokens hold a log macro.
fn logs(tokens: &str) -> bool {
    LOG_MACROS
        .iter()
        .any(|m| tokens.contains(&format!("{m} !")))
}

fn locks_then_logs(tokens: &str) -> bool {
    let first_lock = ACQUIRE
        .iter()
        .filter_map(|a| tokens.find(&format!(". {a} ()")))
        .min();
    first_lock.is_some_and(|at| {
        LOG_MACROS
            .iter()
            .any(|m| tokens[at..].contains(&format!("{m} !")))
    })
}

/// An `Err(..)` arm: a refused `try_lock` holds no guard there.
fn is_err_arm(pat: &syn::Pat) -> bool {
    matches!(pat, syn::Pat::TupleStruct(t) if last_segment(&t.path) == "Err")
}

/// The name passed to `drop(x)` or `std::mem::drop(x)`.
fn dropped(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Call(c) = expr else {
        return None;
    };
    let syn::Expr::Path(f) = &*c.func else {
        return None;
    };
    if last_segment(&f.path) != "drop" || c.args.len() != 1 {
        return None;
    }
    let syn::Expr::Path(arg) = c.args.first()? else {
        return None;
    };
    arg.path.get_ident().map(ToString::to_string)
}

/// A log macro's message: its first string literal that is not a field's
/// value (`name = "x"`) or a `target:`/`parent:` argument. A record with no
/// message is named by its field names instead, so an allowlist entry names
/// the line, not just its function.
fn message(mac: &syn::Macro) -> String {
    use syn::ext::IdentExt;
    // `parse2` refuses input left unread, so the walk goes to the end even
    // after the message is found.
    let parser = |input: syn::parse::ParseStream<'_>| {
        let mut message = None;
        let mut fields = Vec::new();
        let mut is_value = false;
        while !input.is_empty() {
            if message.is_none() && !is_value && input.peek(syn::LitStr) {
                message = Some(input.parse::<syn::LitStr>()?.value());
                continue;
            }
            if !is_value && input.peek(syn::Ident::peek_any) {
                let name = input.call(syn::Ident::parse_any)?;
                if input.peek(syn::Token![=]) {
                    fields.push(name.to_string());
                }
                continue;
            }
            is_value = input.peek(syn::Token![=]) || input.peek(syn::Token![:]);
            input.step(|c| {
                c.token_tree()
                    .map(|(_, rest)| ((), rest))
                    .ok_or_else(|| c.error("end of the macro"))
            })?;
        }
        Ok(message.unwrap_or_else(|| format!("fields {}", fields.join(" "))))
    };
    syn::parse::Parser::parse2(parser, mac.tokens.clone()).unwrap_or_default()
}

impl Scan<'_> {
    fn hit(&mut self, what: &str) {
        self.hits
            .push((self.file.clone(), self.func.clone(), what.to_owned()));
    }

    /// Walk `block` with `held` guards in force from outside it.
    fn block(&mut self, block: &syn::Block, mut held: Vec<String>) {
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        self.expr(&init.expr, &held);
                        if let Some((_, diverge)) = &init.diverge {
                            self.expr(diverge, &held);
                        }
                        if self.acquires(&init.expr, &held) {
                            held.extend(bound_names(&local.pat));
                            // `let b = a;` moves the guard: `a` holds it no more.
                            if let syn::Expr::Path(moved) = &*init.expr
                                && let Some(id) = moved.path.get_ident()
                            {
                                let id = id.to_string();
                                held.retain(|h| *h != id);
                            }
                        }
                    }
                }
                syn::Stmt::Expr(e, _) => {
                    if let Some(name) = dropped(e) {
                        held.retain(|h| *h != name);
                    } else {
                        self.expr(e, &held);
                    }
                }
                syn::Stmt::Macro(m) => self.mac(&m.mac, &held),
                syn::Stmt::Item(item) => self.item(item),
            }
        }
    }

    fn mac(&mut self, mac: &syn::Macro, held: &[String]) {
        let name = last_segment(&mac.path);
        if LOG_MACROS.contains(&name.as_str()) {
            if !held.is_empty() {
                self.hit(&format!("{name}!: {}", message(mac)));
            }
        } else {
            // Inside a macro body (a `select!` arm, say) syn sees only tokens.
            let tokens = mac.tokens.to_string();
            if locks_then_logs(&tokens) {
                self.hit(&format!("{name}! body: lock, then log"));
            } else if !held.is_empty() && logs(&tokens) {
                self.hit(&format!("{name}! body: log under a held guard"));
            }
        }
    }

    /// Walk an expression: macros in it, and the blocks nested in it.
    fn expr(&mut self, expr: &syn::Expr, held: &[String]) {
        match expr {
            syn::Expr::Macro(m) => self.mac(&m.mac, held),
            syn::Expr::Block(b) => self.block(&b.block, held.to_vec()),
            syn::Expr::Async(b) => self.block(&b.block, held.to_vec()),
            syn::Expr::Unsafe(b) => self.block(&b.block, held.to_vec()),
            syn::Expr::Loop(l) => self.block(&l.body, held.to_vec()),
            syn::Expr::ForLoop(l) => {
                self.expr(&l.expr, held);
                let mut inner = held.to_vec();
                if self.acquires(&l.expr, held) || self.iterates_dashmap(&l.expr) {
                    inner.extend(bound_names(&l.pat));
                }
                self.block(&l.body, inner);
            }
            syn::Expr::While(w) => {
                let mut inner = held.to_vec();
                if let syn::Expr::Let(l) = &*w.cond {
                    self.expr(&l.expr, held);
                    if self.acquires(&l.expr, held) {
                        inner.extend(bound_names(&l.pat));
                    }
                } else {
                    self.expr(&w.cond, held);
                }
                self.block(&w.body, inner);
            }
            syn::Expr::If(i) => {
                let mut inner = held.to_vec();
                self.cond(&i.cond, held, &mut inner);
                self.block(&i.then_branch, inner);
                if let Some((_, e)) = &i.else_branch {
                    self.expr(e, held);
                }
            }
            syn::Expr::Match(m) => {
                self.expr(&m.expr, held);
                let scrutinee_holds = self.acquires(&m.expr, held);
                for arm in &m.arms {
                    let mut inner = held.to_vec();
                    if scrutinee_holds && !is_err_arm(&arm.pat) {
                        inner.extend(bound_names(&arm.pat));
                        inner.push("<match scrutinee>".into());
                    }
                    self.expr(&arm.body, &inner);
                }
            }
            syn::Expr::Closure(c) => self.expr(&c.body, held),
            syn::Expr::MethodCall(m) => {
                if !held.is_empty() && m.method == "emit" && m.args.is_empty() {
                    self.hit("PendingLogs::emit");
                }
                self.callback_rule(m);
                self.expr(&m.receiver, held);
                for a in &m.args {
                    self.expr(a, held);
                }
            }
            syn::Expr::Call(c) => {
                self.expr(&c.func, held);
                for a in &c.args {
                    self.expr(a, held);
                }
            }
            syn::Expr::Try(e) => self.expr(&e.expr, held),
            syn::Expr::Await(e) => self.expr(&e.base, held),
            syn::Expr::Paren(e) => self.expr(&e.expr, held),
            syn::Expr::Return(r) => {
                if let Some(e) = &r.expr {
                    self.expr(e, held);
                }
            }
            syn::Expr::Assign(a) => self.expr(&a.right, held),
            syn::Expr::Let(l) => self.expr(&l.expr, held),
            syn::Expr::Binary(b) => {
                self.expr(&b.left, held);
                self.expr(&b.right, held);
            }
            syn::Expr::Unary(u) => self.expr(&u.expr, held),
            syn::Expr::Reference(r) => self.expr(&r.expr, held),
            syn::Expr::Tuple(t) => t.elems.iter().for_each(|e| self.expr(e, held)),
            syn::Expr::Array(a) => a.elems.iter().for_each(|e| self.expr(e, held)),
            syn::Expr::Struct(s) => s.fields.iter().for_each(|f| self.expr(&f.expr, held)),
            _ => {}
        }
    }

    /// An `if` condition: `if let p = acquire` holds `p` in the then-branch,
    /// and so does each `let` in a let-chain.
    fn cond(&mut self, cond: &syn::Expr, held: &[String], inner: &mut Vec<String>) {
        match cond {
            syn::Expr::Let(l) => {
                self.expr(&l.expr, held);
                if self.acquires(&l.expr, held) {
                    inner.extend(bound_names(&l.pat));
                }
            }
            syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::And(_)) => {
                self.cond(&b.left, held, inner);
                let now = inner.clone();
                self.cond(&b.right, &now, inner);
            }
            other => self.expr(other, held),
        }
    }
}

/// Callbacks a callee runs under its own lock: no log line may be written in
/// a closure passed to them. (receiver name, method)
const CALLBACK_UNDER_LOCK: &[(&str, &str)] = &[("tools_cache", "replace")];

impl Scan<'_> {
    fn callback_rule(&mut self, m: &syn::ExprMethodCall) {
        let Some(recv) = receiver_name(&m.receiver) else {
            return;
        };
        if !CALLBACK_UNDER_LOCK.contains(&(recv.as_str(), m.method.to_string().as_str())) {
            return;
        }
        for arg in &m.args {
            if let syn::Expr::Closure(c) = arg {
                let lock = vec![format!("<{recv}.{} callback>", m.method)];
                self.expr(&c.body, &lock);
            }
        }
    }

    fn item(&mut self, item: &syn::Item) {
        if has_cfg_test(attrs_of(item)) {
            return;
        }
        match item {
            syn::Item::Fn(f) => self.func(&f.sig, &f.block),
            syn::Item::Impl(i) => {
                for ii in &i.items {
                    if let syn::ImplItem::Fn(f) = ii
                        && !has_cfg_test(&f.attrs)
                    {
                        self.func(&f.sig, &f.block);
                    }
                }
            }
            syn::Item::Trait(t) => {
                for ti in &t.items {
                    if let syn::TraitItem::Fn(f) = ti
                        && let Some(body) = &f.default
                    {
                        self.func(&f.sig, body);
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    for i in items {
                        self.item(i);
                    }
                }
            }
            _ => {}
        }
    }

    /// A function body, with each guard-typed parameter held throughout.
    fn func(&mut self, sig: &syn::Signature, body: &syn::Block) {
        let outer = std::mem::replace(&mut self.func, sig.ident.to_string());
        let mut held = Vec::new();
        for input in &sig.inputs {
            if let syn::FnArg::Typed(t) = input
                && mentions_guard(&t.ty, self.known)
            {
                held.extend(bound_names(&t.pat));
            }
        }
        self.block(body, held);
        self.func = outer;
    }
}

fn attrs_of(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        _ => &[],
    }
}

/// `#[cfg(test)]` or `#[cfg(all(test, ...))]`.
fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    fn test_only(meta: &syn::Meta) -> bool {
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|all| all.iter().any(test_only)),
            _ => false,
        }
    }
    attrs.iter().any(|a| {
        a.path().is_ident("cfg") && a.parse_args::<syn::Meta>().is_ok_and(|m| test_only(&m))
    })
}

/// Scan parsed files: every log macro written under a held guard.
fn scan(files: &[(String, syn::File)]) -> Vec<Hit> {
    let parsed: Vec<syn::File> = files.iter().map(|(_, f)| f.clone()).collect();
    let known = learn(&parsed);
    let maps: HashSet<String> = parsed.iter().flat_map(dashmaps).collect();
    let mut hits = Vec::new();
    for (name, file) in files {
        let mut s = Scan {
            known: &known,
            dashmaps: &maps,
            file: name.clone(),
            func: String::new(),
            hits: Vec::new(),
        };
        file.items.iter().for_each(|i| s.item(i));
        hits.extend(s.hits);
    }
    hits
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Non-test source under src/, parsed, keyed by its path from the crate root.
fn production_files() -> Vec<(String, syn::File)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    rust_files(&root.join("src"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let test_only =
                rel.ends_with("_tests.rs") || rel.contains("_tests/") || rel.contains("/tests/");
            (!test_only).then_some(())?;
            let text = std::fs::read_to_string(&p).ok()?;
            Some((
                rel,
                syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
            ))
        })
        .collect()
}

#[path = "log_under_lock_scan_g0_tests.rs"]
mod g0;

#[path = "log_under_lock_allowed_tests.rs"]
mod allowed;

/// G1: no production function writes a tracing line while it holds a guard.
#[test]
fn g1_no_production_code_logs_while_holding_a_lock_guard() {
    let hits = scan(&production_files());
    let allowed: BTreeSet<(String, String, String)> = allowed::ALLOWED
        .iter()
        .map(|(f, func, m, _)| ((*f).to_owned(), (*func).to_owned(), (*m).to_owned()))
        .collect();
    let found: BTreeSet<Hit> = hits.into_iter().collect();
    let new: Vec<&Hit> = found.iter().filter(|h| !allowed.contains(*h)).collect();
    assert!(
        new.is_empty(),
        "{} log lines are written under a held guard (file, function, macro and message); log after the guard is released:\n{new:#?}",
        new.len()
    );
    let stale: Vec<_> = allowed.iter().filter(|a| !found.contains(*a)).collect();
    assert!(
        stale.is_empty(),
        "allowlist entries that no longer match a site: {stale:?}"
    );
}

/// G4: the callee-locked callback rule holds on its real target, the tools
/// cache's `replace` in `input_keys.rs`, which no lexical guard binding shows.
#[test]
fn g4_no_log_line_in_a_callback_the_callee_runs_under_its_lock() {
    let files = production_files();
    let input_keys = files
        .iter()
        .find(|(name, _)| name == "src/backend/input_keys.rs")
        .expect("src/backend/input_keys.rs");
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&input_keys.0))
        .expect("readable");
    assert!(
        text.contains("tools_cache.replace("),
        "the callback site moved: update CALLBACK_UNDER_LOCK"
    );
    let hits: Vec<Hit> = scan(&files)
        .into_iter()
        .filter(|(_, _, m)| !m.is_empty())
        .filter(|(f, _, _)| f == "src/backend/input_keys.rs")
        .collect();
    assert!(
        hits.is_empty(),
        "a log line inside the tools_cache.replace callback: {hits:?}"
    );
}
