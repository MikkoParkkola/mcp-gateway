// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660 (DUPC-3.PR3.6, PR3.6d): every production reqwest client outside
//! `src/oauth/` states its redirect policy, and only `security/ssrf/redirect.rs`
//! states a hop limit.
//!
//! Rule (i): `Client::new()`, `reqwest::get`, `Policy::default()`, or a builder
//! chain that reaches `.build()` without `.redirect(` on every path is reqwest's
//! implicit ten-hop default. A fn returning a `ClientBuilder` is a factory; a
//! call to one starts a chain, as does a `ClientBuilder` parameter. Rule (ii):
//! a hop count compared with an integer literal, or `Policy::limited`.
//! Rule (iii): a `Policy::custom` closure that never passes `previous()` into
//! `redirect_decision` / `hop_budget_spent`, or discards the answer instead of
//! branching on it. Production means reached from `lib.rs` / `main.rs`
//! through modules none of which is `#[cfg(test)]`, so a `#[path]` file
//! included under a test module is test code. A parser, not a text match:
//! comments never count.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    rule: &'static str,
    file: String,
    func: String,
}

const RULE_IMPLICIT: &str = "implicit-policy";
const RULE_HOP: &str = "hop-literal";
const RULE_DELEGATION: &str = "delegation";

const EXEMPT_REDIRECT_RS: &str = "src/security/ssrf/redirect.rs";
const OAUTH_PREFIX: &str = "src/oauth/";

fn contains_word(hay: &str, needle: &str) -> bool {
    hay.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == needle)
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("cfg")
            && let syn::Meta::List(list) = &attr.meta
        {
            let text = list.tokens.to_string();
            if contains_word(&text, "test") && !contains_word(&text, "not") {
                return true;
            }
        }
    }
    false
}

fn path_attr_value(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("path")
            && let syn::Meta::NameValue(pair) = &attr.meta
            && let syn::Expr::Lit(lit) = &pair.value
            && let syn::Lit::Str(s) = &lit.lit
        {
            return Some(s.value());
        }
    }
    None
}

fn module_dir_for_file(root: &Path, rel: &str) -> Option<PathBuf> {
    let abs = root.join(rel);
    let parent = abs.parent()?.to_path_buf();
    let name = abs.file_name()?.to_str()?;
    if name == "lib.rs" || name == "main.rs" || name == "mod.rs" {
        Some(parent)
    } else if let Some(stem) = name.strip_suffix(".rs") {
        Some(parent.join(stem))
    } else {
        Some(parent)
    }
}

fn rel_for_abs(root: &Path, abs: &Path) -> Option<String> {
    let rel = abs.strip_prefix(root).ok()?;
    let text = rel.to_str()?;
    Some(text.replace('\\', "/"))
}

fn resolve_child_mod(
    root: &Path,
    current_rel: &str,
    mod_name: &str,
    path_attr: Option<&str>,
) -> Option<String> {
    let current_abs = root.join(current_rel);
    let declaring = current_abs.parent()?.to_path_buf();
    if let Some(p) = path_attr {
        let child = declaring.join(p);
        if child.is_file() {
            return rel_for_abs(root, &child);
        }
        return None;
    }
    let dir = module_dir_for_file(root, current_rel)?;
    let first = dir.join(format!("{mod_name}.rs"));
    if first.is_file() {
        return rel_for_abs(root, &first);
    }
    let second = dir.join(mod_name).join("mod.rs");
    if second.is_file() {
        return rel_for_abs(root, &second);
    }
    None
}

fn collect_child_mods_from_items(
    items: &[syn::Item],
    test_only_ancestor: bool,
    current_rel: &str,
    root: &Path,
    out: &mut Vec<String>,
) {
    for item in items {
        if let syn::Item::Mod(m) = item {
            let test_only = test_only_ancestor || is_cfg_test(&m.attrs);
            if let Some((_, inner)) = &m.content {
                if !test_only {
                    collect_child_mods_from_items(inner, test_only, current_rel, root, out);
                }
            } else {
                if test_only {
                    continue;
                }
                let name = m.ident.to_string();
                let path_attr = path_attr_value(&m.attrs);
                if let Some(child) =
                    resolve_child_mod(root, current_rel, &name, path_attr.as_deref())
                    && !child.starts_with(OAUTH_PREFIX)
                {
                    out.push(child);
                }
            }
        }
    }
}

fn scan_crate(root: &Path) -> Vec<Entry> {
    let mut seen = HashSet::new();
    let mut queue = Vec::new();
    for start in ["src/lib.rs", "src/main.rs"] {
        if root.join(start).is_file() {
            queue.push(start.to_string());
        }
    }
    // The module walk is unchanged; parsing is split from checking so the
    // factory names are known crate-wide before any chain is judged.
    let mut parsed: Vec<(String, syn::File)> = Vec::new();
    while let Some(rel) = queue.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        if rel.starts_with(OAUTH_PREFIX) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(root.join(&rel)) else {
            continue;
        };
        let Ok(file) = syn::parse_file(&content) else {
            continue;
        };
        let test_only = is_cfg_test(&file.attrs);
        let mut kids = Vec::new();
        collect_child_mods_from_items(&file.items, test_only, &rel, root, &mut kids);
        for k in kids {
            if !seen.contains(&k) {
                queue.push(k);
            }
        }
        if !test_only {
            parsed.push((rel, file));
        }
    }
    let mut factories = HashSet::new();
    for (_, file) in &parsed {
        collect_factories_from_items(&file.items, false, &mut factories);
    }
    let mut entries = Vec::new();
    for (rel, file) in &parsed {
        let mut found = Vec::new();
        scan_items(rel, &file.items, false, &factories, &mut found);
        entries.extend(found);
    }
    entries.sort();
    entries.dedup();
    entries
}

fn scan_source(rel: &str, src: &str) -> Vec<Entry> {
    if rel.starts_with(OAUTH_PREFIX) {
        return Vec::new();
    }
    let Ok(file) = syn::parse_file(src) else {
        return Vec::new();
    };
    scan_file_ast(rel, &file)
}

fn scan_file_ast(rel: &str, file: &syn::File) -> Vec<Entry> {
    if rel.starts_with(OAUTH_PREFIX) {
        return Vec::new();
    }
    if is_cfg_test(&file.attrs) {
        return Vec::new();
    }
    let mut factories = HashSet::new();
    collect_factories_from_items(&file.items, false, &mut factories);
    let mut out = Vec::new();
    scan_items(rel, &file.items, false, &factories, &mut out);
    out.sort();
    out.dedup();
    out
}

/// Every free fn or method in production code whose return type mentions
/// `ClientBuilder`: a call to one starts a builder chain.
fn collect_factories_from_items(
    items: &[syn::Item],
    test_only_ancestor: bool,
    out: &mut HashSet<String>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if test_only_ancestor || is_cfg_test(&f.attrs) {
                    continue;
                }
                if return_type_mentions_client_builder(&f.sig.output) {
                    out.insert(f.sig.ident.to_string());
                }
            }
            syn::Item::Mod(m) => {
                if test_only_ancestor || is_cfg_test(&m.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    collect_factories_from_items(inner, false, out);
                }
            }
            syn::Item::Impl(imp) => {
                if test_only_ancestor || is_cfg_test(&imp.attrs) {
                    continue;
                }
                for inner in &imp.items {
                    if let syn::ImplItem::Fn(meth) = inner
                        && !is_cfg_test(&meth.attrs)
                        && return_type_mentions_client_builder(&meth.sig.output)
                    {
                        out.insert(meth.sig.ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn scan_items(
    rel: &str,
    items: &[syn::Item],
    test_only_ancestor: bool,
    factories: &HashSet<String>,
    out: &mut Vec<Entry>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if test_only_ancestor || is_cfg_test(&f.attrs) {
                    continue;
                }
                push_fn_entries(rel, &f.sig, &f.block, factories, out);
            }
            syn::Item::Mod(m) => {
                if test_only_ancestor || is_cfg_test(&m.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    scan_items(rel, inner, false, factories, out);
                }
            }
            syn::Item::Impl(imp) => {
                if test_only_ancestor || is_cfg_test(&imp.attrs) {
                    continue;
                }
                for inner in &imp.items {
                    if let syn::ImplItem::Fn(meth) = inner {
                        if is_cfg_test(&meth.attrs) {
                            continue;
                        }
                        push_fn_entries(rel, &meth.sig, &meth.block, factories, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn push_fn_entries(
    rel: &str,
    sig: &syn::Signature,
    block: &syn::Block,
    factories: &HashSet<String>,
    out: &mut Vec<Entry>,
) {
    let mut v = FnVisitor::new(rel, sig, factories);
    v.visit_block(block);
    if v.hits.implicit {
        out.push(Entry {
            rule: RULE_IMPLICIT,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
    if v.hits.hop {
        out.push(Entry {
            rule: RULE_HOP,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
    if v.hits.delegation {
        out.push(Entry {
            rule: RULE_DELEGATION,
            file: rel.to_string(),
            func: v.func.clone(),
        });
    }
}

struct ClientBuilderFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for ClientBuilderFinder {
    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        if node == "ClientBuilder" {
            self.found = true;
        }
    }
}

fn return_type_mentions_client_builder(output: &syn::ReturnType) -> bool {
    let mut f = ClientBuilderFinder { found: false };
    f.visit_return_type(output);
    f.found
}

fn type_mentions_client_builder(ty: &syn::Type) -> bool {
    let mut f = ClientBuilderFinder { found: false };
    f.visit_type(ty);
    f.found
}

/// Which rules apply to the file under visit.
struct RuleChecks {
    /// Rule (ii): hop-count literals and `Policy::limited`.
    hop: bool,
    /// Rule (iii): `Policy::custom` closures must branch on the decision.
    delegation: bool,
}

/// Which rules have fired in the function under visit.
#[derive(Default)]
struct RuleHits {
    implicit: bool,
    hop: bool,
    delegation: bool,
}

struct FnVisitor<'f> {
    func: String,
    is_factory: bool,
    checks: RuleChecks,
    hits: RuleHits,
    in_conditional: u32,
    in_closure: u32,
    factories: &'f HashSet<String>,
    vars: HashMap<String, (bool, bool)>,
}

impl<'f> FnVisitor<'f> {
    fn new(rel: &str, sig: &syn::Signature, factories: &'f HashSet<String>) -> Self {
        let exempt = rel == EXEMPT_REDIRECT_RS;
        // A `ClientBuilder` parameter starts a chain inside the fn, with no
        // `.redirect(` recorded yet.
        let mut vars = HashMap::new();
        for input in &sig.inputs {
            if let syn::FnArg::Typed(arg) = input
                && let syn::Pat::Ident(name) = &arg.pat
                && type_mentions_client_builder(&arg.ty)
            {
                vars.insert(name.ident.to_string(), (true, false));
            }
        }
        Self {
            func: sig.ident.to_string(),
            is_factory: return_type_mentions_client_builder(&sig.output),
            checks: RuleChecks {
                hop: !exempt,
                delegation: !exempt,
            },
            hits: RuleHits::default(),
            in_conditional: 0,
            in_closure: 0,
            factories,
            vars,
        }
    }
}

impl<'ast, 'f> Visit<'ast> for FnVisitor<'f> {
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _: &'ast syn::ImplItemFn) {}

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_expr(&node.cond);
        self.in_conditional = self.in_conditional.saturating_add(1);
        self.visit_block(&node.then_branch);
        if let Some((_, alt)) = &node.else_branch {
            self.visit_expr(alt);
        }
        self.in_conditional = self.in_conditional.saturating_sub(1);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.visit_expr(&node.scrutinee);
        self.in_conditional = self.in_conditional.saturating_add(1);
        for arm in &node.arms {
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
        }
        self.in_conditional = self.in_conditional.saturating_sub(1);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.in_closure = self.in_closure.saturating_add(1);
        syn::visit::visit_expr_closure(self, node);
        self.in_closure = self.in_closure.saturating_sub(1);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        syn::visit::visit_local(self, node);
        if self.in_conditional != 0 || self.in_closure != 0 {
            return;
        }
        if let syn::Pat::Ident(pat) = &node.pat
            && pat.ident != "_"
            && let Some(init) = &node.init
        {
            let state = analyze_builder_expr(&init.expr, &self.vars, self.factories);
            self.vars.insert(pat.ident.to_string(), state);
        }
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, node);
        if self.in_closure != 0 {
            return;
        }
        if self.in_conditional != 0 {
            // A branch that replaces a tracked builder with a fresh chain
            // invalidates its recorded `.redirect(` state: the chain needs
            // `.redirect(` after the branch.
            if let syn::Expr::Path(p) = &*node.left
                && let Some(ident) = p.path.get_ident()
                && ident != "_"
                && self
                    .vars
                    .get(&ident.to_string())
                    .is_some_and(|(is_builder, _)| *is_builder)
                && expr_contains_builder_start(&node.right, self.factories)
            {
                self.vars.insert(ident.to_string(), (true, false));
            }
            return;
        }
        if let syn::Expr::Path(p) = &*node.left
            && let Some(ident) = p.path.get_ident()
            && ident != "_"
        {
            let state = analyze_builder_expr(&node.right, &self.vars, self.factories);
            self.vars.insert(ident.to_string(), state);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "build" && !self.is_factory {
            let (is_builder, has_redirect) =
                analyze_builder_expr(&node.receiver, &self.vars, self.factories);
            if is_builder && !has_redirect {
                self.hits.implicit = true;
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            let names: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if names.len() >= 2 {
                let last = &names[names.len() - 1];
                let prev = &names[names.len() - 2];
                if prev == "Client" && last == "new" {
                    self.hits.implicit = true;
                }
                if prev == "reqwest" && last == "get" {
                    self.hits.implicit = true;
                }
                if self.checks.hop && prev == "Policy" && last == "limited" {
                    self.hits.hop = true;
                }
                if self.checks.delegation && prev == "Policy" && last == "custom" {
                    let mut bad = false;
                    for arg in &node.args {
                        if let syn::Expr::Closure(cl) = arg
                            && !closure_delegates(&cl.body)
                        {
                            bad = true;
                        }
                    }
                    if bad {
                        self.hits.delegation = true;
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.len() >= 2 {
            let mut rev = node.path.segments.iter().rev();
            if let (Some(last), Some(prev)) = (rev.next(), rev.next())
                && prev.ident == "Policy"
                && last.ident == "default"
            {
                self.hits.implicit = true;
            }
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if self.checks.hop {
            let cmp = matches!(
                &node.op,
                syn::BinOp::Lt(_)
                    | syn::BinOp::Le(_)
                    | syn::BinOp::Gt(_)
                    | syn::BinOp::Ge(_)
                    | syn::BinOp::Eq(_)
            );
            if cmp {
                let left_lit = is_int_lit(&node.left);
                let right_lit = is_int_lit(&node.right);
                if left_lit || right_lit {
                    let other = if left_lit { &node.right } else { &node.left };
                    if expr_mentions_previous_for_hop(other) {
                        self.hits.hop = true;
                    }
                }
            }
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

fn is_int_lit(expr: &syn::Expr) -> bool {
    if let syn::Expr::Lit(lit) = expr {
        matches!(&lit.lit, syn::Lit::Int(_))
    } else {
        false
    }
}

struct IdentCollector {
    idents: Vec<String>,
}

impl<'ast> Visit<'ast> for IdentCollector {
    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        self.idents.push(node.to_string());
    }
}

fn expr_mentions_previous_for_hop(expr: &syn::Expr) -> bool {
    let mut c = IdentCollector { idents: Vec::new() };
    c.visit_expr(expr);
    if c.idents.iter().any(|s| s == "previous_hops") {
        return true;
    }
    let mut seen = false;
    for id in &c.idents {
        if id == "previous" {
            seen = true;
        } else if id == "len" && seen {
            return true;
        }
    }
    false
}

fn expr_mentions_previous_substring(expr: &syn::Expr) -> bool {
    let mut c = IdentCollector { idents: Vec::new() };
    c.visit_expr(expr);
    c.idents.iter().any(|s| s.contains("previous"))
}

/// Whether `expr` calls `redirect_decision` / `hop_budget_spent` on a
/// previous-hop count.
fn is_decision_call(expr: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expr else {
        return false;
    };
    let syn::Expr::Path(func) = &*call.func else {
        return false;
    };
    let Some(last) = func.path.segments.last() else {
        return false;
    };
    if last.ident != "redirect_decision" && last.ident != "hop_budget_spent" {
        return false;
    }
    call.args
        .first()
        .is_some_and(expr_mentions_previous_substring)
}

/// Whether `expr` mentions any of the `let`-bound decision names.
fn expr_mentions_any_bound(expr: &syn::Expr, bound: &HashSet<String>) -> bool {
    let mut collector = IdentCollector { idents: Vec::new() };
    collector.visit_expr(expr);
    collector.idents.iter().any(|id| bound.contains(id))
}

/// Rule (iii): calling the decider is not enough; the closure passes only if
/// it branches on the answer. The decision call is the scrutinee of a `match`,
/// the condition of an `if`, or bound with `let` and that binding later
/// matched on or used in an `if`. `let _ = ...` never counts.
struct DecisionUsage {
    bound: HashSet<String>,
    used: bool,
}

impl<'ast> Visit<'ast> for DecisionUsage {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if is_decision_call(&node.scrutinee) {
            self.used = true;
        } else if let syn::Expr::Path(scrutinee) = &*node.scrutinee
            && let Some(name) = scrutinee.path.get_ident()
            && self.bound.contains(&name.to_string())
        {
            self.used = true;
        }
        if !self.used {
            syn::visit::visit_expr_match(self, node);
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if is_decision_call(&node.cond) || expr_mentions_any_bound(&node.cond, &self.bound) {
            self.used = true;
        }
        if !self.used {
            syn::visit::visit_expr_if(self, node);
        }
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(name) = &node.pat
            && name.ident != "_"
            && let Some(init) = &node.init
            && is_decision_call(&init.expr)
        {
            self.bound.insert(name.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn closure_delegates(body: &syn::Expr) -> bool {
    let mut f = DecisionUsage {
        bound: HashSet::new(),
        used: false,
    };
    f.visit_expr(body);
    f.used
}

fn is_start_path(path: &syn::Path, factories: &HashSet<String>) -> bool {
    let mut rev = path.segments.iter().rev();
    let Some(last) = rev.next() else {
        return false;
    };
    if factories.contains(&last.ident.to_string()) {
        return true;
    }
    let name = last.ident.to_string();
    if name == "builder" {
        if let Some(second) = rev.next() {
            return second.ident == "Client";
        }
        return false;
    }
    if name.ends_with("client_builder") {
        return true;
    }
    if name.ends_with("_builder_for") {
        return true;
    }
    name == "strict_builder"
}

struct StartFinder<'f> {
    factories: &'f HashSet<String>,
    found: bool,
}

impl<'ast, 'f> Visit<'ast> for StartFinder<'f> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func
            && is_start_path(&p.path, self.factories)
        {
            self.found = true;
            return;
        }
        syn::visit::visit_expr_call(self, node);
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn expr_contains_builder_start(expr: &syn::Expr, factories: &HashSet<String>) -> bool {
    let mut f = StartFinder {
        factories,
        found: false,
    };
    f.visit_expr(expr);
    f.found
}

struct BuildFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for BuildFinder {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "build" {
            self.found = true;
            return;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn expr_contains_build(expr: &syn::Expr) -> bool {
    let mut f = BuildFinder { found: false };
    f.visit_expr(expr);
    f.found
}

struct RedirectOutsideIfFinder {
    in_if: u32,
    found: bool,
}

impl<'ast> Visit<'ast> for RedirectOutsideIfFinder {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_expr(&node.cond);
        self.in_if = self.in_if.saturating_add(1);
        self.visit_block(&node.then_branch);
        if let Some((_, alt)) = &node.else_branch {
            self.visit_expr(alt);
        }
        self.in_if = self.in_if.saturating_sub(1);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.in_if == 0 && node.method == "redirect" {
            self.found = true;
            return;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn expr_contains_redirect_outside_if(expr: &syn::Expr) -> bool {
    let mut f = RedirectOutsideIfFinder {
        in_if: 0,
        found: false,
    };
    f.visit_expr(expr);
    f.found
}

struct VarUseCollector<'v> {
    vars: &'v HashMap<String, (bool, bool)>,
    used: Vec<bool>,
}

impl<'ast> Visit<'ast> for VarUseCollector<'_> {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(ident) = node.path.get_ident()
            && let Some((is_builder, has_redirect)) = self.vars.get(&ident.to_string())
            && *is_builder
        {
            self.used.push(*has_redirect);
        }
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn collect_used_builder_redirects(
    expr: &syn::Expr,
    vars: &HashMap<String, (bool, bool)>,
) -> Vec<bool> {
    let mut c = VarUseCollector {
        vars,
        used: Vec::new(),
    };
    c.visit_expr(expr);
    c.used
}

fn analyze_builder_expr(
    expr: &syn::Expr,
    vars: &HashMap<String, (bool, bool)>,
    factories: &HashSet<String>,
) -> (bool, bool) {
    match expr {
        syn::Expr::Call(call) => {
            if let syn::Expr::Path(p) = &*call.func
                && is_start_path(&p.path, factories)
            {
                // A factory that threads a tracked builder through (e.g.
                // `extra_roots(builder)`) keeps that builder's recorded
                // state; a call with no builder argument starts a fresh
                // chain with no `.redirect(` recorded.
                let mut seen_builder = false;
                let mut all_redirect = true;
                for arg in &call.args {
                    let (is_builder, has_redirect) = analyze_builder_expr(arg, vars, factories);
                    if is_builder {
                        seen_builder = true;
                        all_redirect = all_redirect && has_redirect;
                    }
                }
                return (true, seen_builder && all_redirect);
            }
            (false, false)
        }
        syn::Expr::MethodCall(mc) => {
            if mc.method == "build" {
                return (false, false);
            }
            if mc.method == "redirect" {
                let (builder, _) = analyze_builder_expr(&mc.receiver, vars, factories);
                return (builder, true);
            }
            analyze_builder_expr(&mc.receiver, vars, factories)
        }
        syn::Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident()
                && let Some(state) = vars.get(&ident.to_string())
            {
                return *state;
            }
            (false, false)
        }
        _ => {
            if expr_contains_build(expr) {
                return (false, false);
            }
            let has_start = expr_contains_builder_start(expr, factories);
            let used = collect_used_builder_redirects(expr, vars);
            if !has_start && used.is_empty() {
                return (false, false);
            }
            if expr_contains_redirect_outside_if(expr) {
                return (true, true);
            }
            if used.is_empty() {
                return (true, false);
            }
            (true, used.iter().all(|&r| r))
        }
    }
}

/// Reviewed exceptions, each with its reason. Keep this list short: every
/// entry is a site the rules cannot see into.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "delegation",
        "src/transport/http/client.rs",
        "build",
        "hands previous().len() to transport's own decider evaluate_redirect_for, \
         whose count is pinned by transport/http/tests.rs (T1b, T15)",
    ),
    (
        "delegation",
        "src/key_server/oidc_jwks_cache.rs",
        "with_remote_proxy",
        "refuses every redirect; no hop is ever followed, so there is no budget to consult",
    ),
    (
        "implicit-policy",
        "src/personal_accounts/provider/http.rs",
        "build",
        "private; its only callers pass strict_builder(), which sets Policy::none() (the \
         production path and the cfg(test) for_test seam); pinned by \
         personal_accounts_build_is_only_handed_the_strict_builder",
    ),
];

/// Pins the reason of the `personal_accounts/provider/http.rs::build` row in
/// [`ALLOWED`]: every `Self::build(..)` there is handed `strict_builder()`,
/// directly or through the test seam's `configure(strict_builder())`. A new
/// caller with any other builder fails here instead of passing the scan unseen.
#[test]
fn personal_accounts_build_is_only_handed_the_strict_builder() {
    struct Calls(Vec<bool>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*node.func {
                let names: Vec<String> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if names == ["Self", "build"] {
                    self.0
                        .push(node.args.len() == 1 && hands_strict(&node.args[0]));
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    fn called(expr: &syn::Expr, name: &str) -> Option<usize> {
        let syn::Expr::Call(call) = expr else {
            return None;
        };
        let syn::Expr::Path(p) = &*call.func else {
            return None;
        };
        (p.path.segments.last()?.ident == name).then_some(call.args.len())
    }
    fn hands_strict(expr: &syn::Expr) -> bool {
        called(expr, "strict_builder") == Some(0)
            || (called(expr, "configure") == Some(1)
                && matches!(expr, syn::Expr::Call(c) if hands_strict(&c.args[0])))
    }
    let callers = |source: &str| {
        let mut calls = Calls(Vec::new());
        calls.visit_file(&syn::parse_file(source).expect("parse"));
        calls.0
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/personal_accounts/provider/http.rs");
    let real = callers(&std::fs::read_to_string(&path).expect("read http.rs"));
    assert!(
        !real.is_empty(),
        "no Self::build call found: the pin reads the wrong file"
    );
    assert!(
        real.iter().all(|ok| *ok),
        "a Self::build caller is handed another builder: {real:?}"
    );
    // The pin can fail: a caller handing a loose builder is caught.
    let planted = "impl P { fn a() { Self::build(strict_builder()) } fn b() { Self::build(Client::builder()) } }";
    assert_eq!(callers(planted), [true, false]);
}

#[test]
fn production_clients_set_an_explicit_redirect_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut entries = scan_crate(root);
    for (rule, file, func, _why) in ALLOWED {
        let before = entries.len();
        entries.retain(|e| !(e.rule == *rule && e.file == *file && e.func == *func));
        assert!(
            entries.len() < before,
            "stale allowlist entry: {rule} {file}::{func}"
        );
    }
    entries.sort();
    let mut msg = String::from("redirect policy gaps:\n");
    for e in &entries {
        let _ = write!(msg, "{} {}::{}\n", e.rule, e.file, e.func);
    }
    assert!(entries.is_empty(), "{msg}");
}

fn check_reported(name: &str, src: &str) {
    let entries = scan_source("src/fixture.rs", src);
    assert!(!entries.is_empty(), "negative case {name} was not flagged");
}

fn check_clean(name: &str, src: &str) {
    let entries = scan_source("src/fixture.rs", src);
    assert!(
        entries.is_empty(),
        "positive case {name} was flagged: {entries:?}"
    );
}

#[test]
fn the_scanner_reports_each_negative_fixture() {
    check_reported("client-new", "fn f() { let _ = Client::new(); }");
    check_reported(
        "reqwest-get",
        "fn f() { let _ = reqwest::get(\"http://example.com\"); }",
    );
    check_reported(
        "policy-default",
        "fn f() { let _ = reqwest::redirect::Policy::default(); }",
    );
    check_reported(
        "split-chain",
        "fn f() { let b = Client::builder(); let b = b.timeout(std::time::Duration::from_secs(1)); let _ = b.build(); }",
    );
    check_reported(
        "pinned-builder",
        "fn f() { let b = pinned_client_builder(); let _ = b.build(); }",
    );
    check_reported(
        "redirect-only-in-if",
        "fn f(cond: bool) { let mut b = Client::builder(); if cond { b = b.redirect(reqwest::redirect::Policy::none()); } let _ = b.build(); }",
    );
    check_reported(
        "count-handed-to-a-fn-that-ignores-it",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| { ignore(a.previous().len()); a.follow() }); }",
    );
    check_reported(
        "previous-hops-cmp",
        "fn f(previous_hops: usize) { if previous_hops > 5 {} }",
    );
    check_reported(
        "previous-len-cmp",
        "fn f(attempt: reqwest::redirect::Attempt) { if attempt.previous().len() >= 5 {} }",
    );
    check_reported(
        "policy-limited",
        "fn f() { let _ = reqwest::redirect::Policy::limited(3); }",
    );
    check_reported(
        "custom-no-delegation",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| a.follow()); }",
    );
    check_reported(
        "custom-delegates",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| { let _ = redirect_decision(a.previous().len(), a.url().as_str()); a.follow() }); }",
    );
    check_reported(
        "factory-route-no-redirect",
        "fn f() -> Client { route(None).timeout(d).build().expect(\"x\") } fn route(p: Option<u8>) -> reqwest::ClientBuilder { Client::builder() }",
    );
    check_reported(
        "builder-param-no-redirect",
        "fn f(b: reqwest::ClientBuilder) -> Client { b.timeout(d).build().expect(\"x\") }",
    );
    check_reported(
        "if-branch-replaces-builder",
        "fn f(c: bool) { let mut b = Client::builder().redirect(Policy::none()); if c { b = Client::builder(); } b.build(); }",
    );
}

#[test]
fn the_scanner_passes_each_positive_fixture() {
    check_clean(
        "client-new-fixed",
        "fn f() { let _ = Client::builder().redirect(reqwest::redirect::Policy::none()).build(); }",
    );
    check_clean(
        "reqwest-get-fixed",
        "fn f() { let c = Client::builder().redirect(reqwest::redirect::Policy::none()).build(); let _ = c.get(\"http://example.com\"); }",
    );
    check_clean(
        "policy-default-fixed",
        "fn f() { let _ = reqwest::redirect::Policy::none(); }",
    );
    check_clean(
        "split-chain-fixed",
        "fn f() { let b = Client::builder(); let b = b.timeout(std::time::Duration::from_secs(1)); let b = b.redirect(reqwest::redirect::Policy::none()); let _ = b.build(); }",
    );
    check_clean(
        "pinned-builder-fixed",
        "fn f() { let b = pinned_client_builder(); let b = b.redirect(reqwest::redirect::Policy::none()); let _ = b.build(); }",
    );
    check_clean(
        "redirect-main-flow",
        "fn f(cond: bool) { let mut b = Client::builder(); b = b.redirect(reqwest::redirect::Policy::none()); if cond { b = b.timeout(std::time::Duration::from_secs(1)); } let _ = b.build(); }",
    );
    check_clean(
        "previous-hops-const",
        "fn f(previous_hops: usize) { const MAX: usize = 5; if previous_hops > MAX {} }",
    );
    check_clean(
        "previous-len-const",
        "fn f(attempt: reqwest::redirect::Attempt) { const MAX: usize = 5; if attempt.previous().len() >= MAX {} }",
    );
    check_clean(
        "limited-fixed",
        "fn f() { let p = reqwest::redirect::Policy::none(); let _ = p; }",
    );
    check_clean(
        "custom-matches-on-decision",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| match redirect_decision(a.previous().len(), a.url().as_str()) { _ => a.follow() }); }",
    );
    check_clean(
        "factory",
        "fn make() -> reqwest::ClientBuilder { Client::builder().build(); Client::builder() }",
    );
    check_clean(
        "factory-route-with-redirect",
        "fn f() -> Client { route(None).redirect(Policy::none()).timeout(d).build().expect(\"x\") } fn route(p: Option<u8>) -> reqwest::ClientBuilder { Client::builder() }",
    );
    check_clean(
        "builder-param-with-redirect",
        "fn f(b: reqwest::ClientBuilder) -> Client { b.redirect(Policy::none()).timeout(d).build().expect(\"x\") }",
    );
    check_clean(
        "if-branch-replaced-then-redirect",
        "fn f(c: bool) { let mut b = Client::builder().redirect(Policy::none()); if c { b = Client::builder(); } b = b.redirect(Policy::none()); b.build(); }",
    );
    check_clean("comment-only", "fn f() { // Policy::limited(3)\n }");
}

#[test]
fn a_path_included_test_module_is_not_production() {
    let base = std::env::temp_dir().join(format!("redirect_policy_scan_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("src")).expect("make temp src dir for fixture");
    std::fs::write(
        base.join("src/lib.rs"),
        "#[cfg(test)] mod fix;\nmod live;\n",
    )
    .expect("write lib fixture");
    std::fs::write(
        base.join("src/fix.rs"),
        "#[path = \"bridge.rs\"] mod bridge;\n",
    )
    .expect("write fix fixture");
    std::fs::write(
        base.join("src/bridge.rs"),
        "fn f() { let _ = reqwest::Client::new(); }\n",
    )
    .expect("write bridge fixture");
    std::fs::write(
        base.join("src/live.rs"),
        "fn f() { let _ = reqwest::Client::new(); }\n",
    )
    .expect("write live fixture");
    let entries = scan_crate(&base);
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        entries.len() == 1,
        "only live is production, got {entries:?}"
    );
    assert_eq!(entries[0].file, "src/live.rs");
    assert_eq!(entries[0].func, "f");
}
