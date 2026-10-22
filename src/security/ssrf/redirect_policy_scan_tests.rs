// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660 (DUPC-3.PR3.6, PR3.6d): every production reqwest client outside
//! `src/oauth/` states its redirect policy, and only `security/ssrf/redirect.rs`
//! states a hop limit.
//!
//! Rule (i): `Client::new()`, `reqwest::get`, `Policy::default()`, or a builder
//! chain that reaches `.build()` without `.redirect(` on every path is reqwest's
//! implicit ten-hop default. A fn returning a `ClientBuilder` is a factory; its
//! callers are checked. Rule (ii): a hop count compared with an integer
//! literal, or `Policy::limited`. Rule (iii): a `Policy::custom` closure that
//! never passes `previous()` into `redirect_decision` / `hop_budget_spent`.
//! Production means reached from `lib.rs` / `main.rs` through modules none of
//! which is `#[cfg(test)]`, so a `#[path]` file included under a test module is
//! test code. A parser, not a text match: comments never count.

use std::collections::{HashMap, HashSet};
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
const KEY_SERVER_PREFIX: &str = "src/key_server/";

fn contains_word(hay: &str, needle: &str) -> bool {
    hay.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == needle)
}

fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("cfg") {
            if let syn::Meta::List(list) = &attr.meta {
                let text = list.tokens.to_string();
                if contains_word(&text, "test") && !contains_word(&text, "not") {
                    return true;
                }
            }
        }
    }
    false
}

fn path_attr_value(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("path") {
            if let syn::Meta::NameValue(pair) = &attr.meta {
                if let syn::Expr::Lit(lit) = &pair.value {
                    if let syn::Lit::Str(s) = &lit.lit {
                        return Some(s.value());
                    }
                }
            }
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
                {
                    if !child.starts_with(OAUTH_PREFIX) {
                        out.push(child);
                    }
                }
            }
        }
    }
}

fn scan_crate(root: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = Vec::new();
    for start in ["src/lib.rs", "src/main.rs"] {
        if root.join(start).is_file() {
            queue.push(start.to_string());
        }
    }
    while let Some(rel) = queue.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        if rel.starts_with(OAUTH_PREFIX) {
            continue;
        }
        let content = match std::fs::read_to_string(root.join(&rel)) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let file = match syn::parse_file(&content) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if !is_cfg_test(&file.attrs) {
            let mut found = Vec::new();
            scan_items(&rel, &file.items, false, &mut found);
            entries.extend(found);
        }
        let mut kids = Vec::new();
        collect_child_mods_from_items(
            &file.items,
            is_cfg_test(&file.attrs),
            &rel,
            root,
            &mut kids,
        );
        for k in kids {
            if !seen.contains(&k) {
                queue.push(k);
            }
        }
    }
    entries.sort();
    entries.dedup();
    entries
}

fn scan_source(rel: &str, src: &str) -> Vec<Entry> {
    if rel.starts_with(OAUTH_PREFIX) {
        return Vec::new();
    }
    let file = match syn::parse_file(src) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
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
    let mut out = Vec::new();
    scan_items(rel, &file.items, false, &mut out);
    out.sort();
    out.dedup();
    out
}

fn scan_items(rel: &str, items: &[syn::Item], test_only_ancestor: bool, out: &mut Vec<Entry>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                if test_only_ancestor || is_cfg_test(&f.attrs) {
                    continue;
                }
                push_fn_entries(rel, &f.sig.ident.to_string(), &f.sig.output, &f.block, out);
            }
            syn::Item::Mod(m) => {
                if test_only_ancestor || is_cfg_test(&m.attrs) {
                    continue;
                }
                if let Some((_, inner)) = &m.content {
                    scan_items(rel, inner, false, out);
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
                        push_fn_entries(
                            rel,
                            &meth.sig.ident.to_string(),
                            &meth.sig.output,
                            &meth.block,
                            out,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn push_fn_entries(
    rel: &str,
    func: &str,
    output: &syn::ReturnType,
    block: &syn::Block,
    out: &mut Vec<Entry>,
) {
    let factory = return_type_mentions_client_builder(output);
    let mut v = FnVisitor::new(rel, factory);
    v.visit_block(block);
    if v.found_i {
        out.push(Entry {
            rule: RULE_IMPLICIT,
            file: rel.to_string(),
            func: func.to_string(),
        });
    }
    if v.found_ii {
        out.push(Entry {
            rule: RULE_HOP,
            file: rel.to_string(),
            func: func.to_string(),
        });
    }
    if v.found_iii {
        out.push(Entry {
            rule: RULE_DELEGATION,
            file: rel.to_string(),
            func: func.to_string(),
        });
    }
}

struct ClientBuilderFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for ClientBuilderFinder {
    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        if node.to_string() == "ClientBuilder" {
            self.found = true;
        }
    }
}

fn return_type_mentions_client_builder(output: &syn::ReturnType) -> bool {
    let mut f = ClientBuilderFinder { found: false };
    f.visit_return_type(output);
    f.found
}

struct FnVisitor {
    is_factory: bool,
    check_ii: bool,
    check_iii: bool,
    in_if: u32,
    in_closure: u32,
    vars: HashMap<String, (bool, bool)>,
    found_i: bool,
    found_ii: bool,
    found_iii: bool,
}

impl FnVisitor {
    fn new(rel: &str, is_factory: bool) -> Self {
        Self {
            is_factory,
            check_ii: rel != EXEMPT_REDIRECT_RS,
            check_iii: rel != EXEMPT_REDIRECT_RS && !rel.starts_with(KEY_SERVER_PREFIX),
            in_if: 0,
            in_closure: 0,
            vars: HashMap::new(),
            found_i: false,
            found_ii: false,
            found_iii: false,
        }
    }
}

impl<'ast> Visit<'ast> for FnVisitor {
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _: &'ast syn::ImplItemFn) {}

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_expr(&node.cond);
        self.in_if = self.in_if.saturating_add(1);
        self.visit_block(&node.then_branch);
        if let Some((_, alt)) = &node.else_branch {
            self.visit_expr(alt);
        }
        self.in_if = self.in_if.saturating_sub(1);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.in_closure = self.in_closure.saturating_add(1);
        syn::visit::visit_expr_closure(self, node);
        self.in_closure = self.in_closure.saturating_sub(1);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        syn::visit::visit_local(self, node);
        if self.in_if != 0 || self.in_closure != 0 {
            return;
        }
        if let syn::Pat::Ident(pat) = &node.pat {
            let name = pat.ident.to_string();
            if name == "_" {
                return;
            }
            if let Some(init) = &node.init {
                let state = analyze_builder_expr(&init.expr, &self.vars);
                self.vars.insert(name, state);
            }
        }
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, node);
        if self.in_if != 0 || self.in_closure != 0 {
            return;
        }
        if let syn::Expr::Path(p) = &*node.left {
            if let Some(ident) = p.path.get_ident() {
                let name = ident.to_string();
                if name == "_" {
                    return;
                }
                let state = analyze_builder_expr(&node.right, &self.vars);
                self.vars.insert(name, state);
            }
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method.to_string() == "build" && !self.is_factory {
            let (is_builder, has_redirect) =
                analyze_builder_expr(&node.receiver, &self.vars);
            if is_builder && !has_redirect {
                self.found_i = true;
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
                    self.found_i = true;
                }
                if prev == "reqwest" && last == "get" {
                    self.found_i = true;
                }
                if self.check_ii && prev == "Policy" && last == "limited" {
                    self.found_ii = true;
                }
                if self.check_iii && prev == "Policy" && last == "custom" {
                    let mut bad = false;
                    for arg in &node.args {
                        if let syn::Expr::Closure(cl) = arg {
                            if !closure_delegates(&cl.body) {
                                bad = true;
                            }
                        }
                    }
                    if bad {
                        self.found_iii = true;
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.len() >= 2 {
            let mut rev = node.path.segments.iter().rev();
            if let (Some(last), Some(prev)) = (rev.next(), rev.next()) {
                if prev.ident.to_string() == "Policy" && last.ident.to_string() == "default" {
                    self.found_i = true;
                }
            }
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if self.check_ii {
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
                        self.found_ii = true;
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

struct DelegationFinder {
    good: bool,
}

impl<'ast> Visit<'ast> for DelegationFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            if let Some(last) = p.path.segments.last() {
                let name = last.ident.to_string();
                if name == "redirect_decision" || name == "hop_budget_spent" {
                    if let Some(first) = node.args.first() {
                        if expr_mentions_previous_substring(first) {
                            self.good = true;
                        }
                    }
                }
            }
        }
        if !self.good {
            syn::visit::visit_expr_call(self, node);
        }
    }
    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn closure_delegates(body: &syn::Expr) -> bool {
    let mut f = DelegationFinder { good: false };
    f.visit_expr(body);
    f.good
}

fn is_start_path(path: &syn::Path) -> bool {
    let mut rev = path.segments.iter().rev();
    let Some(last) = rev.next() else {
        return false;
    };
    let name = last.ident.to_string();
    if name == "builder" {
        if let Some(second) = rev.next() {
            return second.ident.to_string() == "Client";
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

struct StartFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for StartFinder {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func {
            if is_start_path(&p.path) {
                self.found = true;
                return;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

fn expr_contains_builder_start(expr: &syn::Expr) -> bool {
    let mut f = StartFinder { found: false };
    f.visit_expr(expr);
    f.found
}

struct BuildFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for BuildFinder {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method.to_string() == "build" {
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
        if self.in_if == 0 && node.method.to_string() == "redirect" {
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

impl<'ast, 'v> Visit<'ast> for VarUseCollector<'v> {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(ident) = node.path.get_ident() {
            if let Some((is_builder, has_redirect)) = self.vars.get(&ident.to_string()) {
                if *is_builder {
                    self.used.push(*has_redirect);
                }
            }
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
) -> (bool, bool) {
    match expr {
        syn::Expr::Call(call) => {
            if let syn::Expr::Path(p) = &*call.func {
                if is_start_path(&p.path) {
                    return (true, false);
                }
            }
            (false, false)
        }
        syn::Expr::MethodCall(mc) => {
            if mc.method.to_string() == "build" {
                return (false, false);
            }
            if mc.method.to_string() == "redirect" {
                let (builder, _) = analyze_builder_expr(&mc.receiver, vars);
                return (builder, true);
            }
            analyze_builder_expr(&mc.receiver, vars)
        }
        syn::Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                if let Some(state) = vars.get(&ident.to_string()) {
                    return *state;
                }
            }
            (false, false)
        }
        _ => {
            if expr_contains_build(expr) {
                return (false, false);
            }
            let has_start = expr_contains_builder_start(expr);
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

#[test]
fn production_clients_set_an_explicit_redirect_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut entries = scan_crate(root);
    entries.sort();
    let mut msg = String::from("redirect policy gaps:\n");
    for e in &entries {
        msg.push_str(&format!("{} {}::{}\n", e.rule, e.file, e.func));
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
        "custom-delegates",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| { let _ = redirect_decision(a.previous().len(), a.url().as_str()); a.follow() }); }",
    );
    check_clean(
        "factory",
        "fn make() -> reqwest::ClientBuilder { Client::builder().build(); Client::builder() }",
    );
    check_clean("comment-only", "fn f() { // Policy::limited(3)\n }");
}

#[test]
fn a_path_included_test_module_is_not_production() {
    let base = std::env::temp_dir().join(format!(
        "redirect_policy_scan_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("src")).expect("make temp src dir for fixture");
    std::fs::write(base.join("src/lib.rs"), "#[cfg(test)] mod fix;\nmod live;\n")
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
    assert!(entries.len() == 1, "only live is production, got {entries:?}");
    assert_eq!(entries[0].file, "src/live.rs");
    assert_eq!(entries[0].func, "f");
}
