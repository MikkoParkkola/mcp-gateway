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
use std::path::Path;
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
                && let syn::Pat::Ident(name) = &*arg.pat
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

impl<'ast> Visit<'ast> for FnVisitor<'_> {
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
        self.visit_expr(&node.expr);
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
            // A branch that replaces a tracked builder with a fresh chain, or
            // with another tracked builder variable whose own state has no
            // `.redirect(`, invalidates its recorded `.redirect(` state: the
            // chain needs `.redirect(` after the branch.
            if let syn::Expr::Path(p) = &*node.left
                && let Some(ident) = p.path.get_ident()
                && ident != "_"
                && self
                    .vars
                    .get(&ident.to_string())
                    .is_some_and(|(is_builder, _)| *is_builder)
                && branch_replaces_builder(&node.right, &self.vars, self.factories)
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
/// it branches on the answer. The decision call is the scrutinee of a `match`
/// with an arm naming a variant, the condition of an `if`, or bound with `let`
/// and that binding later matched on or used in an `if`. `let _ = ...` never
/// counts, and neither does `match ... { _ => ... }` nor a bare identifier
/// binding such as `match ... { decided => ... }`.
struct DecisionUsage {
    bound: HashSet<String>,
    used: bool,
}

/// Whether a `match` arm pattern discriminates the decision by naming a
/// variant: a path pattern, a tuple-struct pattern such as `Reject(_)`, or an
/// or-pattern containing one. A bare wildcard `_` or a bare identifier binding
/// (`decided => ..`) does not.
fn pattern_names_variant(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Path(_) | syn::Pat::TupleStruct(_) => true,
        syn::Pat::Or(or) => or.cases.iter().any(pattern_names_variant),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for DecisionUsage {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        // A match counts as using the decision only if some arm names a
        // variant; `{ _ => ... }` or `{ decided => ... }` discards the answer
        // like `let _ = ...`.
        if node.arms.iter().any(|arm| pattern_names_variant(&arm.pat)) {
            if is_decision_call(&node.expr) {
                self.used = true;
            } else if let syn::Expr::Path(scrutinee) = &*node.expr
                && let Some(name) = scrutinee.path.get_ident()
                && self.bound.contains(&name.to_string())
            {
                self.used = true;
            }
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

impl<'ast> Visit<'ast> for StartFinder<'_> {
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

/// Whether an assignment's right-hand side replaces a tracked builder's
/// recorded state from inside a branch: a fresh chain start, another tracked
/// builder variable whose own state has no `.redirect(`, or a builder
/// expression without `.redirect(` such as `loose.timeout(d)`.
fn branch_replaces_builder(
    right: &syn::Expr,
    vars: &HashMap<String, (bool, bool)>,
    factories: &HashSet<String>,
) -> bool {
    if expr_contains_builder_start(right, factories) {
        return true;
    }
    if let syn::Expr::Path(p) = right
        && let Some(name) = p.path.get_ident()
    {
        return vars
            .get(&name.to_string())
            .is_some_and(|(is_builder, has_redirect)| *is_builder && !*has_redirect);
    }
    let (is_builder, has_redirect) = analyze_builder_expr(right, vars, factories);
    is_builder && !has_redirect
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

#[path = "redirect_policy_scan_walk_tests.rs"]
mod walk;

#[path = "redirect_policy_scan_cases_tests.rs"]
mod cases;
