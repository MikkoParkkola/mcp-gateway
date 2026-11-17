// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! No `async fn` wrapper holds the future it scopes twice.

use super::*;

/// The wrappers that stay `async fn`, and the scan behind
/// [`no_async_fn_holds_the_future_it_scopes_twice`].
// (file, function, why it stays an `async fn`): each reads or joins
// task-local state, which must happen in the task that polls it, or (the
// public trace scope) must drop an unpolled future outside the scope.
const DELIBERATE: &[(&str, &str, &str)] = &[
    (
        "src/oauth/login_gate/scopes.rs",
        "non_interactive",
        "reads the caller's contention class",
    ),
    (
        "src/oauth/login_gate/scopes.rs",
        "scope",
        "captures the gate's cohort before it can queue on a start lock",
    ),
    (
        "src/gateway/meta_mcp/invoke/relay_staging.rs",
        "plan_step",
        "reads the outer plan step",
    ),
    (
        "src/gateway/meta_mcp/visible/memo.rs",
        "with_judged",
        "reads the worker's judged names",
    ),
    (
        "src/gateway/meta_mcp/visible/memo.rs",
        "with_visibility_memo",
        "joins a memo already open",
    ),
    (
        "src/gateway/meta_mcp/hiding.rs",
        "with_caller_slot",
        "joins a caller slot already open",
    ),
    (
        "src/gateway/meta_mcp/sealed_hold.rs",
        "scoped",
        "joins holds already open",
    ),
    (
        "src/gateway/trace.rs",
        "with_trace_id",
        "public: an unpolled future must drop under the caller's own trace id",
    ),
];
struct Scan<'a> {
    path: &'a str,
    found: Vec<String>,
    async_fns: Vec<(String, String)>,
}
fn is_future(bound: &syn::TypeParamBound) -> bool {
    matches!(bound, syn::TypeParamBound::Trait(t)
        if t.path.segments.last().is_some_and(|s| s.ident == "Future"))
}
fn ident_of(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
            Some(p.path.segments[0].ident.to_string())
        }
        _ => None,
    }
}
fn takes_a_future(sig: &syn::Signature) -> Vec<String> {
    let mut futures: Vec<String> = sig
        .generics
        .type_params()
        .filter(|p| p.bounds.iter().any(is_future))
        .map(|p| p.ident.to_string())
        .collect();
    if let Some(w) = &sig.generics.where_clause {
        for pred in &w.predicates {
            if let syn::WherePredicate::Type(t) = pred
                && t.bounds.iter().any(is_future)
                && let Some(ident) = ident_of(&t.bounded_ty)
            {
                futures.push(ident);
            }
        }
    }
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pt) => match (&*pt.pat, ident_of(&pt.ty)) {
                (syn::Pat::Ident(pat), Some(ty)) if futures.contains(&ty) => {
                    Some(pat.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}
fn scopes_it(block: &syn::Block, params: &[String]) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Await(aw), None)) = block.stmts.last() else {
        return false;
    };
    let syn::Expr::MethodCall(call) = &*aw.base else {
        return false;
    };
    call.method == "scope"
        && call.args.iter().any(|a| {
            matches!(a, syn::Expr::Path(p)
                if p.path.get_ident().is_some_and(|i| params.contains(&i.to_string())))
        })
}
impl Scan<'_> {
    fn check(&mut self, sig: &syn::Signature, block: &syn::Block) {
        if sig.asyncness.is_none() {
            return;
        }
        let name = sig.ident.to_string();
        self.async_fns.push((self.path.to_owned(), name.clone()));
        let params = takes_a_future(sig);
        if !params.is_empty()
            && scopes_it(block, &params)
            && !DELIBERATE
                .iter()
                .any(|(file, n, _)| *file == self.path && *n == name)
        {
            self.found.push(format!("{}: {name}", self.path));
        }
    }
}
impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.check(&f.sig, &f.block);
        syn::visit::visit_item_fn(self, f);
    }
    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.check(&f.sig, &f.block);
        syn::visit::visit_impl_item_fn(self, f);
    }
    fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
        if let Some(block) = &f.default {
            self.check(&f.sig, block);
        }
        syn::visit::visit_trait_item_fn(self, f);
    }
}

/// Every `async fn` whose body ends in `<task local>.scope(.., future).await`
/// on a future it takes holds that future twice, as the delivery scope did. The
/// plain `fn .. -> impl Future` form holds it once. Listed exceptions read or
/// join task-local state before scoping, which must happen when the future is
/// first polled, not when it is made.
#[test]
fn no_async_fn_holds_the_future_it_scopes_twice() {
    use syn::visit::Visit;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    let mut async_fns = Vec::new();
    for path in crate::mutant_scan::tracked_rs_files(root).expect("list the sources") {
        if !path.starts_with("src/") || path.ends_with("_tests.rs") || path.contains("/tests/") {
            continue;
        }
        // An unreadable or unparsable file fails the row: a file it could
        // not inspect must not pass for one with no such wrapper.
        let text = std::fs::read_to_string(root.join(&path))
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        let file = syn::parse_file(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
        let mut scan = Scan {
            path: &path,
            found: Vec::new(),
            async_fns: Vec::new(),
        };
        scan.visit_file(&file);
        found.extend(scan.found);
        async_fns.extend(scan.async_fns);
    }
    // Every listed exception still names an async fn: a stale row, or one
    // converted without leaving the list, fails here.
    let stale: Vec<&str> = DELIBERATE
        .iter()
        .filter(|(file, name, _)| {
            !async_fns
                .iter()
                .any(|(f, n)| f.as_str() == *file && n.as_str() == *name)
        })
        .map(|(_, name, _)| *name)
        .collect();
    assert!(
        stale.is_empty(),
        "listed exceptions that are no longer an async fn there: {stale:?}"
    );
    assert!(
        found.is_empty(),
        "async fns that hold the future they scope twice (make each a plain fn returning \
         the scoped future): {found:?}"
    );
}
