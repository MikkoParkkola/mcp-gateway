// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660: the redirect-policy scan's reviewed exceptions, its production
//! run, and its fixtures. Split from `redirect_policy_scan_tests.rs` for the
//! 800-line ceiling.

use std::fmt::Write as _;

use super::walk::{scan_crate, scan_source};
use super::*;

/// Reviewed exceptions, each with its reason. Keep this list short: every
/// entry is a site the rules cannot see into.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "delegation",
        "src/transport/http/client.rs",
        "build",
        "hands previous().len() to transport's own decider evaluate_redirect_for, \
         whose count is pinned by transport/http/tests/origin_checks.rs (evaluate_redirect_hop_cap_stops)",
    ),
    (
        "delegation",
        "src/key_server/oidc_jwks_cache.rs",
        "with_remote_proxy",
        "the loopback client's redirect closure errors on every hop; the remote client in the same fn uses remote_redirect_policy, which calls hop_budget_spent",
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
        let _ = writeln!(msg, "{} {}::{}", e.rule, e.file, e.func);
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
        "custom-match-wildcard-only",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| match redirect_decision(a.previous().len(), a.url().as_str()) { _ => a.follow() }); }",
    );
    check_reported(
        "custom-match-ident-binding-only",
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| match redirect_decision(a.previous().len(), a.url().as_str()) { decided => { let _ = decided; a.follow() } }); }",
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
    check_reported(
        "if-branch-replaces-builder-with-variable",
        "fn f(c: bool) { let n = Client::builder(); let mut b = Client::builder().redirect(Policy::none()); if c { b = n; } b.build(); }",
    );
    check_reported(
        "if-branch-replaces-builder-with-builder-expr",
        "fn f(c: bool, d: std::time::Duration) { let loose = Client::builder(); let mut b = Client::builder().redirect(Policy::none()); if c { b = loose.timeout(d); } b.build(); }",
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
        "fn f() { let _ = reqwest::redirect::Policy::custom(|a| match redirect_decision(a.previous().len(), a.url().as_str()) { RedirectDecision::Stop => a.stop(), RedirectDecision::Follow => a.follow(), RedirectDecision::Reject(m) => a.error(m) }); }",
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
