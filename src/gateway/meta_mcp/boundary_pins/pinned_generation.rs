// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost governance (ADR-023) judges a call with the generation its
//! caller context is pinned to, and a context with none judges with the live
//! config's current one. So no production construction of a
//! `MetaMcpCallerContext` may write `generation: None`: every site names the
//! generation it means (the compiler already refuses an omitted field).
//!
//! A stdio message is pinned when its line is read, so the stdio dispatch
//! judges it with that line's generation and never re-reads the live config:
//! a reload landing mid-message would otherwise judge the policy and the
//! budgets of one message under two configs.
//!
//! Syntax scan, per struct expression whose path ends in `MetaMcpCallerContext`.
//! A context built through an alias or a differently named type is missed, as
//! in the other pins.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Why `expr`, a `MetaMcpCallerContext` literal, does not pin a generation.
fn unpinned(expr: &syn::ExprStruct) -> Option<&'static str> {
    if expr.path.segments.last()?.ident != "MetaMcpCallerContext" || expr.rest.is_some() {
        return None;
    }
    let field = expr
        .fields
        .iter()
        .find(|f| matches!(&f.member, syn::Member::Named(name) if name == "generation"))?;
    match &field.expr {
        syn::Expr::Path(path) if path.path.is_ident("None") => Some("generation: None"),
        _ => None,
    }
}

#[derive(Default)]
struct Sites(Vec<String>);

impl Sink for Sites {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let syn::Expr::Struct(literal) = expr
            && let Some(why) = unpinned(literal)
        {
            let func = at.func.as_deref().unwrap_or("<module>");
            self.0.push(format!("{}:{func}: {why}", at.file));
        }
    }
}

/// No production caller context is built without a pinned generation.
#[test]
fn g1_no_production_caller_context_is_unpinned() {
    let mut sites = Sites::default();
    walk(crate_root(), &ROOTS, &mut sites).expect("the walk reads every module");
    sites.0.sort();
    assert!(
        sites.0.is_empty(),
        "a production caller context passes no generation:\n{}",
        sites.0.join("\n")
    );
}

/// The scan flags `generation: None` and nothing else.
#[test]
fn g2_the_scan_flags_a_none_generation_only() {
    let flagged = |src: &str| {
        let expr: syn::ExprStruct = syn::parse_str(src).expect("a struct literal");
        unpinned(&expr).is_some()
    };
    assert!(flagged("MetaMcpCallerContext { era, generation: None }"));
    assert!(flagged(
        "meta_mcp::MetaMcpCallerContext { generation: None, era }"
    ));
    assert!(!flagged(
        "MetaMcpCallerContext { era, generation: Some(g) }"
    ));
    assert!(!flagged(
        "MetaMcpCallerContext { era, generation: live.as_deref() }"
    ));
    assert!(!flagged("Other { generation: None }"));
}

/// The file the stdio messages are dispatched from.
const STDIO_DISPATCH: &str = "src/gateway/server/stdio_dispatch.rs";

/// Calls of `.live_config()` in the stdio dispatch file.
#[derive(Default)]
struct LiveReads(Vec<String>);

impl Sink for LiveReads {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let syn::Expr::MethodCall(call) = expr
            && call.method == "live_config"
            && at.file.ends_with(STDIO_DISPATCH)
        {
            let func = at.func.as_deref().unwrap_or("<module>");
            self.0.push(format!("{}:{func}", at.file));
        }
    }
}

/// The stdio dispatch reads no live config: the generation a message is
/// judged with is its line's, or, for a line that carries none, the one the
/// line's helper resolves once.
#[test]
fn g3_stdio_dispatch_reads_the_generation_from_the_message_line() {
    let mut reads = LiveReads::default();
    walk(crate_root(), &ROOTS, &mut reads).expect("the walk reads every module");
    reads.0.sort();
    // The helper's own read: a scan that missed the file would find none.
    assert!(!reads.0.is_empty(), "the scan reached {STDIO_DISPATCH}");
    assert!(
        reads
            .0
            .iter()
            .all(|site| site.ends_with(":message_generation")),
        "stdio dispatch re-reads the live config outside `message_generation`:\n{}",
        reads.0.join("\n")
    );
}
