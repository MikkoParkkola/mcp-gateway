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
//! The relay witness on a catalogue read takes the generation its
//! `CatalogueCaller` carries; outside tests its `CatalogueGeneration` has
//! only the pinned case, so the compiler refuses a fallback, and the scan
//! below still flags a `generation: None` written there.
//!
//! Syntax scan, per struct expression whose path ends in `MetaMcpCallerContext`
//! or `CatalogueCaller`.
//! A context built through an alias or a differently named type is missed, as
//! in the other pins.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// The struct literals that carry a request's pinned generation.
const PINNED_TYPES: [&str; 2] = ["MetaMcpCallerContext", "CatalogueCaller"];

/// Why `expr`, a literal of a [`PINNED_TYPES`] type, does not pin a generation.
fn unpinned(expr: &syn::ExprStruct) -> Option<&'static str> {
    let ident = &expr.path.segments.last()?.ident;
    if !PINNED_TYPES.iter().any(|t| ident == t) || expr.rest.is_some() {
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

/// No production caller context or catalogue caller is built without a
/// pinned generation.
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
    assert!(flagged("relay::CatalogueCaller { key, generation: None }"));
    assert!(!flagged(
        "CatalogueCaller { key, generation: line.pinned() }"
    ));
    assert!(!flagged("Other { generation: None }"));
}

/// The file the stdio messages are dispatched from.
const STDIO_DISPATCH: &str = "src/gateway/server/stdio_dispatch.rs";
/// The file holding `message_generation`, the one sanctioned live read.
const STDIO_SINGLE: &str = "src/gateway/server/stdio_single.rs";

/// In the stdio dispatch and entry files: every `.live_config()` call
/// outside `message_generation`, how many times the dispatch calls that
/// helper, and how many live reads the helper itself makes.
#[derive(Default)]
struct StdioReads {
    live: Vec<String>,
    helper_calls: usize,
    helper_reads: usize,
}

impl Sink for StdioReads {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let dispatch = at.file.ends_with(STDIO_DISPATCH);
        if !dispatch && !at.file.ends_with(STDIO_SINGLE) {
            return;
        }
        let func = at.func.as_deref().unwrap_or("<module>");
        match expr {
            syn::Expr::MethodCall(call) if call.method == "live_config" => {
                if !dispatch && func == "message_generation" {
                    self.helper_reads += 1;
                } else {
                    self.live.push(format!("{}:{func}", at.file));
                }
            }
            syn::Expr::Call(call)
                if dispatch
                    && matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|s| s.ident == "message_generation")) =>
            {
                self.helper_calls += 1;
            }
            _ => {}
        }
    }
}

/// The stdio dispatch and entry files read no live config except inside
/// `stdio_single::message_generation`, which both of the dispatch's caller
/// contexts call to take the message's generation.
#[test]
fn g3_stdio_dispatch_reads_the_generation_from_the_message_line() {
    let mut reads = StdioReads::default();
    walk(crate_root(), &ROOTS, &mut reads).expect("the walk reads every module");
    reads.live.sort();
    assert!(
        reads.live.is_empty(),
        "stdio re-reads the live config outside message_generation:\n{}",
        reads.live.join("\n")
    );
    // Also proves the scan reached the file.
    assert_eq!(
        reads.helper_calls, 2,
        "both caller contexts take the message's generation"
    );
    assert_eq!(reads.helper_reads, 1, "the helper's one sanctioned read");
}
