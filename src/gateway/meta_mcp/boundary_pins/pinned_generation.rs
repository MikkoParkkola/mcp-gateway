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

/// The struct literals that carry a request's pinned generation.
const PINNED_TYPES: [&str; 1] = ["MetaMcpCallerContext"];

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

/// The stdio dispatch and entry files: a message is judged under the
/// generation its line was pinned to, so neither reads the live config.
const STDIO_FILES: [&str; 2] = [
    "src/gateway/server/stdio_dispatch.rs",
    "src/gateway/server/stdio_single.rs",
];

/// The stdio dispatch file, where every caller context and authorizer of a
/// message takes the line's pinned generation.
const STDIO_DISPATCH: &str = STDIO_FILES[0];

/// Reads of the line's pinned generation (`generation.generation()`) in the
/// dispatch: the authorizers of `dispatch_relay_scoped` and
/// `dispatch_tools_call`, the delivery record of `dispatch_relay_scoped`,
/// and the two caller contexts'.
const LINE_READS: usize = 5;

/// In the stdio dispatch and entry files: every live-config read, in method
/// or fully-qualified form; which files the walk reached; the dispatch's
/// reads of the line's generation; and each caller context's generation.
#[derive(Default)]
struct StdioReads {
    live: Vec<String>,
    reached: std::collections::BTreeSet<&'static str>,
    line_reads: usize,
    callers: Vec<(String, bool)>,
}

/// Whether `expr` is the path `name`.
fn is_path(expr: &syn::Expr, name: &str) -> bool {
    matches!(expr, syn::Expr::Path(p) if p.path.is_ident(name))
}

impl Sink for StdioReads {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        let Some(file) = STDIO_FILES.iter().find(|f| at.file.ends_with(**f)) else {
            return;
        };
        self.reached.insert(file);
        let func = at.func.as_deref().unwrap_or("<module>");
        let last_segment = |call: &syn::ExprCall| match &*call.func {
            syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        match expr {
            syn::Expr::MethodCall(call) if call.method == "live_config" => {
                self.live.push(format!("{}:{func}", at.file));
            }
            syn::Expr::MethodCall(call)
                if *file == STDIO_DISPATCH
                    && call.method == "generation"
                    && is_path(&call.receiver, "generation") =>
            {
                self.line_reads += 1;
            }
            syn::Expr::Call(call) => match last_segment(call).as_deref() {
                Some("live_config") => self.live.push(format!("{}:{func}", at.file)),
                Some("build_stdio_caller_context") if *file == STDIO_DISPATCH => {
                    // The context's `(record key, generation)` argument.
                    let pinned = call.args.last().is_some_and(|arg| {
                        matches!(arg, syn::Expr::Tuple(t)
                            if t.elems.last().is_some_and(|g| is_path(g, "pinned")))
                    });
                    self.callers.push((func.to_owned(), pinned));
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// The stdio dispatch and entry files read no live config at all, and every
/// message takes the generation its line was pinned to when it was read: each
/// caller context is given the line's `pinned` generation, and the dispatch
/// reads the line's generation at each of its sites.
#[test]
fn g3_stdio_dispatch_reads_the_generation_from_the_message_line() {
    let mut reads = StdioReads::default();
    walk(crate_root(), &ROOTS, &mut reads).expect("the walk reads every module");
    // Also proves the scan reached both files.
    assert_eq!(
        reads.reached.len(),
        STDIO_FILES.len(),
        "the walk did not reach every stdio file: {:?}",
        reads.reached
    );
    reads.live.sort();
    assert!(
        reads.live.is_empty(),
        "stdio dispatch reads the live config:\n{}",
        reads.live.join("\n")
    );
    assert_eq!(
        reads.callers.len(),
        2,
        "the dispatch builds two caller contexts: {:?}",
        reads.callers
    );
    assert!(
        reads.callers.iter().all(|(_, pinned)| *pinned),
        "a stdio caller context is not given the line's pinned generation: {:?}",
        reads.callers
    );
    assert_eq!(
        reads.line_reads, LINE_READS,
        "the dispatch's reads of the line's generation changed"
    );
}

/// The scan rejects a live-config read in either stdio file, in method or
/// fully-qualified form, and accepts the same call elsewhere.
#[test]
fn g4_the_stdio_scan_rejects_a_live_read_in_either_file() {
    let reads_of = |file: &str, src: &str| {
        let expr: syn::Expr = syn::parse_str(src).expect("an expression");
        let mut reads = StdioReads::default();
        let place = Place {
            file: format!("/repo/{file}"),
            func: Some("route".to_owned()),
        };
        reads.expr(&place, &expr);
        reads.live.len()
    };
    for file in STDIO_FILES {
        for src in ["meta_mcp.live_config()", "MetaMcp::live_config(meta_mcp)"] {
            assert_eq!(reads_of(file, src), 1, "{file}: `{src}` was not rejected");
        }
    }
    assert_eq!(
        reads_of("src/gateway/router/handlers.rs", "meta_mcp.live_config()"),
        0,
        "a read outside the stdio files was rejected"
    );
}
