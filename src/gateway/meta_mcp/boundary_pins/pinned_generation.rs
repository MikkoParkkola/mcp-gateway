// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cost governance (ADR-023) judges a call with the generation its
//! caller context is pinned to, and a context with none judges with the live
//! config's current one. So no production construction of a
//! `MetaMcpCallerContext` may write `generation: None`: every site names the
//! generation it means (the compiler already refuses an omitted field).
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
