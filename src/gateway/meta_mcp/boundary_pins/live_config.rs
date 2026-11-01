// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The firewall judges with the startup policy only when the `MetaMcp` has
//! no live config (`Firewall::policy_under`). These rows hold that to
//! handlers no production server builds: every production construction of a
//! `MetaMcp` is listed, and each serving mode sets the live config before
//! its first request. The firewall's public `check_request` and
//! `check_response` judge by the rules it was built from, which is current
//! for a program embedding it but not for the gateway: no gateway file
//! calls them. Every production authorizer's `generation()` answer is
//! listed too: a request authorizer that answered `None` would send its
//! checks to the generation published at check time.
//!
//! Syntax scan over the production module graph (`scan::walk`), per
//! expression and item. A call reached through an alias is missed, as in the
//! other pins.

use std::collections::BTreeSet;

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];

/// Every production construction of a `MetaMcp`: `build_meta_mcp`, which
/// the serving modes below call. A new one is a server mode these rows do
/// not yet cover.
const PRODUCTION_CONSTRUCTIONS: [&str; 1] = ["src/gateway/server/build_meta.rs"];

/// Each serving mode: its file, and the call that starts taking requests,
/// which `set_live_config` must precede.
const SERVING_MODES: [(&str, Event); 2] = [
    ("src/gateway/server/run.rs", Event::Serve),
    ("src/gateway/server/stdio_loop.rs", Event::FirstLine),
];

/// Every production `ToolAuthorizer` and its `generation()` body, described
/// by `describe`. A request authorizer answers the request's generation; the
/// operator judges no request, so it answers `None` and its checks take the
/// generation published now.
const AUTHORIZER_GENERATIONS: [(&str, &str); 4] = [
    ("RouterAuthorizer", "Some(self.generation)"),
    (
        "HostAuthorizer",
        "match self { inner.generation(), inner.generation() }",
    ),
    ("ToolPolicyAuthorizer", "self.generation"),
    ("Operator", "None"),
];

/// Every production `StdioLine` and its `generation()` body.
const STDIO_LINE_GENERATIONS: [(&str, &str); 1] = [("Arc<Generation>", "Some(self)")];

/// What a serving mode does, in the order a pin wants it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Build,
    SetLiveConfig,
    Serve,
    FirstLine,
}

/// `Type::func` when `path` ends in those two segments.
fn ends_with(path: &syn::Path, ty: &str, func: &str) -> bool {
    let mut segments = path.segments.iter().rev();
    segments.next().is_some_and(|s| s.ident == func)
        && segments.next().is_some_and(|s| s.ident == ty)
}

/// A type's last name, with its first generic type argument: `Arc<Generation>`.
fn type_name(ty: &syn::Type) -> String {
    let syn::Type::Path(path) = ty else {
        return "<type>".to_owned();
    };
    let Some(last) = path.path.segments.last() else {
        return "<type>".to_owned();
    };
    let argument = match &last.arguments {
        syn::PathArguments::AngleBracketed(args) => args.args.iter().find_map(|arg| match arg {
            syn::GenericArgument::Type(inner) => Some(format!("<{}>", type_name(inner))),
            _ => None,
        }),
        _ => None,
    };
    format!("{}{}", last.ident, argument.unwrap_or_default())
}

/// A `generation()` body in a short form the tables can name.
fn describe(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(|| "<path>".to_owned(), |s| s.ident.to_string()),
        syn::Expr::Call(call) => format!(
            "{}({})",
            describe(&call.func),
            call.args
                .iter()
                .map(describe)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => format!("{}.{name}", describe(&field.base)),
            syn::Member::Unnamed(index) => format!("{}.{}", describe(&field.base), index.index),
        },
        syn::Expr::MethodCall(call) => format!("{}.{}()", describe(&call.receiver), call.method),
        syn::Expr::Match(m) => format!(
            "match {} {{ {} }}",
            describe(&m.expr),
            m.arms
                .iter()
                .map(|arm| describe(&arm.body))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        syn::Expr::Block(block) => block_tail(&block.block),
        syn::Expr::Paren(paren) => describe(&paren.expr),
        _ => "<expr>".to_owned(),
    }
}

/// The tail expression of a block, described; a block with statements is
/// described as such so a table never matches it by accident.
fn block_tail(block: &syn::Block) -> String {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expr, None)] => describe(expr),
        _ => "<block>".to_owned(),
    }
}

#[derive(Default)]
struct Found {
    /// Files that construct a `MetaMcp`.
    constructions: BTreeSet<String>,
    /// Files that call `build_meta_mcp()`.
    builders: BTreeSet<String>,
    /// Each serving-mode event, in walk (source) order: (file, event).
    events: Vec<(String, Event)>,
    /// Files other than the firewall's own that call its startup-rules entry points.
    startup_rules: BTreeSet<String>,
    /// `impl ToolAuthorizer for T`: (T, its `generation()` body).
    authorizers: BTreeSet<(String, String)>,
    /// `impl StdioLine for T`: (T, its `generation()` body).
    stdio_lines: BTreeSet<(String, String)>,
    /// Production `ToolPolicyAuthorizer { .. }` literals: (file, `generation` field).
    stdio_authorizers: Vec<(String, String)>,
}

impl Found {
    /// A macro body is not parsed as expressions (`tokio::select!` holds the
    /// stdio loop's first read): its tokens name the first-line read.
    fn macro_tokens(&mut self, at: &Place, mac: &syn::Macro) {
        if mac.tokens.to_string().contains("next_line") {
            self.events.push((at.file.clone(), Event::FirstLine));
        }
    }
}

impl Sink for Found {
    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let syn::Stmt::Macro(m) = stmt {
            self.macro_tokens(at, &m.mac);
        }
    }

    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        if let syn::Expr::Macro(m) = expr {
            self.macro_tokens(at, &m.mac);
        }
        match expr {
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path) = call.func.as_ref() {
                    let path = &path.path;
                    if ["new", "with_features", "with_features_and_clock"]
                        .iter()
                        .any(|func| ends_with(path, "MetaMcp", func))
                    {
                        self.constructions.insert(at.file.clone());
                    }
                    if ends_with(path, "listener", "serve") {
                        self.events.push((at.file.clone(), Event::Serve));
                    }
                }
            }
            syn::Expr::MethodCall(call) => match call.method.to_string().as_str() {
                "build_meta_mcp" => {
                    self.builders.insert(at.file.clone());
                    self.events.push((at.file.clone(), Event::Build));
                }
                "set_live_config" => self.events.push((at.file.clone(), Event::SetLiveConfig)),
                "next_line" => self.events.push((at.file.clone(), Event::FirstLine)),
                "check_request" | "check_response" if at.file != "src/security/firewall/mod.rs" => {
                    self.startup_rules.insert(at.file.clone());
                }
                _ => {}
            },
            syn::Expr::Struct(literal)
                if literal
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "ToolPolicyAuthorizer") =>
            {
                let generation = literal.fields.iter().find_map(|field| match &field.member {
                    syn::Member::Named(name) if name == "generation" => Some(describe(&field.expr)),
                    _ => None,
                });
                self.stdio_authorizers.push((
                    at.file.clone(),
                    generation.unwrap_or_else(|| "<missing>".to_owned()),
                ));
            }
            _ => {}
        }
    }

    fn item(&mut self, _at: &Place, item: &syn::Item) {
        let syn::Item::Impl(block) = item else {
            return;
        };
        let Some((_, trait_path, _)) = &block.trait_ else {
            return;
        };
        let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        let target = match trait_name.as_str() {
            "ToolAuthorizer" => &mut self.authorizers,
            "StdioLine" => &mut self.stdio_lines,
            _ => return,
        };
        let body = block.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(f) if f.sig.ident == "generation" => Some(block_tail(&f.block)),
            _ => None,
        });
        target.insert((
            type_name(&block.self_ty),
            body.unwrap_or_else(|| "<missing>".to_owned()),
        ));
    }
}

fn found() -> Found {
    let mut found = Found::default();
    walk(crate_root(), &ROOTS, &mut found).expect("the walk reads every module");
    found
}

fn listed(rows: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    rows.iter()
        .map(|(name, body)| ((*name).to_owned(), (*body).to_owned()))
        .collect()
}

#[test]
fn every_production_meta_mcp_construction_is_listed() {
    let found = found();
    let listed: BTreeSet<String> = PRODUCTION_CONSTRUCTIONS.map(str::to_owned).into();
    assert_eq!(
        found.constructions, listed,
        "a production MetaMcp construction must set the live config before its first \
         request; list it with its serving mode here"
    );
}

#[test]
fn build_meta_mcp_is_called_only_by_the_serving_modes() {
    let found = found();
    let modes: BTreeSet<String> = SERVING_MODES.map(|(file, _)| file.to_owned()).into();
    assert_eq!(
        found.builders, modes,
        "a new serving mode must be listed in SERVING_MODES"
    );
}

#[test]
fn every_serving_mode_sets_the_live_config_before_its_first_request() {
    let found = found();
    for (file, serves) in SERVING_MODES {
        let order: Vec<Event> = found
            .events
            .iter()
            .filter(|(at, _)| at == file)
            .map(|(_, event)| *event)
            .collect();
        let first = |event: Event| order.iter().position(|e| *e == event);
        let (built, set, served) = (
            first(Event::Build),
            first(Event::SetLiveConfig),
            first(serves),
        );
        assert!(
            built.is_some() && set.is_some() && served.is_some(),
            "{file}: builds, sets and serves: {order:?}"
        );
        assert!(
            built < set && set < served,
            "{file}: set_live_config must come after build_meta_mcp and before {serves:?}: {order:?}"
        );
    }
}

#[test]
fn no_production_file_calls_the_startup_rules_entry_points() {
    let found = found();
    assert!(
        found.startup_rules.is_empty(),
        "these judge by the startup rules; a gateway check takes the request's generation: {:?}",
        found.startup_rules
    );
}

#[test]
fn every_production_authorizer_answers_its_listed_generation() {
    let found = found();
    assert_eq!(
        found.authorizers,
        listed(&AUTHORIZER_GENERATIONS),
        "a new or changed authorizer must say which generation its checks judge under"
    );
    assert_eq!(
        found.stdio_lines,
        listed(&STDIO_LINE_GENERATIONS),
        "a production stdio line carries its generation"
    );
}

/// The stdio authorizer's generation is a field: no production construction
/// leaves it `None`.
#[test]
fn no_production_stdio_authorizer_is_built_without_a_generation() {
    let found = found();
    assert!(
        !found.stdio_authorizers.is_empty(),
        "premise: the scan finds the stdio authorizer's constructions"
    );
    let empty: Vec<&(String, String)> = found
        .stdio_authorizers
        .iter()
        .filter(|(_, generation)| generation == "None" || generation == "<missing>")
        .collect();
    assert!(
        empty.is_empty(),
        "stdio authorizers built with no generation: {empty:?}"
    );
}
