// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every path that hands a backend's notification toward a client passes its
//! transport's scrub first, or ends unread. A new transport, a new sink call,
//! a scrub moved after its sink, or a per-backend route that keeps its
//! notifications fails here.
//!
//! Rules:
//! - Every production `impl Transport for ..` is in [`TRANSPORTS`] with the
//!   routes its notifications take, and each route has an [`EGRESS`] row.
//! - Every call under src/transport, src/a2a or src/backend to a sink entry
//!   (`notification_sink::publish`, or a `deliver` method: the progress
//!   handle's) sits in an [`EGRESS`] row's function.
//! - An `Own` row's function calls one of [`SCRUB_CALLS`] before its first
//!   [`SINK_CALLS`] call. A `By` row's scrubber calls a scrub before its
//!   first call of the row's function, and does call it. A `ParseRow` row is
//!   a `scrubbed` or `scrubbed-by` row of `inbound_parse_sites.tsv`, whose
//!   own pin proves the scrub. A `Discard` row binds `collect`'s
//!   notifications to `_` or a `_`-prefixed name it never reads again.
//!
//! Syntax scan with `syn`, per function body. Its limits, as the parse-site
//! pin's: names, not types; order is source order (a call counts after its
//! arguments), not flow analysis; a `By` hop is one direct call by name; a
//! tap's scrub depends on the needle set its caller passes. The behaviour
//! rows (`secret_echo_notify_tests.rs` and each transport's scrub rows) stay
//! the primary proof.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];
const SCOPES: [&str; 3] = ["src/transport/", "src/a2a/", "src/backend/"];

/// The calls that remove a backend's injected values (as the parse-site pin).
const SCRUB_CALLS: [&str; 6] = [
    "ingress_scrub",
    "scrub_frame",
    "withheld",
    "scrub_note",
    "scrubbed",
    "scrub_answer",
];

/// The calls that hand a notification on (as the parse-site pin).
const SINK_CALLS: [&str; 4] = ["publish", "send", "try_send", "deliver"];

/// The production transports and the routes their notifications take. A2A
/// raises no MCP notification: its replies are task answers, scrubbed as
/// answers (the a2a rows of `inbound_parse_sites.tsv`).
const TRANSPORTS: [(&str, &[&str]); 4] = [
    ("A2aTransport", &[]),
    ("HttpTransport", &["http-stream", "listen"]),
    ("StdioTransport", &["stdio", "listen"]),
    ("WebSocketTransport", &["websocket", "listen"]),
];

/// How a row's notification is shown scrubbed, or unread.
#[derive(Clone, Copy, Debug)]
enum Proof {
    /// The function itself scrubs before its first sink call.
    Own,
    /// This function (file, name) scrubs, then calls the row's function.
    By(&'static str, &'static str),
    /// Its row in `inbound_parse_sites.tsv` proves the scrub.
    ParseRow,
    /// `collect`'s notifications are bound and never read.
    Discard,
}

/// (route, file, function, proof): every function that hands a backend's
/// notification toward a client, or holds the route that drops them.
const EGRESS: [(&str, &str, &str, Proof); 7] = [
    (
        "stdio",
        "src/transport/stdio.rs",
        "capture_notification",
        Proof::By("src/transport/stdio.rs", "handle_response"),
    ),
    (
        "http-stream",
        "src/transport/http/sse_decoder.rs",
        "drain_events",
        Proof::Own,
    ),
    (
        "websocket",
        "src/transport/websocket_progress.rs",
        "route_progress",
        Proof::By("src/transport/websocket.rs", "dispatch_inbound"),
    ),
    (
        "listen",
        "src/transport/upstream_tap.rs",
        "notification_keyed",
        Proof::Own,
    ),
    (
        "listen",
        "src/transport/http/listen.rs",
        "frame",
        Proof::ParseRow,
    ),
    (
        "listen",
        "src/transport/http/listen.rs",
        "unsolicited_frame",
        Proof::ParseRow,
    ),
    (
        "direct",
        "src/gateway/router/backend_handlers/direct_send.rs",
        "send_in_scope",
        Proof::Discard,
    ),
];

/// What one function body does, in source order.
#[derive(Clone, Default)]
struct Body {
    /// Callee names, each after its arguments.
    calls: Vec<String>,
    /// Its sink-entry calls: `publish` (the sink's) or `deliver`.
    entries: Vec<&'static str>,
    /// Names bound to `collect`'s notifications.
    discarded: Vec<String>,
    /// How often each identifier appears outside macros.
    idents: BTreeMap<String, usize>,
    /// Every macro's tokens, as text.
    macros: Vec<String>,
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// `notification_sink::collect(..)`, awaited or not.
fn collects(expr: &syn::Expr) -> bool {
    let expr = match expr {
        syn::Expr::Await(awaited) => awaited.base.as_ref(),
        other => other,
    };
    matches!(expr, syn::Expr::Call(call) if matches!(call.func.as_ref(), syn::Expr::Path(p)
        if segments(&p.path).ends_with(&["notification_sink".to_owned(), "collect".to_owned()])))
}

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        syn::visit::visit_expr_call(self, call);
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let names = segments(&p.path);
            if names.ends_with(&["notification_sink".to_owned(), "publish".to_owned()]) {
                self.entries.push("publish");
            }
            self.calls.extend(names.last().cloned());
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        if call.method == "deliver" {
            self.entries.push("deliver");
        }
        self.calls.push(call.method.to_string());
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        let (syn::Pat::Tuple(pair), Some(init)) = (&local.pat, &local.init) else {
            return;
        };
        if pair.elems.len() == 2 && collects(&init.expr) {
            match &pair.elems[1] {
                syn::Pat::Ident(kept) => self.discarded.push(kept.ident.to_string()),
                syn::Pat::Wild(_) => self.discarded.push("_".to_owned()),
                // Destructured: its parts are read, so it is not discarded.
                _ => self.discarded.push(String::new()),
            }
        }
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        *self.idents.entry(ident.to_string()).or_default() += 1;
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.macros.push(mac.tokens.to_string());
    }
}

impl Body {
    fn of(block: &syn::Block) -> Self {
        let mut body = Self::default();
        body.visit_block(block);
        body
    }

    fn first(&self, names: &[&str]) -> Option<usize> {
        self.calls.iter().position(|c| names.contains(&c.as_str()))
    }

    /// `name` is bound and never read: `_`, or `_`-prefixed, met once and in
    /// no macro.
    fn unread(&self, name: &str) -> bool {
        name == "_"
            || (name.starts_with('_')
                && self.idents.get(name) == Some(&1)
                && !self.macros.iter().any(|tokens| {
                    tokens
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .any(|word| word == name)
                }))
    }
}

/// What the walk found: the production transports, and every function body
/// by file and name (two bodies under one name are both kept, and a rule
/// must hold for each).
#[derive(Clone, Default)]
struct Egress {
    transports: BTreeSet<String>,
    bodies: BTreeMap<(String, String), Vec<Body>>,
}

impl Egress {
    fn function(&mut self, file: &str, func: &str, block: &syn::Block) {
        self.bodies
            .entry((file.to_owned(), func.to_owned()))
            .or_default()
            .push(Body::of(block));
    }

    fn bodies_of(&self, file: &str, func: &str) -> &[Body] {
        self.bodies
            .get(&(file.to_owned(), func.to_owned()))
            .map_or(&[], Vec::as_slice)
    }
}

impl Sink for Egress {
    fn item(&mut self, at: &Place, item: &syn::Item) {
        match item {
            syn::Item::Fn(function) if !test_only(&function.attrs) => {
                self.function(&at.file, &function.sig.ident.to_string(), &function.block);
            }
            syn::Item::Impl(block) if !test_only(&block.attrs) => {
                if let Some((_, path, _)) = &block.trait_
                    && path.segments.last().is_some_and(|s| s.ident == "Transport")
                    && let syn::Type::Path(ty) = block.self_ty.as_ref()
                    && let Some(name) = ty.path.segments.last()
                {
                    self.transports.insert(name.ident.to_string());
                }
                for member in &block.items {
                    if let syn::ImplItem::Fn(method) = member
                        && !test_only(&method.attrs)
                    {
                        self.function(&at.file, &method.sig.ident.to_string(), &method.block);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Whether `parse_rows` lists `file::func` as `scrubbed` or `scrubbed-by`.
fn parse_row_scrubs(parse_rows: &str, file: &str, func: &str) -> bool {
    parse_rows
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .any(|cells| {
            cells.len() >= 5
                && cells[0] == file
                && cells[1] == func
                && matches!(cells[4], "scrubbed" | "scrubbed-by")
        })
}

/// Whether `proof` holds for the row `file::func`.
fn holds(scan: &Egress, parse_rows: &str, file: &str, func: &str, proof: Proof) -> bool {
    let bodies = scan.bodies_of(file, func);
    match proof {
        Proof::Own => bodies.iter().all(|body| {
            matches!((body.first(&SCRUB_CALLS), body.first(&SINK_CALLS)),
                (Some(scrub), Some(sink)) if scrub < sink)
        }),
        Proof::By(by_file, by_func) => {
            let scrubbers = scan.bodies_of(by_file, by_func);
            !scrubbers.is_empty()
                && scrubbers.iter().all(|body| {
                    matches!((body.first(&SCRUB_CALLS), body.first(&[func])),
                        (Some(scrub), Some(call)) if scrub < call)
                })
        }
        Proof::ParseRow => parse_row_scrubs(parse_rows, file, func),
        Proof::Discard => bodies.iter().all(|body| {
            !body.discarded.is_empty() && body.discarded.iter().all(|name| body.unread(name))
        }),
    }
}

fn failure(proof: Proof) -> &'static str {
    match proof {
        Proof::Own => "scrub not before sink",
        Proof::By(..) => "scrubber does not scrub first",
        Proof::ParseRow => "no scrubbing parse row",
        Proof::Discard => "keeps its notifications",
    }
}

/// Every way `scan` departs from the reviewed tables.
fn differences(scan: &Egress, parse_rows: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let listed: BTreeSet<String> = TRANSPORTS.iter().map(|(t, _)| (*t).to_owned()).collect();
    for name in scan.transports.difference(&listed) {
        wrong.push(format!("unlisted transport: {name}"));
    }
    for name in listed.difference(&scan.transports) {
        wrong.push(format!("stale transport: {name}"));
    }
    for (name, routes) in TRANSPORTS {
        for route in routes {
            if !EGRESS.iter().any(|(r, ..)| r == route) {
                wrong.push(format!("route without a row: {name} {route}"));
            }
        }
    }
    for ((file, func), bodies) in &scan.bodies {
        if !SCOPES.iter().any(|scope| file.starts_with(scope)) {
            continue;
        }
        for entry in bodies.iter().flat_map(|body| &body.entries) {
            if !EGRESS
                .iter()
                .any(|(_, f, n, _)| *f == file.as_str() && *n == func.as_str())
            {
                wrong.push(format!("unlisted sink call: {file}::{func} ({entry})"));
            }
        }
    }
    for (route, file, func, proof) in EGRESS {
        if scan.bodies_of(file, func).is_empty() {
            wrong.push(format!("stale row: {route} {file}::{func}"));
        } else if !holds(scan, parse_rows, file, func, proof) {
            wrong.push(format!("{}: {route} {file}::{func}", failure(proof)));
        }
    }
    wrong
}

const PARSE_ROWS: &str = include_str!("inbound_parse_sites.tsv");

/// The crate, walked once for every row here.
fn scanned() -> Egress {
    static SCAN: std::sync::LazyLock<Egress> = std::sync::LazyLock::new(|| {
        let mut scan = Egress::default();
        walk(crate_root(), &ROOTS, &mut scan).expect("the walk reads every module");
        scan
    });
    SCAN.clone()
}

/// `file::func`'s bodies replaced by `block` alone.
fn replaced(mut scan: Egress, file: &str, func: &str, block: &syn::Block) -> Egress {
    scan.bodies
        .insert((file.to_owned(), func.to_owned()), vec![Body::of(block)]);
    scan
}

fn fails_with(scan: &Egress, parse_rows: &str, prefix: &str) -> bool {
    differences(scan, parse_rows)
        .iter()
        .any(|line| line.starts_with(prefix))
}

/// Every notification a backend raises reaches a client only through its
/// transport's scrub, and the per-backend route reads none.
#[test]
fn every_notification_egress_is_scrubbed_or_unread() {
    let wrong = differences(&scanned(), PARSE_ROWS);
    assert!(
        wrong.is_empty(),
        "notification egress differs from the reviewed rows ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The pin's own proof: a new transport and a new sink call fail.
#[test]
fn a_new_transport_or_sink_call_fails() {
    let mut scan = scanned();
    scan.transports.insert("FakeTransport".to_owned());
    assert!(
        fails_with(&scan, PARSE_ROWS, "unlisted transport: FakeTransport"),
        "a new transport passed"
    );
    let mut scan = scanned();
    scan.function(
        "src/transport/fake.rs",
        "fake_publish",
        &syn::parse_quote!({
            crate::transport::notification_sink::publish(vec![note]);
        }),
    );
    assert!(
        fails_with(
            &scan,
            PARSE_ROWS,
            "unlisted sink call: src/transport/fake.rs::fake_publish"
        ),
        "a new sink call passed"
    );
}

/// The pin's own proof: a scrub moved after its sink, a scrubber that no
/// longer scrubs, and a lost parse row each fail.
#[test]
fn a_late_or_lost_scrub_fails() {
    let late = replaced(
        scanned(),
        "src/transport/http/sse_decoder.rs",
        "drain_events",
        &syn::parse_quote!({
            crate::transport::notification_sink::publish(vec![note]);
            let _ = withheld(needles, &mut message);
        }),
    );
    assert!(
        fails_with(&late, PARSE_ROWS, "scrub not before sink: http-stream"),
        "a scrub after its sink passed"
    );
    let unscrubbed = replaced(
        scanned(),
        "src/transport/stdio.rs",
        "handle_response",
        &syn::parse_quote!({
            self.capture_notification(notification, None);
        }),
    );
    assert!(
        fails_with(
            &unscrubbed,
            PARSE_ROWS,
            "scrubber does not scrub first: stdio"
        ),
        "a scrubber without its scrub passed"
    );
    let rows: String = PARSE_ROWS
        .lines()
        .filter(|line| !line.starts_with("src/transport/http/listen.rs\tframe\t"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(
        fails_with(
            &scanned(),
            &rows,
            "no scrubbing parse row: listen src/transport/http/listen.rs::frame"
        ),
        "a lost parse row passed"
    );
}

/// The pin's own proof: a per-backend route that keeps or reads its
/// notifications fails, while one that drops them to `_` passes.
#[test]
fn a_direct_route_that_keeps_its_notifications_fails() {
    const DIRECT: (&str, &str) = (
        "src/gateway/router/backend_handlers/direct_send.rs",
        "send_in_scope",
    );
    let kept: [syn::Block; 2] = [
        syn::parse_quote!({
            let (response, notifications) =
                crate::transport::notification_sink::collect(None, call).await;
            forward(notifications);
        }),
        syn::parse_quote!({
            let (response, _discarded) =
                crate::transport::notification_sink::collect(None, call).await;
            tracing::debug!(?_discarded);
        }),
    ];
    for block in &kept {
        let scan = replaced(scanned(), DIRECT.0, DIRECT.1, block);
        assert!(
            fails_with(&scan, PARSE_ROWS, "keeps its notifications: direct"),
            "a kept notification passed"
        );
    }
    let dropped = replaced(
        scanned(),
        DIRECT.0,
        DIRECT.1,
        &syn::parse_quote!({
            let (response, _) = crate::transport::notification_sink::collect(None, call).await;
        }),
    );
    assert!(
        !fails_with(&dropped, PARSE_ROWS, "keeps its notifications"),
        "a dropped notification failed"
    );
}
