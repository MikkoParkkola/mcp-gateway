// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every path that hands a backend's notification toward a client passes its
//! transport's scrub first, or ends unread. A new transport, a new sink or
//! channel send, a scrub moved after its sink, a scrub helper that stops
//! scrubbing, a needle set replaced by `None`, a second caller of a scrubbed
//! hop, or a per-backend route that keeps its notifications fails here.
//!
//! Rules:
//! - Every production `impl Transport for ..` is in [`TRANSPORTS`]; each one
//!   that raises notifications has its own [`EGRESS`] rows.
//! - A sink entry anywhere in the crate (`notification_sink::publish`), and
//!   in the transport trees (src/transport, src/a2a, src/backend) a bare
//!   `publish(..)`, a `deliver(..)` or a one-argument `send`/`try_send` (a
//!   channel send: a zero-argument `send()` is an outbound HTTP request, a
//!   two-argument one the transport's own request helper), sits in an
//!   [`EGRESS`] row's function or in a `notification_egress.tsv` row saying
//!   why that send carries no backend notification.
//! - `Own`: the function calls a scrub ([`SCRUB_CALLS`]) before its first
//!   sink. `By`: the named scrubber calls a scrub before its first call of
//!   the row's function, and no other function calls it. `MapBy`: the
//!   function sends what a stored map returns; every such map (an
//!   `sse_channel` `Sink { .. }` literal) is built in the named function,
//!   whose body calls a scrub.
//! - Every scrub helper in [`HELPERS`] reaches a needle-set primitive
//!   ([`PRIMITIVES`]) over helper calls, and no scrub call in the transport
//!   trees passes a literal `None` needle set.
//! - The per-backend route ([`DIRECT`]) binds `collect`'s notifications to
//!   `_` or a `_`-prefixed name it never reads again.
//!
//! Syntax scan with `syn`, per function body; a macro body (`select!`,
//! `matches!`) is read from its tokens, a name before parentheses being a
//! call. Its limits: names, not types;
//! order is source order (a call counts after its arguments), so a second
//! sink handing on other, unscrubbed data after a scrub passes (a 4.0.1
//! follow-up closes this by type: the sinks will accept only a
//! `ScrubbedNotification` that only the scrub constructs); a `By` hop is
//! a direct call by name; `Withhold` and `Refuse` outcomes are honoured only
//! as the behaviour rows check. The behaviour rows (the route rows in
//! `secret_echo_notify_tests.rs`, each transport's scrub rows) stay the
//! primary proof; the per-transport mutants show those rows depend on it.

use std::collections::{BTreeMap, BTreeSet};

use syn::visit::Visit;

use super::inbound_parse_sites::{SCRUB_CALLS, SINK_CALLS};
use super::packaged::crate_root;
use super::scan::{Place, Sink, test_only, walk};

const ROOTS: [&str; 1] = ["src/lib.rs"];
const SCOPES: [&str; 3] = ["src/transport/", "src/a2a/", "src/backend/"];

/// The production transports. A2A raises no MCP notification: its replies
/// are task answers, scrubbed as answers (the a2a rows of
/// `inbound_parse_sites.tsv`), so it has no [`EGRESS`] row. The command
/// preview's pipe drops every notification its server sends and hands none
/// toward a client, so it has none either.
const TRANSPORTS: [&str; 5] = [
    "A2aTransport",
    "HttpTransport",
    "PreviewPipe",
    "StdioTransport",
    "WebSocketTransport",
];
const NO_NOTIFICATIONS: [&str; 2] = ["A2aTransport", "PreviewPipe"];

/// The helpers a scrub call may be, and the needle-set primitives each must
/// reach.
const HELPERS: [&str; 4] = ["withheld", "scrub_frame", "scrub_note", "scrubbed"];
const PRIMITIVES: [&str; 4] = [
    "ingress_scrub",
    "scrub_text",
    "scrub_response_with",
    "scrub_answer",
];

/// Calls that take a needle set as an argument besides the scrubs: a
/// literal `None` there skips the scrub.
const NEEDLE_TAKERS: [&str; 1] = ["notification_keyed"];

/// How a row's notification is shown scrubbed.
#[derive(Clone, Copy, Debug)]
enum Proof {
    /// The function itself scrubs before its first sink.
    Own,
    /// This function (file, name) scrubs, then calls the row's function; no
    /// other function calls it.
    By(&'static str, &'static str),
    /// The function sends what a stored map returns; every map is built in
    /// this function (file, name), which scrubs.
    MapBy(&'static str, &'static str),
}

/// (transport, route, file, function, proof): every function that hands a
/// backend's notification toward a client.
const EGRESS: [(&str, &str, &str, &str, Proof); 9] = [
    (
        "StdioTransport",
        "stdio",
        "src/transport/stdio.rs",
        "capture_notification",
        Proof::By("src/transport/stdio.rs", "handle_response"),
    ),
    (
        "StdioTransport",
        "listen",
        "src/transport/upstream_tap.rs",
        "notification_keyed",
        Proof::Own,
    ),
    (
        "HttpTransport",
        "http-stream",
        "src/transport/http/sse_decoder.rs",
        "drain_events",
        Proof::Own,
    ),
    (
        "HttpTransport",
        "listen",
        "src/transport/http/listen.rs",
        "open_session_stream_as",
        Proof::Own,
    ),
    (
        "HttpTransport",
        "listen",
        "src/transport/http/listen.rs",
        "read_stream",
        Proof::Own,
    ),
    (
        "HttpTransport",
        "listen",
        "src/transport/http/listen.rs",
        "read_single",
        Proof::Own,
    ),
    (
        "HttpTransport",
        "listen",
        "src/transport/http/sse_channel.rs",
        "route",
        Proof::MapBy("src/transport/http/sse_listen.rs", "handshake"),
    ),
    (
        "WebSocketTransport",
        "websocket",
        "src/transport/websocket_progress.rs",
        "route_progress",
        Proof::By("src/transport/websocket.rs", "dispatch_inbound"),
    ),
    (
        "WebSocketTransport",
        "listen",
        "src/transport/upstream_tap.rs",
        "notification_keyed",
        Proof::Own,
    ),
];

/// The per-backend route: it collects a call's notifications and drops them.
const DIRECT: (&str, &str) = (
    "src/gateway/router/backend_handlers/direct_send.rs",
    "send_in_scope",
);

/// Where an `sse_channel` map may be built.
const MAP_FILES: &str = "src/transport/http/";

/// The reviewed sends that carry no backend notification.
const SENDS: &str = include_str!("notification_egress.tsv");

/// What one function body does, in source order.
#[derive(Clone, Default)]
struct Body {
    /// Callee names, each after its arguments.
    calls: Vec<String>,
    /// Its sink entries: the kind and the index of the call in `calls`.
    sinks: Vec<(&'static str, usize)>,
    /// Scrub or needle-taking calls given a literal `None`.
    none_needles: Vec<String>,
    /// `Sink { .. }` literals built here whose `map` closure scrubs.
    maps: usize,
    /// `Sink { .. }` literals built here whose `map` does not scrub (or is absent).
    unscrubbed_maps: usize,
    /// `notification_sink::collect(..)` calls.
    collects: usize,
    /// Names bound from a stored map's result (`let`/`if let` over `(map)`).
    map_bound: BTreeSet<String>,
    /// The single plain-name argument of the last channel send, if it had one.
    last_send_arg: Option<String>,
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

fn ends_with(path: &[String], tail: [&str; 2]) -> bool {
    path.len() >= 2 && path[path.len() - 2] == tail[0] && path[path.len() - 1] == tail[1]
}

/// `notification_sink::collect(..)`, awaited or not.
fn collects(expr: &syn::Expr) -> bool {
    let expr = match expr {
        syn::Expr::Await(awaited) => awaited.base.as_ref(),
        other => other,
    };
    matches!(expr, syn::Expr::Call(call) if matches!(call.func.as_ref(), syn::Expr::Path(p)
        if ends_with(&segments(&p.path), ["notification_sink", "collect"])))
}

/// `None`, however qualified (`Option::None`).
fn is_none(arg: &syn::Expr) -> bool {
    matches!(arg, syn::Expr::Path(p)
        if p.qself.is_none() && p.path.segments.last().is_some_and(|s| s.ident == "None"))
}

/// `(x.map)(..)`: a call through a stored `map` closure.
fn is_map_call(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Call(call) if matches!(call.func.as_ref(), syn::Expr::Paren(inner)
        if matches!(inner.expr.as_ref(), syn::Expr::Field(syn::ExprField {
            member: syn::Member::Named(name), ..
        }) if name == "map")))
}

/// Every plain name a pattern binds (`note`, `Some(note)`, `(a, b)`).
fn bound_names(pat: &syn::Pat, into: &mut BTreeSet<String>) {
    match pat {
        syn::Pat::Ident(ident) => {
            into.insert(ident.ident.to_string());
        }
        syn::Pat::TupleStruct(tuple) => tuple.elems.iter().for_each(|p| bound_names(p, into)),
        syn::Pat::Tuple(tuple) => tuple.elems.iter().for_each(|p| bound_names(p, into)),
        _ => {}
    }
}

/// The first closure written inside `expr` (`Box::new(move |data| ..)`).
fn first_closure(expr: &syn::Expr) -> Option<&syn::ExprClosure> {
    struct Find<'a>(Option<&'a syn::ExprClosure>);
    impl<'a> Visit<'a> for Find<'a> {
        fn visit_expr_closure(&mut self, closure: &'a syn::ExprClosure) {
            if self.0.is_none() {
                self.0 = Some(closure);
            }
        }
    }
    let mut find = Find(None);
    find.visit_expr(expr);
    find.0
}

impl Body {
    fn of(block: &syn::Block) -> Self {
        let mut body = Self::default();
        body.visit_block(block);
        body
    }

    fn called<'a>(
        &mut self,
        name: &str,
        args: impl Iterator<Item = &'a syn::Expr>,
        sink: Option<&'static str>,
    ) {
        if (SCRUB_CALLS.contains(&name) || NEEDLE_TAKERS.contains(&name))
            && args.into_iter().any(is_none)
        {
            self.none_needles.push(name.to_owned());
        }
        self.calls.push(name.to_owned());
        if let Some(kind) = sink {
            self.sinks.push((kind, self.calls.len() - 1));
            self.last_send_arg = None;
        }
    }

    fn first_scrub(&self) -> Option<usize> {
        self.calls
            .iter()
            .position(|c| SCRUB_CALLS.contains(&c.as_str()))
    }

    fn first_call(&self, name: &str) -> Option<usize> {
        self.calls.iter().position(|c| c == name)
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

impl<'ast> Visit<'ast> for Body {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        syn::visit::visit_expr_call(self, call);
        let field = match call.func.as_ref() {
            syn::Expr::Paren(inner) => inner.expr.as_ref(),
            other => other,
        };
        // `(open.map)(data)`: a call through a stored closure, recorded as
        // `(map)` so an ordinary `.map(..)` method never stands in for it.
        if let syn::Expr::Field(syn::ExprField {
            member: syn::Member::Named(name),
            ..
        }) = field
        {
            self.called(&format!("({name})"), call.args.iter(), None);
            return;
        }
        if let syn::Expr::Path(p) = call.func.as_ref() {
            let path = segments(&p.path);
            let qualified = path.len() >= 2;
            let last = path.last().map(String::as_str);
            let sink = if ends_with(&path, ["notification_sink", "publish"]) {
                Some("publish")
            } else if path.len() == 1 && path[0] == "publish" {
                Some("bare publish")
            // `DeliveryHandle::deliver(&handle, note)`, `Sender::send(&tx, note)`:
            // the receiver is the first argument.
            } else if qualified && last == Some("deliver") {
                Some("deliver")
            } else if qualified && matches!(last, Some("send" | "try_send")) && call.args.len() == 2
            {
                Some("send")
            } else {
                None
            };
            if ends_with(&path, ["notification_sink", "collect"]) {
                self.collects += 1;
            }
            if let Some(name) = path.last() {
                self.called(name, call.args.iter(), sink);
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        let name = call.method.to_string();
        let sink = match name.as_str() {
            sink if !SINK_CALLS.contains(&sink) => None,
            // One argument: a channel send. None is an outbound HTTP request,
            // two the transport's own request helper.
            "send" | "try_send" => (call.args.len() == 1).then_some("send"),
            "deliver" => Some("deliver"),
            // A method named `publish` is not the sink's free function.
            _ => None,
        };
        self.called(&name, call.args.iter(), sink);
        if sink.is_some() {
            self.last_send_arg = match call.args.first() {
                Some(syn::Expr::Path(p)) if call.args.len() == 1 => {
                    p.path.get_ident().map(ToString::to_string)
                }
                _ => None,
            };
        }
    }

    fn visit_expr_let(&mut self, expr: &'ast syn::ExprLet) {
        syn::visit::visit_expr_let(self, expr);
        if is_map_call(&expr.expr) {
            bound_names(&expr.pat, &mut self.map_bound);
        }
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        syn::visit::visit_expr_struct(self, expr);
        if expr.path.segments.last().is_some_and(|s| s.ident == "Sink") {
            // The scrub must sit inside the stored closure's own body: not
            // beside the literal, and not in the field's initializer around it.
            let scrubs = expr.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(name) if name == "map")
                    && first_closure(&field.expr).is_some_and(|closure| {
                        let mut map = Self::default();
                        map.visit_expr(&closure.body);
                        map.first_scrub().is_some()
                    })
            });
            if scrubs {
                self.maps += 1;
            } else {
                self.unscrubbed_maps += 1;
            }
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        if let Some(init) = &local.init
            && is_map_call(&init.expr)
        {
            bound_names(&local.pat, &mut self.map_bound);
        }
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
        self.macro_calls(mac.tokens.clone());
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

fn in_scopes(file: &str) -> bool {
    SCOPES.iter().any(|scope| file.starts_with(scope))
}

fn is_egress(file: &str, func: &str) -> bool {
    EGRESS
        .iter()
        .any(|(_, _, f, n, _)| *f == file && *n == func)
}

/// The reviewed sends: (file, function) to its class.
fn send_rows(text: &str) -> BTreeMap<(String, String), String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            (cells.len() == 4).then(|| {
                (
                    (cells[0].to_owned(), cells[1].to_owned()),
                    cells[2].to_owned(),
                )
            })
        })
        .collect()
}

/// Whether `proof` holds for the row `file::func`.
fn holds(scan: &Egress, file: &str, func: &str, proof: Proof) -> bool {
    let bodies = scan.bodies_of(file, func);
    match proof {
        Proof::Own => bodies.iter().all(|body| {
            matches!((body.first_scrub(), body.sinks.first()),
                (Some(scrub), Some((_, sink))) if scrub < *sink)
        }),
        Proof::By(by_file, by_func) => {
            let scrubbers = scan.bodies_of(by_file, by_func);
            let scrubs_first = !scrubbers.is_empty()
                && scrubbers.iter().all(|body| {
                    matches!((body.first_scrub(), body.first_call(func)),
                        (Some(scrub), Some(call)) if scrub < call)
                });
            let sole_caller = scan.bodies.iter().all(|((f, n), found)| {
                (f == by_file && n == by_func)
                    || found.iter().all(|body| body.first_call(func).is_none())
            });
            scrubs_first && sole_caller
        }
        Proof::MapBy(by_file, by_func) => {
            // The row's function sends what its stored map returned: it calls
            // `(map)`, its last send comes after that call, and that send's
            // argument is a name bound from the map's result. (It also answers
            // waiting calls, so an earlier send is allowed.)
            let applies_map = bodies.iter().all(|body| {
                matches!((body.first_call("(map)"), body.sinks.last()),
                    (Some(map), Some((_, sink))) if map < *sink)
                    // The last send hands on a name bound from the map's result.
                    && body
                        .last_send_arg
                        .as_ref()
                        .is_some_and(|arg| body.map_bound.contains(arg))
            });
            let builders = scan.bodies_of(by_file, by_func);
            let builds_scrubbing_maps = !builders.is_empty()
                && builders
                    .iter()
                    .all(|body| body.maps > 0 && body.unscrubbed_maps == 0);
            let sole_builder = scan.bodies.iter().all(|((f, n), found)| {
                !f.starts_with(MAP_FILES)
                    || (f == by_file && n == by_func)
                    || found
                        .iter()
                        .all(|body| body.maps == 0 && body.unscrubbed_maps == 0)
            });
            applies_map && builds_scrubbing_maps && sole_builder
        }
    }
}

fn failure(proof: Proof) -> &'static str {
    match proof {
        Proof::Own => "scrub not before sink",
        Proof::By(..) => "scrubber does not scrub first, or another function calls it",
        Proof::MapBy(..) => "stored map unapplied, unscrubbed or built elsewhere",
    }
}

/// Each helper whose every body under src/transport reaches a primitive,
/// directly or over other helpers that do.
fn helper_failures(scan: &Egress) -> Vec<String> {
    let mut reaching: BTreeSet<&str> = BTreeSet::new();
    loop {
        let before = reaching.len();
        for helper in HELPERS {
            let bodies: Vec<&Body> = scan
                .bodies
                .iter()
                .filter(|((f, n), _)| n == helper && f.starts_with("src/transport/"))
                .flat_map(|(_, found)| found)
                .collect();
            if !bodies.is_empty()
                && bodies.iter().all(|body| {
                    body.calls
                        .iter()
                        .any(|c| PRIMITIVES.contains(&c.as_str()) || reaching.contains(c.as_str()))
                })
            {
                reaching.insert(helper);
            }
        }
        if reaching.len() == before {
            break;
        }
    }
    HELPERS
        .iter()
        .filter(|helper| !reaching.contains(*helper))
        .map(|helper| format!("helper reaches no needle scrub: {helper}"))
        .collect()
}

/// Every way `scan` departs from the reviewed tables.
fn differences(scan: &Egress, sends: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let listed: BTreeSet<String> = TRANSPORTS.iter().map(|t| (*t).to_owned()).collect();
    for name in scan.transports.difference(&listed) {
        wrong.push(format!("unlisted transport: {name}"));
    }
    for name in listed.difference(&scan.transports) {
        wrong.push(format!("stale transport: {name}"));
    }
    for name in TRANSPORTS {
        if !NO_NOTIFICATIONS.contains(&name) && !EGRESS.iter().any(|(t, ..)| *t == name) {
            wrong.push(format!("transport without a row: {name}"));
        }
    }
    let rows = send_rows(sends);
    for ((file, func), bodies) in &scan.bodies {
        for (kind, _) in bodies.iter().flat_map(|body| &body.sinks) {
            let counted = *kind == "publish" || in_scopes(file);
            let reviewed = *kind == "send" && rows.contains_key(&(file.clone(), func.clone()));
            if counted && !reviewed && !is_egress(file, func) {
                wrong.push(format!("unlisted sink: {file}::{func} ({kind})"));
            }
        }
        if in_scopes(file) {
            for name in bodies.iter().flat_map(|body| &body.none_needles) {
                wrong.push(format!("a None needle set: {file}::{func} ({name})"));
            }
        }
    }
    for (file, func) in rows.keys() {
        let sends_here = scan
            .bodies_of(file, func)
            .iter()
            .any(|body| body.sinks.iter().any(|(kind, _)| *kind == "send"));
        if !sends_here || is_egress(file, func) {
            wrong.push(format!("stale send row: {file}::{func}"));
        }
    }
    for (transport, route, file, func, proof) in EGRESS {
        if scan.bodies_of(file, func).is_empty() {
            wrong.push(format!("stale row: {transport} {route} {file}::{func}"));
        } else if !holds(scan, file, func, proof) {
            wrong.push(format!(
                "{}: {transport} {route} {file}::{func}",
                failure(proof)
            ));
        }
    }
    wrong.extend(helper_failures(scan));
    let direct = scan.bodies_of(DIRECT.0, DIRECT.1);
    // Every `collect` call's notifications are bound unread: one kept beside a
    // dropped one fails.
    let dropped = !direct.is_empty()
        && direct.iter().all(|body| {
            body.collects > 0
                && body.discarded.len() == body.collects
                && body.discarded.iter().all(|name| body.unread(name))
        });
    if !dropped {
        wrong.push(format!(
            "keeps its notifications: {}::{}",
            DIRECT.0, DIRECT.1
        ));
    }
    wrong
}

/// The crate, walked once for every row here.
fn scanned() -> Egress {
    static SCAN: std::sync::LazyLock<Egress> = std::sync::LazyLock::new(|| {
        let mut scan = Egress::default();
        walk(crate_root(), &ROOTS, &mut scan).expect("the walk reads every module");
        scan
    });
    SCAN.clone()
}

/// The scan with one more body under `file::func`.
fn with(mut scan: Egress, file: &str, func: &str, block: &syn::Block) -> Egress {
    scan.function(file, func, block);
    scan
}

/// The scan with `file::func`'s bodies replaced by `block` alone.
fn replaced(mut scan: Egress, file: &str, func: &str, block: &syn::Block) -> Egress {
    scan.bodies
        .insert((file.to_owned(), func.to_owned()), vec![Body::of(block)]);
    scan
}

fn fails_with(scan: &Egress, prefix: &str) -> bool {
    differences(scan, SENDS)
        .iter()
        .any(|line| line.starts_with(prefix))
}

/// Every notification a backend raises reaches a client only through its
/// transport's scrub, and the per-backend route reads none.
#[test]
fn every_notification_egress_is_scrubbed_or_unread() {
    let wrong = differences(&scanned(), SENDS);
    assert!(
        wrong.is_empty(),
        "notification egress differs from the reviewed rows ({}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[path = "notification_egress_macros.rs"]
mod macros;
#[path = "notification_egress_proof_tests.rs"]
mod proofs;
