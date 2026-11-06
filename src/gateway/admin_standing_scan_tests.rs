// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every production reader of a caller's admin standing, inventoried: the
//! raw `admin` flag, the role mapping's admin answers and the
//! `CallerStanding` constructors. A gateway-wide power reads `Gateway`; admin
//! breadth inside a backend scope reads `InScope` too. A new reader fails the
//! scan until it is listed here with the standing it reads.

/// (needle, file, count, the standing it reads).
const ADMIN_READERS: &[(&str, &str, usize, &str)] = &[
    (
        ".admin",
        "src/config/features/api_key.rs",
        1,
        "the key config Debug field",
    ),
    (
        "resolve_role(",
        "src/control_plane/role_mapping.rs",
        10,
        "the role mapping itself",
    ),
    (
        ".admin",
        "src/events/operational_source.rs",
        2,
        "Gateway: the key config through authz::admin_standing, and its result",
    ),
    (
        ".admin",
        "src/events/rpc.rs",
        1,
        "Gateway: set from CallerStanding::of_client",
    ),
    (
        ".admin",
        "src/gateway/auth_caller.rs",
        1,
        "the accessor: AuthenticatedClient::admin_standing",
    ),
    (
        ".admin",
        "src/gateway/auth_api_key.rs",
        1,
        "the resolved key Debug field",
    ),
    (
        ".admin",
        "src/gateway/auth_bootstrap.rs",
        1,
        "whether any admin credential is configured; no caller standing",
    ),
    (
        ".admin",
        "src/gateway/auth_live.rs",
        1,
        "sets a key-server client flag from the role mapping",
    ),
    (
        "grants_admin(",
        "src/gateway/auth_live.rs",
        1,
        "the key-server admission",
    ),
    (
        ".admin",
        "src/gateway/auth_resolved.rs",
        4,
        "key config into the client, the load warning, session liveness through authz::admin_standing",
    ),
    (".admin", "src/gateway/authz.rs", 1, "BackendGrant::for_ui"),
    (
        ".admin",
        "src/gateway/meta_mcp/call_dispatch.rs",
        4,
        "AdminStanding context reads: meta-tools, stats and profile are Gateway",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/call_dispatch.rs",
        1,
        "the meta-tool gate",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/caller_context.rs",
        2,
        "AdminStanding passed through",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/admin.rs",
        3,
        "Gateway: the cost report admin views",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/chokepoint.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/errors.rs",
        1,
        "Gateway: the revive hint",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/invoke/errors.rs",
        1,
        "the revive hint",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/gate.rs",
        2,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/invoke/policy.rs",
        1,
        "InScope: the admin-only capability rule, after the backend check",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/signing.rs",
        1,
        "Gateway: the signing admin bypass",
    ),
    (
        "CallerStanding::of(",
        "src/gateway/meta_mcp/signing.rs",
        1,
        "the signing admin bypass",
    ),
    (
        ".admin",
        "src/gateway/meta_mcp/visibility.rs",
        3,
        "InScope: the admin-only capability rule; Gateway: the CallerStanding conversion",
    ),
    (
        "CallerStanding::of_client(",
        "src/gateway/router/authorization.rs",
        2,
        "the tools/call and tools/list gates",
    ),
    (
        "grants_admin(",
        "src/gateway/router/authorization_owned.rs",
        1,
        "a key-server task re-judged under the current mapping",
    ),
    (
        ".admin",
        "src/gateway/router/handlers/tasks.rs",
        3,
        "AdminStanding passed through",
    ),
    (
        "CallerStanding::of_client(",
        "src/gateway/router/handlers.rs",
        2,
        "events listing and catalogue standing",
    ),
    (
        ".admin",
        "src/gateway/task_service/execution/context.rs",
        1,
        "AdminStanding passed through",
    ),
    (
        "resolve_role(",
        "src/gateway/ui/activity/access.rs",
        1,
        "Activity breadth by role, bounded by the scope",
    ),
    (
        "resolve_role(",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "the control-plane actor, capped at Auditor when scoped",
    ),
    (
        ".admin",
        "src/gateway/ui/keys.rs",
        1,
        "the key listing shows the config flag",
    ),
    (
        ".admin",
        "src/gateway/ui/stream/conn.rs",
        1,
        "Gateway: set from ui::is_admin",
    ),
    (
        ".admin",
        "src/gateway/ui/stream/sent.rs",
        2,
        "Gateway: set from ui::is_admin",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/handlers.rs",
        1,
        "the embedder's unscoped tools/list, no request caller",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/list_paging_e2e.rs",
        3,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/search_disclosure_e2e_discovery.rs",
        4,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/search_disclosure_e2e_guide.rs",
        6,
        "a cfg(test) module the file-name filter does not see",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/spec_preview.rs",
        7,
        "its cfg(test) rows",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/meta_mcp/visibility.rs",
        2,
        "InvokeScope::unscoped: the operator's view at a given standing",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/router/authorization.rs",
        1,
        "CallerStanding::of: Admin only from Gateway",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/router/handlers.rs",
        1,
        "events listing: of_client compared with Admin",
    ),
    (
        "CallerStanding::Admin",
        "src/gateway/server/mod.rs",
        1,
        "stdio: the spawning client is the operator",
    ),
    (
        "is_gateway_admin",
        "src/gateway/router/backend_handlers/costs.rs",
        1,
        "Gateway: /api/costs",
    ),
    (
        "is_gateway_admin",
        "src/gateway/router/handlers/health.rs",
        1,
        "Gateway: /health backend detail",
    ),
    (
        "is_gateway_admin",
        "src/gateway/ui/guard.rs",
        2,
        "Gateway: AdminSplit and the dashboard link mint",
    ),
    (
        "is_gateway_admin",
        "src/gateway/ui/mod.rs",
        1,
        "Gateway: ui::is_admin",
    ),
    (
        "admin_standing",
        "src/events/operational_source.rs",
        1,
        "Gateway: operator event standing from the key config",
    ),
    (
        "admin_standing",
        "src/gateway/auth_caller.rs",
        2,
        "the accessor and is_gateway_admin",
    ),
    (
        "admin_standing",
        "src/gateway/auth_resolved.rs",
        2,
        "InScope: the load warning; Gateway: session liveness",
    ),
    (
        "admin_standing",
        "src/gateway/router/authorization.rs",
        1,
        "CallerStanding::of_client",
    ),
    (
        "admin_standing",
        "src/gateway/router/authorization_owned.rs",
        4,
        "task re-judgement: any step down refuses",
    ),
    (
        "admin_standing",
        "src/gateway/router/backend_handlers/direct_permit.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_intake_run.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_tools_call/route_stage.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/dispatch_tools_call.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers/tasks.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/handlers.rs",
        3,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/view_judge.rs",
        1,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/router/watch_poll.rs",
        2,
        "context construction: the standing as is",
    ),
    (
        "admin_standing",
        "src/gateway/ui/activity/access.rs",
        1,
        "InScope: Activity breadth, bounded by within",
    ),
    (
        "admin_standing",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "Gateway: Admin; InScope: Auditor",
    ),
    (
        "is_gateway()",
        "src/gateway/meta_mcp/call_dispatch.rs",
        3,
        "Gateway: stats and the profile tools",
    ),
    (
        "is_admin(",
        "src/gateway/ui/guard.rs",
        1,
        "Gateway: the Admin rows",
    ),
    (
        "is_admin(",
        "src/gateway/ui/mod.rs",
        1,
        "its definition and the auth facts",
    ),
    (
        "is_admin(",
        "src/gateway/ui/status.rs",
        1,
        "Gateway: the full status view",
    ),
    (
        "is_admin(",
        "src/gateway/ui/stream/mod.rs",
        2,
        "Gateway: the stream's reload kind and full view",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/activity/access.rs",
        1,
        "the scope that bounds Activity breadth",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/control_plane/mutations.rs",
        1,
        "the actor cap: a scoped Admin identity is Auditor",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/control_plane/snapshot.rs",
        1,
        "the snapshot scope",
    ),
    (
        "::for_ui(",
        "src/gateway/ui/status.rs",
        1,
        "the status scope beside the Gateway check",
    ),
    (
        "{ admin, .. }",
        "src/gateway/meta_mcp/boundary_pins/key_field_rows.rs",
        1,
        "none: an exhaustive field list (no `..`) on ApiKeyConfig::default(), the value discarded",
    ),
];

/// The key for a struct pattern that binds an `admin` field, with or without a
/// rest (`..`): the name is kept from the text finder, so the inventory reads
/// as before.
const DESTRUCTURED: &str = "{ admin, .. }";

/// Whether `path`, relative to the crate, is test-only source.
fn test_only(path: &std::path::Path) -> bool {
    path.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        let stem = part.strip_suffix(".rs").unwrap_or(&part);
        stem == "tests"
            || stem.ends_with("_tests")
            || stem.starts_with("test_")
            || stem.ends_with("_test")
            || stem.contains("fixture")
    })
}

fn production_sources(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) {
    for entry in std::fs::read_dir(dir).expect("src reads") {
        let path = entry.expect("a directory entry").path();
        if test_only(path.strip_prefix(root).expect("under the crate")) {
            continue;
        }
        if path.is_dir() {
            production_sources(root, &path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

// ─── The finder: readers by syntax, not text ───────────────────────────────

/// A monitored name, as the inventory keys it, and the shape that reads it.
#[derive(Clone, Copy)]
enum Shape {
    /// A path ending in these segments, wherever it appears (expression,
    /// pattern, function reference): `is_gateway_admin`, `admin_standing`,
    /// `CallerStanding::Admin`.
    Path(&'static [&'static str]),
    /// A call of a path ending in these segments, or a method call of the
    /// last one: `is_admin(`, `resolve_role(`, `CallerStanding::of(`.
    Call(&'static [&'static str]),
    /// A call of a path of at least two segments ending in this one: `::for_ui(`.
    QualifiedCall(&'static str),
    /// A method call with no arguments: `is_gateway()`.
    NullaryMethod(&'static str),
}

const SHAPES: &[(&str, Shape)] = &[
    ("resolve_role(", Shape::Call(&["resolve_role"])),
    ("grants_admin(", Shape::Call(&["grants_admin"])),
    (
        "CallerStanding::of(",
        Shape::Call(&["CallerStanding", "of"]),
    ),
    (
        "CallerStanding::of_client(",
        Shape::Call(&["CallerStanding", "of_client"]),
    ),
    (
        "CallerStanding::Admin",
        Shape::Path(&["CallerStanding", "Admin"]),
    ),
    ("is_gateway_admin", Shape::Path(&["is_gateway_admin"])),
    ("admin_standing", Shape::Path(&["admin_standing"])),
    ("is_gateway()", Shape::NullaryMethod("is_gateway")),
    ("is_admin(", Shape::Call(&["is_admin"])),
    ("::for_ui(", Shape::QualifiedCall("for_ui")),
];

/// An identifier as written, with any `r#` removed: `r#admin` is `admin`.
fn plain(ident: &syn::Ident) -> String {
    use syn::ext::IdentExt;
    ident.unraw().to_string()
}

/// The file's `use` bindings: each local name with every full path it may
/// stand for, and the paths globbed into scope. File-wide: a binding in one
/// module is applied everywhere in the file, which can only add matches.
#[derive(Default)]
struct Aliases {
    named: std::collections::BTreeMap<String, Vec<Vec<String>>>,
    globs: Vec<Vec<String>>,
}

impl Aliases {
    fn of(file: &syn::File) -> Self {
        struct Uses(Vec<(Vec<String>, Option<String>)>);
        impl<'ast> syn::visit::Visit<'ast> for Uses {
            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                crate::gateway::syn_scan_support::bindings(
                    &item.tree,
                    &mut Vec::new(),
                    &mut self.0,
                );
            }
        }
        let mut uses = Uses(Vec::new());
        syn::visit::Visit::visit_file(&mut uses, file);
        let unraw = |s: &str| s.strip_prefix("r#").unwrap_or(s).to_owned();
        let mut aliases = Self::default();
        for (full, local) in uses.0 {
            let full: Vec<String> = full.iter().map(|s| unraw(s)).collect();
            match local {
                Some(local) => aliases.named.entry(unraw(&local)).or_default().push(full),
                None => aliases.globs.push(full),
            }
        }
        aliases
    }

    /// Every reading of `segments`: as written, through each binding of its
    /// first segment, and, for a single bare name, as a member of each glob.
    fn readings(&self, segments: &[String]) -> Vec<Vec<String>> {
        let mut out = vec![segments.to_vec()];
        if let Some((first, rest)) = segments.split_first() {
            for full in self.named.get(first).into_iter().flatten() {
                out.push(full.iter().chain(rest).cloned().collect());
            }
            if rest.is_empty() {
                for glob in &self.globs {
                    out.push(glob.iter().chain(std::iter::once(first)).cloned().collect());
                }
            }
        }
        out
    }
}

fn ends_with(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len()
        && path[path.len() - tail.len()..]
            .iter()
            .zip(tail)
            .all(|(a, b)| a == b)
}

fn segments(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| plain(&s.ident)).collect()
}

/// Counts per inventory key in one file. `in_macro` marks syntax recovered
/// from a macro or attribute body, where a base-less struct expression may be
/// a pattern written in expression position and so counts as one.
struct Finder<'a> {
    aliases: &'a Aliases,
    counts: std::collections::BTreeMap<&'static str, usize>,
    in_macro: bool,
}

impl Finder<'_> {
    fn add(&mut self, key: &'static str) {
        *self.counts.entry(key).or_default() += 1;
    }

    /// One occurrence of a path: each `Path` shape any of its readings ends
    /// with counts once.
    fn path_occurrence(&mut self, segments: &[String]) {
        let readings = self.aliases.readings(segments);
        for (key, shape) in SHAPES {
            if let Shape::Path(tail) = shape
                && readings.iter().any(|r| ends_with(r, tail))
            {
                self.add(*key);
            }
        }
    }

    /// One call of a path: each `Call` or `QualifiedCall` shape counts once.
    fn call_occurrence(&mut self, segments: &[String]) {
        let readings = self.aliases.readings(segments);
        for (key, shape) in SHAPES {
            let hit = match shape {
                Shape::Call(tail) => readings.iter().any(|r| ends_with(r, tail)),
                Shape::QualifiedCall(last) => readings
                    .iter()
                    .any(|r| r.len() >= 2 && r.last().is_some_and(|l| l == last)),
                _ => false,
            };
            if hit {
                self.add(*key);
            }
        }
    }

    /// One method call: by its name alone, as a method has no path to resolve.
    fn method_occurrence(&mut self, method: &str, nullary: bool) {
        for (key, shape) in SHAPES {
            let hit = match shape {
                Shape::Call(tail) => tail.len() == 1 && tail[0] == method,
                Shape::Path(tail) => tail.len() == 1 && tail[0] == method,
                Shape::NullaryMethod(name) => nullary && *name == method,
                Shape::QualifiedCall(_) => false,
            };
            if hit {
                self.add(*key);
            }
        }
    }

    fn binds_admin<'f>(mut members: impl Iterator<Item = &'f syn::Member>) -> bool {
        members.any(|m| matches!(m, syn::Member::Named(ident) if plain(ident) == "admin"))
    }
}

impl<'ast> syn::visit::Visit<'ast> for Finder<'_> {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if matches!(&field.member, syn::Member::Named(ident) if plain(ident) == "admin") {
            self.add(".admin");
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_pat_struct(&mut self, pat: &'ast syn::PatStruct) {
        if Self::binds_admin(pat.fields.iter().map(|f| &f.member)) {
            self.add(DESTRUCTURED);
        }
        syn::visit::visit_pat_struct(self, pat);
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        // A struct literal is a write, except inside a macro body, where a
        // base-less one may be a pattern: counted, failing closed.
        if self.in_macro
            && expr.rest.is_none()
            && Self::binds_admin(expr.fields.iter().map(|f| &f.member))
        {
            self.add(DESTRUCTURED);
        }
        syn::visit::visit_expr_struct(self, expr);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.path_occurrence(&segments(path));
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*call.func {
            self.call_occurrence(&segments(&func.path));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.method_occurrence(&plain(&call.method), call.args.is_empty());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        // A bare name in a pattern may be a variant brought in by `use`.
        if pat.subpat.is_none() && pat.by_ref.is_none() && pat.mutability.is_none() {
            let name = vec![plain(&pat.ident)];
            if self.aliases.readings(&name).len() > 1 {
                self.path_occurrence(&name);
            }
        }
        syn::visit::visit_pat_ident(self, pat);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.visit_path(&mac.path);
        if let Some((expr, pat, guard)) = crate::gateway::syn_scan_support::matches_parts(mac) {
            let was = std::mem::replace(&mut self.in_macro, true);
            self.visit_expr(&expr);
            self.visit_pat(&pat);
            if let Some(guard) = &guard {
                self.visit_expr(guard);
            }
            self.in_macro = was;
        } else {
            macro_body(self, Body::Mac(mac));
        }
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if let syn::Meta::List(list) = &attr.meta {
            macro_body(self, Body::List(list));
        }
    }
}

/// A macro's or an attribute's body, parsed in place, so no token-stream type
/// is named and no dependency is added.
#[derive(Clone, Copy)]
enum Body<'a> {
    Mac(&'a syn::Macro),
    List(&'a syn::MetaList),
}

impl Body<'_> {
    fn parse<T>(self, parser: impl syn::parse::Parser<Output = T>) -> syn::Result<T> {
        match self {
            Self::Mac(mac) => mac.parse_body_with(parser),
            Self::List(list) => list.parse_args_with(parser),
        }
    }
}

/// Visit whatever syntax a macro or attribute body holds, as a macro body:
/// comma-separated expressions, else comma-separated patterns, else, as a last
/// resort, a walk of its tokens.
fn macro_body(finder: &mut Finder<'_>, body: Body<'_>) {
    use syn::visit::Visit;
    let was = std::mem::replace(&mut finder.in_macro, true);
    let exprs =
        body.parse(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated);
    if let Ok(exprs) = exprs {
        for expr in &exprs {
            finder.visit_expr(expr);
        }
    } else if let Ok(pats) = body.parse(|input: syn::parse::ParseStream| {
        syn::punctuated::Punctuated::<syn::Pat, syn::Token![,]>::parse_terminated_with(
            input,
            syn::Pat::parse_multi_with_leading_vert,
        )
    }) {
        for pat in &pats {
            finder.visit_pat(pat);
        }
    } else {
        token_walk(finder, body);
    }
    finder.in_macro = was;
}

/// A token, reduced to what the walk needs, read with syn's parse API.
enum Tok {
    Ident(String),
    Punct(char),
    /// A delimited group: `true` for braces.
    Group(bool, Vec<Tok>),
    Other,
}

fn toks(input: syn::parse::ParseStream) -> syn::Result<Vec<Tok>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if input.peek(syn::token::Brace) {
            let inner;
            syn::braced!(inner in input);
            out.push(Tok::Group(true, toks(&inner)?));
        } else if input.peek(syn::token::Paren) {
            let inner;
            syn::parenthesized!(inner in input);
            out.push(Tok::Group(false, toks(&inner)?));
        } else if input.peek(syn::token::Bracket) {
            let inner;
            syn::bracketed!(inner in input);
            out.push(Tok::Group(false, toks(&inner)?));
        } else {
            out.push(input.step(|cursor| {
                if let Some((ident, rest)) = cursor.ident() {
                    return Ok((Tok::Ident(plain(&ident)), rest));
                }
                if let Some((punct, rest)) = cursor.punct() {
                    return Ok((Tok::Punct(punct.as_char()), rest));
                }
                match cursor.token_tree() {
                    Some((_, rest)) => Ok((Tok::Other, rest)),
                    None => Err(cursor.error("no token")),
                }
            })?);
        }
    }
    Ok(out)
}

/// The last resort, for a body no parser takes: `.admin`, a brace group with
/// an `admin` field (before `,`, before a single `:`, or last), and the
/// monitored names, a multi-segment one only after its own `Segment ::`. Every
/// identifier is compared after unrawing.
fn token_walk(finder: &mut Finder<'_>, body: Body<'_>) {
    if let Ok(trees) = body.parse(toks) {
        walk(finder, &trees);
    }
}

fn walk(finder: &mut Finder<'_>, trees: &[Tok]) {
    fn ident(t: Option<&Tok>) -> Option<&str> {
        match t {
            Some(Tok::Ident(i)) => Some(i.as_str()),
            _ => None,
        }
    }
    let punct = |t: Option<&Tok>, c: char| matches!(t, Some(Tok::Punct(p)) if *p == c);
    let at = |i: usize, back: usize| i.checked_sub(back).and_then(|k| trees.get(k));
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            Tok::Group(brace, inner) => {
                if *brace {
                    let binds = inner.iter().enumerate().any(|(j, t)| {
                        matches!(t, Tok::Ident(n) if n == "admin")
                            && !punct(j.checked_sub(1).and_then(|k| inner.get(k)), '.')
                            && (j + 1 == inner.len()
                                || punct(inner.get(j + 1), ',')
                                || (punct(inner.get(j + 1), ':') && !punct(inner.get(j + 2), ':')))
                    });
                    if binds {
                        finder.add(DESTRUCTURED);
                    }
                }
                walk(finder, inner);
            }
            Tok::Ident(name) => {
                let after_dot = punct(at(i, 1), '.');
                let called = matches!(trees.get(i + 1), Some(Tok::Group(false, _)));
                let empty_call =
                    matches!(trees.get(i + 1), Some(Tok::Group(false, g)) if g.is_empty());
                let qualified = punct(at(i, 1), ':') && punct(at(i, 2), ':');
                // `A :: B`: the segment before this one, if any.
                let before = if qualified { ident(at(i, 3)) } else { None };
                let tail_matches = |tail: &[&str]| match tail {
                    [last] => *last == name.as_str(),
                    [.., prev, last] => *last == name.as_str() && before == Some(*prev),
                    [] => false,
                };
                if after_dot && name == "admin" && !called {
                    finder.add(".admin");
                }
                for (key, shape) in SHAPES {
                    let hit = match shape {
                        Shape::Path(tail) => tail_matches(tail),
                        Shape::Call(tail) => called && tail_matches(tail),
                        Shape::QualifiedCall(last) => called && qualified && *last == name.as_str(),
                        Shape::NullaryMethod(m) => after_dot && empty_call && *m == name.as_str(),
                    };
                    if hit {
                        finder.add(*key);
                    }
                }
            }
            Tok::Punct(_) | Tok::Other => {}
        }
    }
}

/// The key a file that does not parse is found under: no reader can be
/// vouched for in it, so it fails the scan, named.
const UNPARSED: &str = "<does not parse>";
/// The key a file is found under when one local name is bound to two
/// different paths and one of them is monitored.
const CONFLICT: &str = "<conflicting import>";

/// Whether any binding of one local name to two different paths reaches a
/// monitored name: an unrelated pair (a `cfg(unix)` and `cfg(windows)` import
/// of one trait) is not.
fn conflicting(aliases: &Aliases) -> bool {
    aliases.named.values().any(|fulls| {
        let mut distinct = fulls.clone();
        distinct.sort();
        distinct.dedup();
        distinct.len() > 1
            && distinct.iter().any(|full| {
                SHAPES.iter().any(|(_, shape)| match shape {
                    Shape::Path(tail) | Shape::Call(tail) => ends_with(full, tail),
                    Shape::QualifiedCall(last) | Shape::NullaryMethod(last) => {
                        full.last().is_some_and(|l| l == last)
                    }
                })
            })
    })
}

fn found_in(
    files: &[(String, String)],
) -> std::collections::BTreeMap<(&'static str, String), usize> {
    let mut found = std::collections::BTreeMap::new();
    for (name, text) in files {
        let Ok(file) = syn::parse_file(text) else {
            found.insert((UNPARSED, name.clone()), 1);
            continue;
        };
        let aliases = Aliases::of(&file);
        if conflicting(&aliases) {
            found.insert((CONFLICT, name.clone()), 1);
        }
        let mut finder = Finder {
            aliases: &aliases,
            counts: std::collections::BTreeMap::new(),
            in_macro: false,
        };
        syn::visit::Visit::visit_file(&mut finder, &file);
        for (key, n) in finder.counts {
            found.insert((key, name.clone()), n);
        }
    }
    found
}

#[test]
fn every_admin_standing_reader_is_inventoried() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    production_sources(root, &root.join("src"), &mut paths);
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            let name = path
                .strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .replace('\\', "/");
            (
                name,
                std::fs::read_to_string(path).expect("a source file reads"),
            )
        })
        .collect();
    let listed: std::collections::BTreeMap<_, _> = ADMIN_READERS
        .iter()
        .map(|(needle, file, n, _)| ((*needle, (*file).to_owned()), *n))
        .collect();
    assert_eq!(
        found_in(&files),
        listed,
        "an admin standing reader changed: decide whether it reads Gateway or InScope, add a row that fails if it reads the other, then list it"
    );
}

/// The scan's own row: a new raw read of the flag is found, and a read of the
/// accessor is not.
#[test]
fn the_scan_finds_a_new_raw_admin_read() {
    let files = file_of("let a = client.admin; let b = client.admin_standing();");
    assert_eq!(
        found_in(&files).get(&(".admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// The two reads a field-access needle cannot see: a struct pattern that
/// binds the flag (with or without a new name, or ignoring it) and a direct
/// `CallerStanding::Admin`. Struct update syntax is a write and is not found.
#[test]
fn the_scan_finds_a_destructured_read_and_a_direct_admin_standing() {
    let cells = [
        ("let Caller { admin, .. } = client;", 1),
        ("let Caller { name, admin: flag, .. } = client;", 1),
        ("match c { Self { admin: _, .. } => {} }", 1),
        ("Caller { admin: true, ..base }", 0),
    ];
    for (text, want) in cells {
        let files = file_of(text);
        assert_eq!(
            found_in(&files)
                .get(&("{ admin, .. }", "src/new.rs".to_owned()))
                .copied()
                .unwrap_or(0),
            want,
            "{text}"
        );
    }
    let files = file_of("let s = CallerStanding::Admin;");
    assert_eq!(
        found_in(&files).get(&("CallerStanding::Admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// Every accessor that reads a standing is a reader too: each one picks
/// `Gateway` or `InScope`, so each call is inventoried with the one it reads.
#[test]
fn the_scan_finds_every_standing_accessor() {
    for (text, needle) in [
        ("if c.is_gateway_admin() {}", "is_gateway_admin"),
        ("let s = c.admin_standing();", "admin_standing"),
        (
            "client.map_or(None, AuthenticatedClient::admin_standing)",
            "admin_standing",
        ),
        ("if caller.admin.is_gateway() {}", "is_gateway()"),
        ("if is_admin(Some(c)) {}", "is_admin("),
        ("let g = BackendGrant::for_ui(Some(c));", "::for_ui("),
    ] {
        let files = file_of(text);
        assert_eq!(
            found_in(&files).get(&(needle, "src/new.rs".to_owned())),
            Some(&1),
            "{text}"
        );
    }
}

/// A fixture as a source file: wrapped in an item so a parser accepts it.
fn file_of(body: &str) -> Vec<(String, String)> {
    vec![(
        "src/new.rs".to_owned(),
        format!("fn fixture() {{ {body} }}"),
    )]
}

/// How many times `needle` is found in the one fixture file.
fn found(files: &[(String, String)], needle: &'static str) -> usize {
    found_in(files)
        .get(&(needle, "src/new.rs".to_owned()))
        .copied()
        .unwrap_or(0)
}

/// A raw identifier names the same field: `c.r#admin` reads the flag.
#[test]
fn the_scan_finds_a_raw_identifier_read() {
    assert_eq!(found(&file_of("let a = c.r#admin;"), ".admin"), 1);
}

/// A struct pattern that names every field binds the flag as surely as one
/// with `..`, outside a macro and inside one.
#[test]
fn the_scan_finds_a_full_field_pattern() {
    for body in [
        "let Small { admin, name } = s;",
        "let _ = matches!(s, Small { admin, name });",
        "assert_matches!(s, Small { admin, name });",
        "check!(s => Small { name, admin });",
    ] {
        assert_eq!(found(&file_of(body), "{ admin, .. }"), 1, "{body}");
    }
}

/// An accessor imported under another name is still that accessor: each
/// call counts, and the use line itself does not. (The text finder counts the
/// name once, in the use line, so two calls tell the finders apart.)
#[test]
fn the_scan_resolves_a_renamed_accessor() {
    let renamed = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::authz::admin_standing as standing;\n\
         fn fixture() { let _ = standing(true, &[]); let _ = standing(false, &[]); }"
            .to_owned(),
    )];
    assert_eq!(found(&renamed, "admin_standing"), 2);
}

/// Comments, string literals and definitions read nothing.
#[test]
fn the_scan_ignores_comments_strings_and_definitions() {
    let files = vec![(
        "src/new.rs".to_owned(),
        "// c.admin\n/// c.admin\nfn is_gateway_admin() {}\nfn fixture() { let _ = \"c.admin\"; }"
            .to_owned(),
    )];
    assert_eq!(found(&files, ".admin"), 0);
    assert_eq!(found(&files, "is_gateway_admin"), 0);
}

/// A raw identifier in a macro no parser takes, and a bare variant through a
/// glob import or a rename, are each one read. (Two reads through the rename:
/// the text finder counts its use line once.)
#[test]
fn the_scan_finds_readers_in_token_walks_globs_and_renamed_variants() {
    assert_eq!(found(&file_of("check!(s => c.r#admin);"), ".admin"), 1);
    let glob = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::router::authorization::CallerStanding::*;\n\
         fn fixture(s: CallerStanding) { match s { Admin => {} _ => {} } }"
            .to_owned(),
    )];
    assert_eq!(found(&glob, "CallerStanding::Admin"), 1);
    let renamed = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::router::authorization::CallerStanding::Admin as Elevated;\n\
         fn fixture(s: CallerStanding) { match s { Elevated => {} _ => {} }; let _ = matches!(s, Elevated); }"
            .to_owned(),
    )];
    assert_eq!(found(&renamed, "CallerStanding::Admin"), 2);
}

// Guard rows: green on the text finder too, they pin the new finder's handling.

/// An unrelated import under a monitored name does not hide a real call.
#[test]
fn an_unrelated_alias_does_not_hide_a_real_accessor_call() {
    let shadowed = vec![(
        "src/new.rs".to_owned(),
        "mod other { use std::mem::drop as is_admin; }\n\
         fn fixture() { let _ = is_admin(Some(c)); }"
            .to_owned(),
    )];
    assert_eq!(found(&shadowed, "is_admin("), 1);
}

/// A reader in a `matches!` guard is a read.
#[test]
fn the_scan_finds_a_reader_in_a_matches_guard() {
    assert_eq!(
        found(
            &file_of("let _ = matches!(c, Some(x) if x.admin);"),
            ".admin"
        ),
        1
    );
}
