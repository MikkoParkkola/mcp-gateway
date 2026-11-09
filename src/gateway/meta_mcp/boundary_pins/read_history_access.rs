// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-tenant read verdict is made in one place: every producer reaches
//! the process's read history through the outbound judge, which decides
//! whether to judge at all (`judge::judging`). A second path to the history
//! could judge, or skip judging, on a switch of its own.
//!
//! Syntax scan of the production nodes (test-only code is skipped by cfg
//! evaluation, never by filename): a method call `.reads()` (the firewall's
//! accessor to the history) outside the judge is a finding, and so is a
//! `.reserve(..)` call in a production file that names the history
//! (`ReadHistory` or `tenant_reads::`) outside the judge and the history's
//! own module. The positive control requires the judge's own `.reads()`
//! call, so the scan cannot pass by seeing nothing.
//!
//! Threat model. The scan catches a second path to the history written in
//! ordinary production code, or in a `macro_rules!` whose body names the
//! call: every macro that splices a metavariable after `.` or `::`, or calls
//! one, is refused unless listed in `SPLICES` with its body's fingerprint.
//! A macro that assembles the call from token fragments
//! (`$f $dot $name $args`) or stores a path argument and calls it later
//! (`let f = $m; f($v)`) is out of model: the call exists only after
//! expansion, which a syntax scan of the source cannot see. The compiler can,
//! and does: the first line of defence is a type-level restriction.
//! `Firewall::reads` and `ReadHistory::reserve` take a read token that only
//! the judge can build (`outbound::ReadsToken`), so any other caller, however
//! a macro assembles it, fails to compile; a must-fail probe build pins that
//! in CI. This scan stays as the second line of defence.

use super::packaged::crate_root;
use super::scan::{Place, Sink, walk};

const ROOTS: [&str; 3] = ["src/lib.rs", "src/main.rs", "src/bin/provenance-eval.rs"];
const JUDGE: &str = "src/gateway/outbound/judge.rs";
const HISTORY: &str = "src/security/tenant_reads.rs";

#[derive(Default)]
struct Access {
    /// Files with a production `.reads()` call, one entry per call.
    readers: Vec<String>,
    /// Files with a production `.reserve(..)` call, one entry per call.
    reservers: Vec<String>,
    /// `macro_rules!` definitions that splice a metavariable into a member or
    /// path position, call one, or call a repetition: a caller could pass
    /// `reads` and no text would say so. By file, macro name and the
    /// fingerprint of the whole body; refused unless listed in [`SPLICES`].
    splices: Vec<(String, String, u64)>,
}

/// The splicing macros the crate is known to define: file, macro, the
/// fingerprint of the body as reviewed ([`body_fingerprint`]), and why it
/// cannot reach the read history. The real walk must find exactly these, so a
/// new splice, any change to a listed body and a stale entry all fail. A new
/// fingerprint is accepted only after re-checking that reason against the new
/// body.
const SPLICES: [(&str, &str, u64, &str); 7] = [
    (
        "src/config_reload/diff.rs",
        "sections",
        0x7d7c_30a8_74df_c9cd,
        "only reads fields, named at its call sites in diff.rs, of two config values; no config field is the read history",
    ),
    (
        "src/duration_bound.rs",
        "delta",
        0xc340_7321_5edc_4345,
        "$try comes only from its own arms (try_weeks ..) and is called on chrono::TimeDelta, never on a caller's value",
    ),
    (
        "src/gateway/meta_mcp/dispatch_names.rs",
        "meta_arms",
        0x6bb1_f53b_93a3_9354,
        "splices variant names into the MetaArm enum it defines; it calls nothing",
    ),
    (
        "src/personal_accounts/commit.rs",
        "boundary",
        0x7368_4427_9eab_5355,
        "splices a Boundary variant into a test-only fault hook; it calls nothing on a caller's value",
    ),
    (
        "src/security/firewall/collusion_seam_excuse.rs",
        "count",
        0xc0a1_a90d_4d8f_1107,
        "splices a field of the test-only thread-local counters; it reads no firewall",
    ),
    (
        "src/yaml/de/mod.rs",
        "typed",
        0x2346_1eff_ee83_d4fe,
        "calls the named method on the deserializer `$de.follow()` returns, never on a firewall",
    ),
    (
        "src/yaml/ser.rs",
        "refuse",
        0x46f1_6387_20d2_0b3a,
        "defines refusing Serializer methods by name; it calls none of them",
    ),
];

/// A macro body with spacing and `r#` removed, as the splice check reads it.
fn macro_text(mac: &syn::Macro) -> String {
    mac.tokens
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("r#", "")
}

/// A 64-bit FNV-1a hash of the body's [`macro_text`]: a listed macro is
/// pinned to its reviewed body, so a changed receiver fails.
fn body_fingerprint(mac: &syn::Macro) -> u64 {
    macro_text(mac).bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The splices in a `macro_rules!` body, in order: a metavariable or a
/// repetition right after `.` or `::` (`$f.$m`, `<$t>::$m`, `$f$(.$m)*`),
/// and a metavariable or a repetition that is called (`$m(`, `$m::<`,
/// `$($m)+(`). `$crate` is not one. A member or path splice is reported
/// whatever follows it: a fail-closed rule, so no spelling of the call
/// escapes it.
fn call_splices(mac: &syn::Macro) -> Vec<String> {
    let text = macro_text(mac);
    let bytes = text.as_bytes();
    let ident_end = |from: usize| {
        text[from..]
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .map_or(text.len(), |e| e + from)
    };
    // Past the `$( .. )` group opening at `open`, its separator and operator.
    let group_end = |open: usize| {
        let mut depth = 0usize;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let mut end = (i + 1).min(bytes.len());
        let op = |at: usize| at < bytes.len() && matches!(bytes[at], b'*' | b'+' | b'?');
        if !op(end) && end < bytes.len() {
            // A separator: one whole character, which may be several bytes.
            end += text[end..].chars().next().map_or(1, char::len_utf8);
        }
        if op(end) {
            end += 1;
        }
        end
    };
    let called = |at: usize| text[at..].starts_with('(') || text[at..].starts_with("::<");
    let mut found = Vec::new();
    for (i, _) in text.match_indices('$') {
        let after = i + 1;
        if text[after..].starts_with("crate") && ident_end(after) == after + 5 {
            continue;
        }
        let end = if text[after..].starts_with('(') {
            group_end(after)
        } else {
            ident_end(after)
        };
        if end == after {
            continue;
        }
        let lead = if text[..i].ends_with('.') {
            "."
        } else if text[..i].ends_with("::") {
            "::"
        } else {
            ""
        };
        if !lead.is_empty() || called(end) {
            found.push(format!("{lead}{}", &text[i..end]));
        }
    }
    found
}

impl Access {
    /// A macro's arguments are tokens, not parsed expressions, so they are
    /// matched as text with the spacing and every `r#` removed: a path that
    /// ends in `::reads` / `::reserve` (not followed by more of a name), and a
    /// method call `.reads(` / `.reserve(`, with or without a turbofish. A
    /// bare `.reads` is a field, not counted.
    fn tokens(&mut self, at: &Place, mac: &syn::Macro) {
        let text: String = mac
            .tokens
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .replace("r#", "");
        let count = |name: &str| {
            let path = format!("::{name}");
            let paths = text
                .match_indices(&path)
                .filter(|(i, _)| {
                    !text[i + path.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
                })
                .count();
            let calls = text.matches(&format!(".{name}(")).count()
                + text.matches(&format!(".{name}::<")).count();
            paths + calls
        };
        for _ in 0..count("reads") {
            self.readers.push(at.file.clone());
        }
        for _ in 0..count("reserve") {
            self.reservers.push(at.file.clone());
        }
    }

    fn found(&mut self, at: &Place, name: &str) {
        match name {
            "reads" => self.readers.push(at.file.clone()),
            "reserve" => self.reservers.push(at.file.clone()),
            _ => {}
        }
    }
}

impl Sink for Access {
    fn expr(&mut self, at: &Place, expr: &syn::Expr) {
        use syn::ext::IdentExt;
        match expr {
            syn::Expr::MethodCall(call) => {
                let name = call.method.unraw().to_string();
                // With or without arguments: the judge's own call carries the
                // read token, so an argument count is no reason to look away.
                if name == "reserve" || name == "reads" {
                    self.found(at, &name);
                }
            }
            // A path taken anywhere, called or not: `Firewall::reads(&f)`,
            // `let read = Firewall::reads;`, `(Firewall::reads)(f)`, `<T>::reads`.
            // A call's callee reaches the sink as its own expression, so a call
            // counts once. One segment is a local or free name: `use` cannot
            // import an associated function.
            syn::Expr::Path(path) if path.qself.is_some() || path.path.segments.len() >= 2 => {
                if let Some(last) = path.path.segments.last() {
                    self.found(at, &last.ident.unraw().to_string());
                }
            }
            syn::Expr::Macro(mac) => self.tokens(at, &mac.mac),
            _ => {}
        }
    }

    fn stmt(&mut self, at: &Place, stmt: &syn::Stmt) {
        if let syn::Stmt::Macro(mac) = stmt {
            self.tokens(at, &mac.mac);
        }
    }

    fn item(&mut self, at: &Place, item: &syn::Item) {
        if let syn::Item::Macro(mac) = item {
            if mac.mac.path.is_ident("macro_rules") && !call_splices(&mac.mac).is_empty() {
                let name = mac
                    .ident
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string);
                self.splices
                    .push((at.file.clone(), name, body_fingerprint(&mac.mac)));
            }
            self.tokens(at, &mac.mac);
        }
    }
}

/// Whether the production part of `file` names the read history.
fn names_the_history(file: &str) -> bool {
    let text = std::fs::read_to_string(crate_root().join(file)).expect("read source");
    let code = crate::test_source_text::production_text(&text);
    code.contains("ReadHistory") || code.contains("tenant_reads::")
}

#[test]
fn the_read_history_is_reached_from_the_judge_alone() {
    let mut access = Access::default();
    walk(crate_root(), &ROOTS, &mut access).expect("the crate walks");
    let allowed: Vec<(String, String, u64)> = SPLICES
        .iter()
        .map(|(file, name, print, _)| ((*file).to_owned(), (*name).to_owned(), *print))
        .collect();
    let mut found = access.splices.clone();
    found.sort();
    assert_eq!(
        found, allowed,
        "a macro_rules! that calls a method named by a metavariable could reach the read history \
         unseen: refuse it, or list it in SPLICES with why it cannot (a stale entry fails too)"
    );
    assert_eq!(
        access.readers,
        [JUDGE],
        "only the judge calls `.reads()` on a firewall (and the walk saw its call)"
    );
    assert!(
        access.reservers.iter().any(|file| file == JUDGE),
        "the walk saw the judge's own `.reserve(..)` (positive control)"
    );
    let mut reservers: Vec<&String> = access
        .reservers
        .iter()
        .filter(|file| *file != JUDGE && *file != HISTORY && names_the_history(file))
        .collect();
    reservers.dedup();
    assert!(
        reservers.is_empty(),
        "reserves on the read history outside the judge: {reservers:?}"
    );
}

/// Every way a `macro_rules!` body can splice a name into a call is reported,
/// each splice exactly: a member or path splice whatever follows it, a raw
/// name, a repetition (around the name or around the member), a bare callee,
/// a parenthesised or deferred path call. A fixed call and `$crate` are not.
#[test]
fn a_macro_that_splices_a_call_is_reported() {
    for (source, want) in [
        ("($f:expr, $m:ident) => { $f.$m() }", &[".$m"][..]),
        ("($f:expr, $m:ident) => { $f.$m::<u8>() }", &[".$m"]),
        ("($f:expr, $r#m:ident) => { $f.$r#m() }", &[".$m"]),
        ("($f:expr, $($m:ident)+) => { $f.$($m)+() }", &[".$($m)+"]),
        (
            "($f:expr, $($m:ident)*) => { $f$(.$m)*() }",
            &["$(.$m)*", ".$m"],
        ),
        ("($t:ty, $m:ident, $v:expr) => { $t::$m($v) }", &["::$m"]),
        ("($t:ty, $m:ident, $v:expr) => { <$t>::$m($v) }", &["::$m"]),
        (
            "($t:ty, $m:ident, $v:expr) => { (<$t>::$m)($v) }",
            &["::$m"],
        ),
        (
            "($t:ty, $m:ident, $v:expr) => { { let f = <$t>::$m; f($v) } }",
            &["::$m"],
        ),
        ("($m:path, $v:expr) => { $m($v) }", &["$m"]),
        ("($f:expr, $x:ident) => { $f.$x }", &[".$x"]),
        ("($v:ident) => { Kind::$v }", &["::$v"]),
        ("($f:expr) => { $f.len() }", &[]),
        ("($f:expr) => { $crate::helpers::run($f) }", &[]),
        ("($($x:ident)é*) => { $($x)é*() }", &["$($x)é*"]),
    ] {
        let item: syn::Item =
            syn::parse_str(&format!("macro_rules! m {{ {source}; }}")).expect("a macro_rules item");
        let syn::Item::Macro(mac) = item else {
            unreachable!("parsed as a macro");
        };
        assert_eq!(call_splices(&mac.mac), want, "{source}");
    }
}

/// A listed macro is pinned to its body: another receiver in its call changes
/// the fingerprint, so the inventory fails; spacing does not change it.
#[test]
fn a_changed_macro_body_changes_its_fingerprint() {
    let print = |body: &str| {
        let item: syn::Item =
            syn::parse_str(&format!("macro_rules! delta {{ {body}; }}")).expect("an item");
        let syn::Item::Macro(mac) = item else {
            unreachable!("parsed as a macro");
        };
        body_fingerprint(&mac.mac)
    };
    let real = print("($try:ident, $n:expr) => { ::chrono::TimeDelta::$try($n) }");
    assert_eq!(
        real,
        print("($try:ident,$n:expr)=>{::chrono::TimeDelta::$try($n)}"),
        "spacing is not part of the body"
    );
    assert_ne!(
        real,
        print("($try:ident, $n:expr) => { ::other::Firewall::$try($n) }"),
        "another receiver is another body"
    );
}

/// What the walk does with an expression (scan.rs `visit_expr`): the sink
/// sees it, then every expression inside it.
struct Mirror<'a>(&'a mut Access, Place);

impl<'ast> syn::visit::Visit<'ast> for Mirror<'_> {
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        self.0.expr(&self.1, expr);
        syn::visit::visit_expr(self, expr);
    }
}

/// The sink sees the history however a reader is spelled: a method or path
/// call, raw or not, a path taken as a value or called in parentheses, a
/// turbofish, inside a macro's arguments or not. Each fixture counts exactly
/// once; a field named `reads`, a longer name and a one-segment call count
/// nothing.
#[test]
fn macro_wrapped_and_path_calls_are_seen() {
    for (source, readers, reservers) in [
        ("assert!(firewall.reads().len() > 0)", 1, 0),
        // The token-bearing call: arguments do not hide a reader.
        ("firewall.reads(&t)", 1, 0),
        ("firewall.reads(&ReadsToken(Cell::new(())))", 1, 0),
        ("m!(f.reads(&t))", 1, 0),
        ("Firewall::reads(&firewall)", 1, 0),
        ("ReadHistory::reserve(&history, key)", 0, 1),
        ("debug_assert!(history.reserve(key).is_ok())", 0, 1),
        ("firewall.r#reads()", 1, 0),
        ("Firewall::r#reads(&f)", 1, 0),
        ("{ let read = Firewall::reads; read(f) }", 1, 0),
        ("(Firewall::reads)(f)", 1, 0),
        ("<Firewall>::reads(&f)", 1, 0),
        ("history.r#reserve(k)", 0, 1),
        ("ReadHistory::r#reserve(&h, k)", 0, 1),
        ("m!(f.r#reads())", 1, 0),
        ("m!((Firewall::reads)(f))", 1, 0),
        ("m!({ let r = Firewall::reads; })", 1, 0),
        ("m!(f.reads::<>())", 1, 0),
        ("m!(h.reserve::<>(k))", 0, 1),
        ("m!(self.reads)", 0, 0),
        ("Firewall::reads_all(&f)", 0, 0),
        ("reads(f)", 0, 0),
    ] {
        let expr: syn::Expr = syn::parse_str(source).expect("an expression");
        let mut access = Access::default();
        let at = Place {
            file: "src/elsewhere.rs".to_owned(),
            func: None,
        };
        syn::visit::Visit::visit_expr(&mut Mirror(&mut access, at), &expr);
        assert_eq!(
            (access.readers.len(), access.reservers.len()),
            (readers, reservers),
            "{source}"
        );
    }
    let stmt: syn::Stmt =
        syn::parse_str("println!(\"{}\", firewall.reads().len());").expect("a statement");
    let mut access = Access::default();
    let at = Place {
        file: "src/elsewhere.rs".to_owned(),
        func: None,
    };
    access.stmt(&at, &stmt);
    assert_eq!(access.readers.len(), 1, "a statement macro is seen");
}
