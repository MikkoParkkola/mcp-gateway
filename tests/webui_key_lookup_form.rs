// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The classic dashboard's admin email-lookup form.
//!
//! The page's own lookup code (the block between the KEY-LOOKUP markers in
//! `index.html`) runs under node against a stubbed DOM, `fetch` and browser
//! storage; every sink the email must never reach is a trap that records a
//! touch. A source scan of the same block backs the traps.

use std::process::Command;

const INDEX: &str = include_str!("../src/gateway/ui/index.html");

/// The lookup block exactly as the page defines it.
fn block() -> &'static str {
    let begin = "// KEY-LOOKUP BEGIN";
    let start = INDEX
        .find(begin)
        .expect("index.html has a KEY-LOOKUP BEGIN marker");
    let end = INDEX[start..]
        .find("// KEY-LOOKUP END")
        .expect("index.html has a KEY-LOOKUP END marker");
    &INDEX[start..start + end]
}

/// The stub environment: a tiny DOM keyed by id, a fetch that records each
/// call and answers from `replies`, and traps on every storage-like sink.
const STUB: &str = r"
const touched = [];
const trap = (name) => new Proxy({}, {
  get: (_, k) => { touched.push(name + '.' + String(k)); return () => { touched.push(name + '()'); }; },
  set: (_, k) => { touched.push(name + '.' + String(k) + '='); return true; },
});
const node = (id) => ({ id, value: '', textContent: '', hidden: false, disabled: false,
  style: {}, children: [], dataset: {},
  replaceChildren(...c) { this.children = c; },
  append(...c) { this.children.push(...c); },
  appendChild(c) { this.children.push(c); return c; },
  setAttribute() {}, focus() {}, addEventListener() {} });
const dom = {};
const put = (k, v) => Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
globalThis.document = {
  getElementById: (id) => (dom[id] ??= node(id)),
  createElement: (tag) => ({ ...node(tag), tag }),
  createTextNode: (t) => ({ text: t }),
  get cookie() { touched.push('document.cookie'); return ''; },
  set cookie(_) { touched.push('document.cookie='); },
};
put('localStorage', trap('localStorage'));
put('sessionStorage', trap('sessionStorage'));
put('indexedDB', trap('indexedDB'));
put('history', trap('history'));
put('navigator', { sendBeacon: () => touched.push('sendBeacon') });
const realConsole = globalThis.console;
put('console', trap('console'));
const out = (v) => realConsole.log(JSON.stringify(v));
const calls = [];
let replies = [];
const listeners = {};
globalThis.window = { addEventListener: (t, f) => { listeners[t] = f; } };
globalThis.apiKey = 'k';
globalThis.authState = 'admin';
globalThis.authHeaders = () => ({ Accept: 'application/json', Authorization: 'Bearer k' });
globalThis.refusedMessage = () => 'refused';
globalThis.AuthRefused = class extends Error {};
globalThis.uiFetch = async (url, opts) => {
  calls.push({ url, opts, emailField: dom['kl-email']?.value });
  const r = replies.shift();
  if (r.gate) await r.gate;
  return { ok: r.status >= 200 && r.status < 300, status: r.status,
    headers: { get: (h) => (r.headers ?? {})[h.toLowerCase()] ?? null },
    json: async () => { if (r.bad) throw new Error('not json'); return r.body; } };
};
const page = (rows, extra = {}) => ({ status: 200, body: { rows, next_cursor: null,
  scan_exhausted: false, cursor_reset: false, unreadable: 0, scope: 'retained', ...extra } });
const row = (subject) => ({ timestamp: '2026-11-01T00:00:00Z', token_jti: 'j1', subject,
  issuer: 'https://idp', backends: ['b'], tools: ['t'], segment: 0 });
const submit = async (email) => {
  document.getElementById('kl-email').value = email;
  await submitKeyLookup({ preventDefault() {} });
};
";

/// Run `scenario` (module code after the stub and the page's block) and read
/// the one JSON line it prints.
fn run(scenario: &str) -> serde_json::Value {
    let script = format!("{STUB}\n{}\n{scenario}", block());
    let output = Command::new("node")
        .args(["--input-type=module", "-e", &script])
        .output()
        .expect("node is required: this test runs the dashboard's own JavaScript");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scenario prints one JSON line")
}

/// UIFORM.1: the field is empty by the time the request is on the wire, so
/// the email lives in the request body and nowhere on the page. Mutant:
/// clear after the answer, or never clear.
#[test]
fn the_field_is_cleared_before_the_request_is_sent() {
    let got = run(r"
replies = [page([row('s1')])];
await submit('ada@example.org');
out({ atCall: calls[0].emailField, after: dom['kl-email'].value, body: calls[0].opts.body });
");
    assert_eq!(
        got["atCall"], "",
        "the field still held the email when the request went out"
    );
    assert_eq!(got["after"], "");
    assert!(
        got["body"].as_str().unwrap().contains("ada@example.org"),
        "the request body carries the email"
    );
}

/// UIFORM.1: through a whole flow (a page, the next page, a throttle, a
/// failure) the email reaches no storage, history, cookie, console or beacon,
/// and the request URL is the bare route with no query. Mutant: any one sink.
#[test]
fn the_email_reaches_no_sink_and_no_url() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' }), page([row('s2')]),
  { status: 429, headers: { 'retry-after': '7' } }, { status: 500 }];
await submit('ada@example.org');
await keyLookupNext();
await submit('bob@example.org');
await submit('eve@example.org');
out({ touched, urls: calls.map((c) => c.url) });
");
    assert_eq!(got["touched"], serde_json::json!([]), "a sink was touched");
    for url in got["urls"].as_array().unwrap() {
        assert_eq!(url, "/ui/api/key-server/audit/lookup-email");
    }
}

/// UIFORM.1: the page's own lookup code names none of the places an email
/// could be kept or sent. Backs the traps above with a scan.
/// Mutant: a `localStorage` write, a `location` assignment, an analytics call.
#[test]
fn the_lookup_code_names_no_storage_or_analytics() {
    let code = block();
    for word in [
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "history.",
        "location.",
        "console.",
        "sendBeacon",
        "XMLHttpRequest",
        "gtag",
        "analytics",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
    ] {
        assert!(!code.contains(word), "the lookup code names {word}");
    }
}

/// The form's markup: a text field with no name (nothing to autofill or
/// remember under), autocomplete off, and a form that cannot submit itself as
/// a GET (the script handles the submit).
/// Mutant: add a `name`, drop autocomplete off, or give the form an action.
#[test]
fn the_form_markup_gives_a_browser_nothing_to_remember() {
    let start = INDEX
        .find(r#"id="kl-form""#)
        .expect("the page has the lookup form");
    let open = INDEX[..start]
        .rfind("<form")
        .expect("a form element opens it");
    let form_end = INDEX[start..].find("</form>").expect("the form closes") + start;
    let form = &INDEX[open..form_end];
    let field_at = form.find(r#"id="kl-email""#).expect("the email field");
    let field_open = form[..field_at].rfind("<input").expect("an input element");
    let field = &form[field_open..field_open + form[field_open..].find('>').unwrap()];
    assert!(field.contains(r#"autocomplete="off""#), "{field}");
    assert!(!field.contains(" name="), "the field has a name: {field}");
    let tag = &form[..form.find('>').unwrap()];
    assert!(!tag.contains("action="), "{tag}");
    assert!(!tag.contains("method="), "{tag}");
    assert!(
        tag.contains("onsubmit="),
        "the script must own the submit: {tag}"
    );
}

/// UIFORM.2: a page with a `next_cursor` offers the next page, which asks
/// again with the same email, window and the cursor; the last page ends it
/// and the held query is dropped. Mutant: next page without the cursor, a
/// held query that outlives the last page.
#[test]
fn paging_follows_next_cursor_and_ends_with_the_last_page() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' }), page([row('s2')])];
await submit('ada@example.org');
const offered = dom['kl-next'].hidden === false;
await keyLookupNext();
const second = JSON.parse(calls[1].opts.body);
out({ offered, second, endedHidden: dom['kl-next'].hidden, held: keyLookupHeld });
");
    assert_eq!(got["offered"], true);
    assert_eq!(got["second"]["cursor"], "c1");
    assert!(
        got["second"].get("email").is_none(),
        "the next page must not carry the email again: {}",
        got["second"]
    );
    assert_eq!(got["endedHidden"], true);
    assert_eq!(
        got["held"],
        serde_json::Value::Null,
        "the query outlived the last page"
    );
}

/// UIFORM.2: the answer says what it covers: retained rows only, and when the
/// scan budget or a reset cursor shaped the page, that too, in words.
/// Mutant: drop any of the three lines.
#[test]
fn the_page_says_retained_only_and_when_a_scan_stopped_or_reset() {
    let got = run(r"
replies = [page([], { scan_exhausted: true, cursor_reset: true, unreadable: 2 })];
await submit('ada@example.org');
out({ scope: dom['kl-scope'].textContent, notes: dom['kl-notes'].textContent });
");
    let scope = got["scope"].as_str().unwrap();
    let notes = got["notes"].as_str().unwrap();
    assert!(scope.contains("retained"), "{scope}");
    assert!(notes.contains("scan stopped"), "{notes}");
    assert!(notes.contains("restarted"), "{notes}");
    assert!(notes.contains("2 unreadable"), "{notes}");
}

/// UIFORM.2: a 429 shows the wait the server named, and keeps the pending
/// page so the same button retries it; a missing or silly wait is not shown
/// as a number. Mutant: ignore Retry-After, or drop the pending page.
#[test]
fn a_throttle_shows_the_wait_and_keeps_the_pending_page() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' }), { status: 429, headers: { 'retry-after': '7' } },
  { status: 429, headers: { 'retry-after': '99999999' } }];
await submit('ada@example.org');
await keyLookupNext();
const first = dom['kl-status'].textContent;
const kept = keyLookupHeld !== null;
await keyLookupNext();
out({ first, kept, silly: dom['kl-status'].textContent });
");
    assert!(
        got["first"].as_str().unwrap().contains("7 seconds"),
        "{}",
        got["first"]
    );
    assert_eq!(got["kept"], true);
    let silly = got["silly"].as_str().unwrap();
    assert!(!silly.contains("99999999"), "{silly}");
}

/// UIFORM.2: anything but a well-formed answer shows one fixed line, renders
/// no row and drops the held query: a failed status, a body that is not JSON,
/// rows that are not an array, a row field that is not text, too many rows.
/// Mutant: `unwrap_or_default` style leniency, render what parses.
#[test]
fn a_bad_answer_shows_a_fixed_line_and_renders_no_rows() {
    let got = run(r"
const bad = [
  { status: 500 }, { status: 200, bad: true }, { status: 200, body: { rows: 'x' } },
  page([{ ...row('s'), subject: { a: 1 } }]),
  page(Array.from({ length: 201 }, (_, i) => row('s' + i))),
];
const seen = [];
for (const r of bad) {
  replies = [r];
  await submit('ada@example.org');
  seen.push([dom['kl-status'].textContent, dom['kl-rows'].children.length, keyLookupHeld]);
}
out(seen);
");
    for case in got.as_array().unwrap() {
        assert!(!case[0].as_str().unwrap().is_empty(), "no message: {case}");
        assert_eq!(case[1], 0, "rows were rendered: {case}");
        assert_eq!(
            case[2],
            serde_json::Value::Null,
            "the query was kept: {case}"
        );
    }
}

/// A subject from a retained row is text, never markup: rows are built from
/// text nodes. Mutant: build a row with `innerHTML`.
#[test]
fn a_hostile_subject_is_shown_as_text() {
    let got = run(r#"
replies = [page([row('<img src=x onerror=alert(1)>')])];
await submit('ada@corp.test');
const walk = (n) => [n.tag ?? '', n.text ?? '', ...(n.children ?? []).flatMap(walk)];
const all = dom['kl-rows'].children.flatMap(walk);
out({ all });
"#);
    let all: Vec<&str> = got["all"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        all.iter()
            .any(|t| t.contains("<img src=x onerror=alert(1)>")),
        "the subject must be shown as text: {all:?}"
    );
    assert!(
        !all.contains(&"img"),
        "an element was built from the subject: {all:?}"
    );
}

/// UIFORM.3: the request is a POST of JSON with the page's auth headers and
/// `cache: 'no-store'`, one call per submit, to the exact route.
/// Mutant: GET, or drop no-store.
#[test]
fn the_request_is_a_no_store_post_with_the_page_auth() {
    let got = run(r"
replies = [page([])];
await submit('ada@example.org');
const o = calls[0].opts;
out({ method: o.method, cache: o.cache, ct: o.headers['Content-Type'],
  auth: o.headers.Authorization, n: calls.length });
");
    assert_eq!(got["method"], "POST");
    assert_eq!(got["cache"], "no-store");
    assert_eq!(got["ct"], "application/json");
    assert_eq!(got["auth"], "Bearer k");
    assert_eq!(got["n"], 1);
}

/// UIFORM.3: a caller the page does not know as an admin sends nothing and is
/// told why, in the page's own refusal line; a blank email sends nothing.
/// Mutant: send regardless of the auth state.
#[test]
fn a_non_admin_or_a_blank_email_sends_nothing() {
    let got = run(r"
replies = [page([])];
authState = 'signed_in';
await submit('ada@example.org');
const n1 = calls.length;
const said = dom['kl-status'].textContent;
authState = 'admin';
await submit('   ');
out({ n1, said, n2: calls.length });
");
    assert_eq!(got["n1"], 0);
    assert_eq!(got["said"], "refused");
    assert_eq!(got["n2"], 0);
}

/// UIFORM.3: the nav link and the page exist but the link starts hidden, and
/// the page's own `renderAuth` shows it for an admin state only.
/// Mutant: a link that is visible by default, or shown for signed-in users.
#[test]
fn the_page_is_hidden_from_everyone_but_an_admin() {
    let link = INDEX
        .find(r#"data-page="key-audit""#)
        .expect("a nav link for the page");
    let tag_open = INDEX[..link].rfind("<a ").unwrap();
    let tag = &INDEX[tag_open..link + INDEX[link..].find('>').unwrap()];
    assert!(
        tag.contains("display:none"),
        "the link must start hidden: {tag}"
    );
    assert!(INDEX.contains(r#"id="page-key-audit""#), "the page exists");
    assert!(
        INDEX.contains("navKeyAudit.style.display = state === 'admin' ? '' : 'none'"),
        "renderAuth must show the link for an admin state only"
    );
}

/// UIFORM.1: Clear, leaving the page and losing admin standing all drop the
/// held query, the field and the rows. Mutant: skip the clear in `onHash` or
/// in `renderAuth`, or leave the held query set.
#[test]
fn clear_leaving_and_losing_admin_drop_everything() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' })];
await submit('ada@corp.test');
const before = keyLookupHeld !== null;
keyLookupClear();
out({ before, held: keyLookupHeld, field: dom['kl-email'].value,
  rows: dom['kl-rows'].children.length, next: dom['kl-next'].hidden });
");
    assert_eq!(got["before"], true);
    assert_eq!(got["held"], serde_json::Value::Null);
    assert_eq!(got["field"], "");
    assert_eq!(got["rows"], 0);
    assert_eq!(got["next"], true);
    assert!(
        INDEX.contains("if (hash !== 'key-audit') keyLookupClear();"),
        "leaving the page must drop the query"
    );
    assert!(
        INDEX.contains("if (state !== 'admin') keyLookupClear();"),
        "losing admin standing must drop the query"
    );
}

/// Ruling row: the email is in the POST body and in no other part of the
/// request (URL, query string, headers, options), and the rendered form has
/// no GET path to the server of its own.
/// Mutant: put the email in the URL, a header or a query string.
#[test]
fn the_email_is_only_in_the_post_body() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' }), page([])];
await submit('ada@corp.test');
await keyLookupNext();
const rest = calls.map((c) => JSON.stringify({ url: c.url, opts: { ...c.opts, body: undefined } }));
out({ rest, bodies: calls.map((c) => c.opts.body), qs: calls.map((c) => c.url.includes('?')) });
");
    for part in got["rest"].as_array().unwrap() {
        assert!(!part.as_str().unwrap().contains("ada@corp.test"), "{part}");
    }
    for q in got["qs"].as_array().unwrap() {
        assert_eq!(q, false, "the URL carries a query string");
    }
    let bodies = got["bodies"].as_array().unwrap();
    assert!(
        bodies[0].as_str().unwrap().contains("ada@corp.test"),
        "the first page carries the email"
    );
    assert!(
        !bodies[1].as_str().unwrap().contains("ada@corp.test"),
        "the next page must send the sealed token alone: {}",
        bodies[1]
    );
    assert!(bodies[1].as_str().unwrap().contains("c1"));
}

/// A next page the server no longer honours (its token expired, was spent or
/// belongs to another session) is a 400: the page says to run the lookup again,
/// draws nothing and drops what it held. A first-page 400 stays the generic
/// failure. Mutant: show the generic line for a refused token, or keep the token.
#[test]
fn a_refused_token_says_to_run_the_lookup_again_and_is_dropped() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' }), { status: 400 }, { status: 400 }];
await submit('ada@corp.test');
await keyLookupNext();
const afterToken = [dom['kl-status'].textContent, keyLookupHeld, dom['kl-rows'].children.length];
await submit('bob@corp.test');
out({ afterToken, afterFirst: dom['kl-status'].textContent });
");
    let after = got["afterToken"].as_array().unwrap();
    assert!(
        after[0].as_str().unwrap().contains("run the lookup again"),
        "{after:?}"
    );
    assert_eq!(after[1], serde_json::Value::Null);
    assert_eq!(after[2], 0);
    let first = got["afterFirst"].as_str().unwrap();
    assert!(
        !first.contains("run the lookup again"),
        "a first-page 400 is the generic failure: {first}"
    );
}

/// A request that was in flight when the query was dropped writes nothing:
/// not the held query, not the rows, not a message. Covers Clear, leaving the
/// page (the same drop) and losing admin standing before the answer lands.
/// Mutant: drop the epoch/auth check after the awaits.
#[test]
fn an_answer_that_lands_after_a_drop_writes_nothing() {
    let got = run(r"
const results = [];
for (const how of ['clear', 'auth']) {
  let release;
  const gate = new Promise((ok) => { release = ok; });
  authState = 'admin';
  replies = [{ ...page([row('late')], { next_cursor: 'c9' }), gate }];
  document.getElementById('kl-email').value = 'ada@corp.test';
  const pending = submitKeyLookup({ preventDefault() {} });
  await Promise.resolve();
  if (how === 'clear') keyLookupClear(); else authState = 'signed_in';
  release();
  await pending;
  results.push([how, keyLookupHeld, dom['kl-rows'].children.length, dom['kl-next'].hidden]);
  keyLookupClear();
}
out(results);
");
    for case in got.as_array().unwrap() {
        assert_eq!(
            case[1],
            serde_json::Value::Null,
            "the query came back: {case}"
        );
        assert_eq!(case[2], 0, "rows were drawn after the drop: {case}");
        assert_eq!(
            case[3], true,
            "Next page was offered after the drop: {case}"
        );
    }
}

/// A second submit while a lookup is running changes nothing: the new email
/// stays in its field, no second request goes out, and the first answer is
/// the one shown. Mutant: clear the field or the page before the busy check.
#[test]
fn a_second_submit_while_busy_changes_nothing() {
    let got = run(r"
let release;
const gate = new Promise((ok) => { release = ok; });
replies = [{ ...page([row('first')]), gate }];
document.getElementById('kl-email').value = 'ada@corp.test';
const pending = submitKeyLookup({ preventDefault() {} });
await Promise.resolve();
document.getElementById('kl-email').value = 'bob@corp.test';
await submitKeyLookup({ preventDefault() {} });
const kept = dom['kl-email'].value;
release();
await pending;
out({ kept, n: calls.length, rows: dom['kl-rows'].children.length });
");
    assert_eq!(got["kept"], "bob@corp.test");
    assert_eq!(got["n"], 1);
    assert_eq!(got["rows"], 1);
}

/// Leaving through the back/forward cache drops the query: the page registers
/// `pagehide` with the one drop. The request also carries an abort signal so
/// a drop cancels it. Mutant: no listener, or no signal.
#[test]
fn pagehide_drops_the_query_and_a_drop_aborts_the_request() {
    let got = run(r"
replies = [page([row('s1')], { next_cursor: 'c1' })];
await submit('ada@corp.test');
const had = keyLookupHeld !== null;
listeners.pagehide({ persisted: true });
out({ registered: typeof listeners.pagehide, had, held: keyLookupHeld,
  rows: dom['kl-rows'].children.length, signal: calls[0].opts.signal instanceof AbortSignal });
");
    assert_eq!(got["registered"], "function");
    assert_eq!(got["had"], true);
    assert_eq!(got["held"], serde_json::Value::Null);
    assert_eq!(got["rows"], 0);
    assert_eq!(got["signal"], true);
}
