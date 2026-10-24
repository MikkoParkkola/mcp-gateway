// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8786.AUTH.2-4: the page decides its auth state from the facts
//! `/ui/api/status` states, never from a 200 alone.
//!
//! The page's own code, extracted from `index.html` by anchors, runs under
//! node against a stubbed `fetch` and DOM (as in `webui_delete_note_render.rs`).

use std::process::Command;

const INDEX: &str = include_str!("../src/gateway/ui/index.html");

/// `INDEX[start..end]` for the first `start` anchor and the next `end` after
/// it; each anchor must occur exactly once, so a moved anchor fails here and
/// never reads as a product failure.
fn span(start: &str, end: &str) -> &'static str {
    assert_eq!(
        INDEX.matches(start).count(),
        1,
        "anchor {start:?} must occur once"
    );
    let a = INDEX.find(start).expect("start anchor");
    let b = a + INDEX[a..].find(end).expect("end anchor");
    &INDEX[a..b]
}

/// A function the page defines, up to its closing brace at column 0.
fn function(signature: &str) -> String {
    let body = span(signature, "\n}\n");
    format!("{body}\n}}\n")
}

/// The auth block: from the key's declaration up to the router.
fn auth_block() -> &'static str {
    span("let apiKey =", "// Router")
}

/// Run the page's auth block and `refreshDashboard` with `answers` (a JS
/// object literal: URL -> list of `{status, body}`, served in order), then
/// `then` (JS, may await), and return every recorded element state plus the
/// headers each fetch sent, as JSON.
fn run(answers: &str, then: &str) -> serde_json::Value {
    run_with(answers, then, "")
}

/// [`run`] with `extra` (more of the page's own functions) defined too.
fn run_with(answers: &str, then: &str, extra: &str) -> serde_json::Value {
    let script = format!(
        r"
const els = {{}};
function el(id) {{
  if (!els[id]) {{
    els[id] = {{ id, textContent: '', innerHTML: '', className: '', style: {{ display: '' }},
      dataset: {{}}, value: '', listeners: {{}},
      classList: {{ add() {{}}, remove() {{}}, contains() {{ return false; }} }},
      addEventListener(t, f) {{ this.listeners[t] = f; }} }};
  }}
  return els[id];
}}
el('auth-dot').className = 'dot off';
el('auth-label').textContent = 'Not authenticated';
el('auth-btn').textContent = 'Set API Key';
el('servers-tbody').innerHTML = '<tr><td>Loading...</td></tr>';
globalThis.document = {{ getElementById: el, querySelectorAll: () => [], querySelector: () => null }};
globalThis.location = {{ hash: '' }};
globalThis.prompt = () => null;
globalThis.fmtUptime = (s) => String(s);
globalThis.esc = (s) => String(s);
globalThis.refreshServersTable = (servers) => {{ el('servers-tbody').innerHTML = 'ROWS:' + servers.length; }};
globalThis.refreshAll = () => {{}};
const answers = {answers};
const sent = [];
globalThis.fetch = async (url, opts = {{}}) => {{
  sent.push({{ url, headers: opts.headers || {{}} }});
  const queue = answers[url] || [];
  const a = queue.length > 1 ? queue.shift() : (queue[0] || {{ status: 404, body: {{}} }});
  return {{ ok: a.status >= 200 && a.status < 300, status: a.status, statusText: 'S' + a.status,
    json: async () => a.body, text: async () => JSON.stringify(a.body) }};
}};
const tick = () => new Promise((r) => setTimeout(r, 0));
{auth}
{dash}
{extra}
await tick(); await tick(); await tick();
{then}
await tick(); await tick(); await tick();
const out = {{}};
for (const [id, e] of Object.entries(els)) {{
  out[id] = {{ text: e.textContent, html: e.innerHTML, cls: e.className, display: e.style.display }};
}}
console.log(JSON.stringify({{ els: out, sent }}));
",
        auth = auth_block(),
        dash = function("async function refreshDashboard("),
    );
    let output = Command::new("node")
        .args(["--input-type=module", "-e", &script])
        .output()
        .expect("node is required: this test runs the dashboard's own JavaScript");
    assert!(
        output.status.success(),
        "scaffold: node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("element state as JSON")
}

/// The text of element `id` after a run.
fn text(state: &serde_json::Value, id: &str) -> String {
    state["els"][id]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn html(state: &serde_json::Value, id: &str) -> String {
    state["els"][id]["html"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A status answer with the given facts; `full` adds the admin inventory.
fn status(code: u16, auth: &str, full: bool) -> String {
    let servers = if full {
        ", servers: [{ name: 'a' }], tool_count: 3"
    } else {
        ""
    };
    let auth = if auth.is_empty() {
        String::new()
    } else {
        format!(", auth: {auth}")
    };
    format!(
        "{{ status: {code}, body: {{ server_count: 1, healthy_count: 1, degraded_count: 0, \
         uptime_secs: 5, version: 'x'{servers}{auth} }} }}"
    )
}

fn answers_for(status_answers: &[String]) -> String {
    format!("{{ '/ui/api/status': [{}] }}", status_answers.join(", "))
}

const AUTH_OFF_LABELS: [&str; 2] = ["Auth disabled", "Authentication off"];

/// P1 (D2): a dashboard session on a secured gateway is signed in, never
/// "Auth disabled".
#[test]
fn p1_a_signed_in_admin_is_shown_signed_in() {
    let s = run(
        &answers_for(&[status(
            200,
            "{ enabled: true, signed_in: true, admin: true }",
            true,
        )]),
        "",
    );
    let label = text(&s, "auth-label");
    assert_eq!(label, "Signed in", "P1: {s}");
    assert_ne!(
        s["els"]["auth-btn"]["display"], "none",
        "P1: the key control stays: {s}"
    );
}

/// P2 (D3): an anonymous caller on a secured gateway is offered sign-in.
#[test]
fn p2_auth_on_without_a_key_offers_sign_in() {
    let s = run(
        &answers_for(&[status(
            200,
            "{ enabled: true, signed_in: false, admin: false }",
            false,
        )]),
        "",
    );
    assert_eq!(text(&s, "auth-label"), "Not signed in", "P2: {s}");
    assert_eq!(text(&s, "auth-btn"), "Sign in", "P2: {s}");
    assert_ne!(s["els"]["auth-btn"]["display"], "none", "P2: {s}");
}

/// P3 (D1): authentication off is said plainly, with no sign-in control, no
/// green dot, the startup warning's guidance, and no endless "Loading...".
#[test]
fn p3_auth_off_says_so_and_how_to_turn_it_on() {
    let s = run(
        &answers_for(&[status(
            200,
            "{ enabled: false, signed_in: false, admin: false }",
            false,
        )]),
        "",
    );
    assert_eq!(text(&s, "auth-label"), "Authentication off", "P3: {s}");
    assert_eq!(s["els"]["auth-btn"]["display"], "none", "P3: {s}");
    assert_eq!(s["els"]["auth-dot"]["cls"], "dot neutral", "P3: {s}");
    let banner = text(&s, "auth-banner");
    assert!(
        banner.contains("mcp-gateway init") && banner.contains("auth.enabled: true"),
        "P3: the banner gives the way to turn authentication on: {s}"
    );
    let servers = html(&s, "servers-tbody");
    assert!(
        !servers.contains("Loading...") && servers.contains("auth.enabled: true"),
        "P3: the Servers table says why it is empty: {s}"
    );
}

/// P4: a status answer without usable facts offers sign-in; it never claims
/// authentication is off.
#[test]
fn p4_missing_or_malformed_facts_offer_sign_in() {
    for auth in [
        "",
        "{}",
        "{ enabled: null, signed_in: false, admin: false }",
    ] {
        let s = run(&answers_for(&[status(200, auth, false)]), "");
        let label = text(&s, "auth-label");
        assert!(
            !AUTH_OFF_LABELS.contains(&label.as_str()),
            "P4 ({auth:?}): {label:?} claims authentication is off: {s}"
        );
        assert_ne!(
            s["els"]["auth-btn"]["display"], "none",
            "P4 ({auth:?}): {s}"
        );
    }
}

/// P8: a key without the admin role is signed in, told admin views are
/// hidden, and the Servers table says it needs an admin key.
#[test]
fn p8_a_key_without_admin_is_signed_in_without_admin_views() {
    let s = run(
        &answers_for(&[status(
            200,
            "{ enabled: true, signed_in: true, admin: false }",
            false,
        )]),
        "",
    );
    assert_eq!(text(&s, "auth-label"), "Signed in (no admin)", "P8: {s}");
    assert!(text(&s, "auth-banner").contains("no admin role"), "P8: {s}");
    assert!(
        html(&s, "servers-tbody").contains("This needs an admin key"),
        "P8: {s}"
    );
}

/// P5 (D4): a session that ended (status 401) shows sign-in and a plain line
/// in the Servers table, never "Loading..." or the status code.
#[test]
fn p5_an_ended_session_shows_sign_in_not_loading() {
    let s = run(
        "{ '/ui/api/status': [{ status: 401, body: { error: 'Authentication required' } }] }",
        "await refreshDashboard();",
    );
    assert_eq!(text(&s, "auth-label"), "Not signed in", "P5: {s}");
    let servers = html(&s, "servers-tbody");
    assert!(
        servers.contains("Sign in (top right) to see servers")
            && !servers.contains("Loading...")
            && !servers.contains("401"),
        "P5: {s}"
    );
}

/// P9: a poll that finds the session gone updates the bar, clears the admin
/// rows, and still carries the poll marker.
#[test]
fn p9_a_poll_that_loses_access_updates_the_bar() {
    let s = run(
        &answers_for(&[
            status(200, "{ enabled: true, signed_in: true, admin: true }", true),
            status(
                200,
                "{ enabled: true, signed_in: false, admin: false }",
                false,
            ),
        ]),
        "await refreshDashboard(true);",
    );
    assert_eq!(text(&s, "auth-label"), "Not signed in", "P9: {s}");
    assert!(
        !html(&s, "servers-tbody").starts_with("ROWS:"),
        "P9: admin rows stayed: {s}"
    );
    for cell in ["d-cb-closed", "d-cb-open", "d-cb-half"] {
        assert_eq!(text(&s, cell), "-", "P9: {cell} kept the admin count: {s}");
    }
    let last = s["sent"]
        .as_array()
        .and_then(|v| v.last())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        last["headers"]["X-Mcp-Gateway-Poll"], "1",
        "P9: the poll was unmarked: {s}"
    );
}

/// P6 (D4): any other refused call throws a plain message, chosen from the
/// current state, with no status code in it.
#[test]
fn p6_a_refused_call_has_a_plain_message() {
    let then = "let m = '';\ntry { await apiFetch('/ui/api/tools'); } catch (e) { m = e.message; }\nel('p6-out').textContent = m;";
    let s = run(
        &format!(
            "{{ '/ui/api/status': [{}], '/ui/api/tools': [{{ status: 403, body: {{ error: 'Admin authentication required' }} }}] }}",
            status(
                200,
                "{ enabled: true, signed_in: true, admin: false }",
                false
            )
        ),
        then,
    );
    let m = text(&s, "p6-out");
    assert_eq!(
        m, "This needs an admin key: use Change key (top right)",
        "P6: {s}"
    );
    assert!(!m.chars().any(|c| c.is_ascii_digit()), "P6: {m:?}");
}

/// P7: every `/ui/api` call goes through the wrapper except the one status
/// read, and the poll marker is written in one place that both readers use.
#[test]
fn p7_every_ui_api_call_goes_through_the_wrapper() {
    let raw: Vec<_> = INDEX
        .match_indices("fetch(")
        .filter(|(i, _)| {
            let after = &INDEX[i + 6..];
            (after.starts_with("'/ui/api") || after.starts_with("`/ui/api"))
                && !INDEX[..*i].ends_with("ui")
        })
        .map(|(i, _)| INDEX[..i].lines().count())
        .collect();
    assert_eq!(
        raw.len(),
        1,
        "P7: raw /ui/api fetch calls outside uiFetch, at index.html lines {raw:?}"
    );
    let read_status = function("async function readStatus(");
    assert!(
        read_status.contains("fetch('/ui/api/status'"),
        "P7: the one raw read is readStatus"
    );
    assert_eq!(
        INDEX.matches("X-Mcp-Gateway-Poll").count(),
        1,
        "P7: one poll marker"
    );
    assert!(
        read_status.contains("requestHeaders(poll)"),
        "P7: readStatus marks polls"
    );
    assert!(
        function("async function apiFetch(").contains("requestHeaders(poll)"),
        "P7: apiFetch marks polls"
    );
}

/// P10: capability validation that is refused shows the plain refusal in the
/// field's error line; a network error still shows nothing.
#[test]
fn p10_a_refused_capability_validation_says_so() {
    let then = "const ta = el('ta-1'); ta.dataset.cap = 'c'; ta.value = 'x: 1';\nawait validateCapBlur(ta);";
    let s = run_with(
        &format!(
            "{{ '/ui/api/status': [{}], '/ui/api/capabilities/c?validate=1': [{{ status: 403, body: {{ error: 'Admin authentication required' }} }}] }}",
            status(
                200,
                "{ enabled: true, signed_in: true, admin: false }",
                false
            )
        ),
        then,
        &function("async function validateCapBlur("),
    );
    assert_eq!(
        text(&s, "err-1"),
        "This needs an admin key: use Change key (top right)",
        "P10: {s}"
    );
}

/// P11: a refused registry load shows the plain refusal in the add-server
/// note instead of only logging it.
#[test]
fn p11_a_refused_registry_load_says_so() {
    let s = run_with(
        &format!(
            "{{ '/ui/api/status': [{}], '/ui/api/registry': [{{ status: 401, body: {{ error: 'Authentication required' }} }}] }}",
            status(
                200,
                "{ enabled: true, signed_in: false, admin: false }",
                false
            )
        ),
        "await loadRegistry();",
        &format!(
            "let regAllServers = [];\n{}",
            function("async function loadRegistry(")
        ),
    );
    assert_eq!(
        text(&s, "add-server-note"),
        "Sign in (top right) to see this",
        "P11: {s}"
    );
}
