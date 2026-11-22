// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The classic page's + New Capability as the page runs it: the CAP-CREATE
//! part of `index.html` under node, its `fetch` sent to this router on a
//! local port, so the page's own request meets the real route. Beside it, the
//! route's answers to the two bodies that let a create read as done when
//! nothing was written.

use std::net::SocketAddr;
use tokio::process::Command;

use super::*;

const PAGE: &str = include_str!("../ui/index.html");

/// How long one press's node run may take: the parent's 30 s bound, stated
/// here so the timing guard can read it from this file.
const NODE_WINDOW: Duration = Duration::from_secs(30);

/// The text between the page's two CAP-CREATE comments.
fn create_part() -> &'static str {
    let (_, rest) = PAGE
        .split_once("// CAP-CREATE BEGIN")
        .expect("the page opens its create part");
    let (part, _) = rest
        .split_once("// CAP-CREATE END")
        .expect("the page closes its create part");
    part
}

/// `async function <name>` from the page, up to its closing brace line.
fn page_async_fn(name: &str) -> &'static str {
    let head = format!("\nasync function {name}(");
    let (_, rest) = PAGE.split_once(head.as_str()).expect("the page has it");
    let (body, _) = rest.split_once("\n}\n").expect("it ends");
    let at = PAGE.len() - rest.len() - head.len() + 1;
    &PAGE[at..at + head.len() - 1 + body.len() + 2]
}

/// Browser stand-ins for the page's code, each recording what it was asked.
/// `fetch` forwards the page's path to `BASE`, or, while `scripted` holds
/// answers, hands those out one by one instead.
const BROWSER: &str = r"
const toRouter = globalThis.fetch;
const sent = [], alerts = [], opened = [];
let refreshed = 0, scripted = null;
Object.assign(globalThis, {
  fetch: async (path, init = {}) => {
    const h = init.headers ?? {};
    sent.push({ path, method: init.method ?? 'GET', contentType: h['Content-Type'] ?? null,
      body: init.body ?? null });
    if (!scripted) return toRouter(BASE + path, init);
    const next = scripted.shift();
    return new Response(next.body, { status: next.status, headers: { 'content-type': next.type } });
  },
  prompt: () => NAME,
  alert: (text) => { alerts.push(String(text)); },
  authHeaders: () => ({ Authorization: `Bearer ${KEY}`, Accept: 'application/json' }),
  refreshAuth: async () => {},
  refusedMessage: () => 'not allowed',
  AuthRefused: class NotAllowed extends Error {},
  refreshCapabilities: async () => { refreshed += 1; },
  toggleCap: async (which) => { opened.push(which); },
  document: { getElementById: () => ({ classList: { contains: () => false } }) },
});
";

/// This fixture's router, listening on a free local port.
async fn serve(fx: &Fixture) -> SocketAddr {
    // The listener moves into the spawned task, so its port stays bound.
    // port-check: a listener serving on in a spawned task for the row's life
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a free port");
    let addr = listener.local_addr().expect("the bound address");
    let app =
        create_router(Arc::clone(&fx.state)).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serving") });
    addr
}

/// One press of + New Capability with `name` typed at the prompt and
/// `scripted` (a JS array literal, or `null` for the real route): what the
/// page sent, alerted and opened.
async fn press(addr: SocketAddr, name: &str, scripted: &str) -> Value {
    let program = format!(
        "const BASE = 'http://{addr}'; const NAME = {name:?}; const KEY = {KEY:?};\n{BROWSER}\n\
         {}\n{}\nscripted = {scripted};\nawait newCapability();\n\
         console.log(JSON.stringify({{ sent, alerts, opened, refreshed }}));",
        page_async_fn("uiFetch"),
        create_part(),
    );
    // A child the timeout abandons is killed when its future drops, so a hung
    // script can never outlive the row or hold the runtime's shutdown.
    let mut node = Command::new("node");
    node.args(["--input-type=module", "-e", &program])
        .kill_on_drop(true);
    let ran = tokio::time::timeout(NODE_WINDOW, node.output())
        .await
        .expect("the page's script finished in time")
        .expect("these rows drive the page's script with node, so node must be on PATH");
    assert!(
        ran.status.success(),
        "the page's script exited with an error: {}",
        String::from_utf8_lossy(&ran.stderr)
    );
    serde_json::from_slice(&ran.stdout).expect("a single JSON result line")
}

/// The capability directory's file names, sorted.
fn listing(fx: &Fixture) -> Vec<String> {
    let dir = fx.file.parent().expect("the capability directory");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the directory reads")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort_unstable();
    names
}

/// A JSON POST to the create route as the admin.
fn create(body: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/capabilities")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request")
}

/// CREATE.1 (C2, the prediction behind the page fix): the template the page
/// carried, a `tools:` list with no `providers`, is not a capability the
/// writer accepts. Sent under the right field name it is refused with 422 and
/// writes nothing, so renaming the field alone would not have fixed the page.
#[tokio::test]
async fn c2_the_pages_old_template_shape_is_refused_by_the_writer() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let shape = "tools:\n  - name: probe_tool\n    description: a tool list, no providers\n";
    let body = serde_json::json!({ "name": "c2", "yaml": shape }).to_string();
    let (status, answer) = fx.send(create(&body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert!(
        !fx.file.with_file_name("c2.yaml").exists(),
        "a refused create made a file"
    );
}

/// STRICT.2 (S1): a create body with a field the route does not know is
/// refused with 422 naming it, and writes nothing; the body-less template
/// answer is unchanged.
#[tokio::test]
async fn s1_a_create_body_with_an_unknown_field_is_refused() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let before = listing(&fx);
    let (status, answer) = fx.send(create(r#"{"extra": 1}"#)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert!(answer.contains("unknown field `extra`"), "{answer}");
    assert_eq!(
        listing(&fx),
        before,
        "a refused create changed the directory"
    );
    let (status, template) = fx.send(create("{}")).await;
    assert_eq!(status, StatusCode::OK, "{template}");
    assert!(template.contains("\nproviders:\n"), "{template}");
}

/// CREATE.1 (CR1): pressing + New Capability writes `<name>.yaml` from the
/// server's own template under that name, the list shows it, and the page
/// opens it without an alert. The template request carries no body and no
/// Content-Type, so the route answers its template rather than a refusal.
#[tokio::test]
async fn cr1_the_page_creates_the_named_capability_through_the_route() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    let got = press(addr, "page_made", "null").await;
    let file = fx.file.with_file_name("page_made.yaml");
    assert!(file.exists(), "no file was written: {got}");
    let written = crate::capability::parse_capability_file(&file)
        .await
        .expect("the written file is a capability");
    assert_eq!(written.name, "page_made");
    let text = std::fs::read_to_string(&file).expect("the file reads");
    assert!(text.contains("\nproviders:\n"), "{text}");
    let (status, list) = fx
        .send(request("GET", "/ui/api/capabilities", "", ""))
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(list.contains("page_made"), "{list}");
    assert_eq!(got["alerts"], serde_json::json!([]), "{got}");
    assert_eq!(got["opened"], serde_json::json!(["page_made"]), "{got}");
    let sent = got["sent"].as_array().expect("the requests");
    assert_eq!(sent.len(), 2, "{got}");
    assert_eq!(sent[0]["contentType"], Value::Null, "{got}");
    assert_eq!(sent[0]["body"], Value::Null, "{got}");
    let create: Value = serde_json::from_str(sent[1]["body"].as_str().expect("a JSON body"))
        .expect("the create body is JSON");
    let keys: Vec<&String> = create.as_object().expect("an object").keys().collect();
    assert_eq!(keys, ["name", "yaml"], "{create}");
}

/// CREATE.2 (CR2): a create the route refuses (the name is taken) shows the
/// route's own message and opens nothing.
#[tokio::test]
async fn cr2_a_refused_create_shows_the_routes_message_and_opens_nothing() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    press(addr, "twice", "null").await;
    let got = press(addr, "twice", "null").await;
    let alerts = got["alerts"].as_array().expect("the alerts");
    assert_eq!(alerts.len(), 1, "{got}");
    assert!(
        alerts[0].as_str().expect("text").contains("already exists"),
        "{got}"
    );
    assert_eq!(got["opened"], serde_json::json!([]), "{got}");
}

/// CREATE.2 (CR3): a create answered 200 rather than 201 was not performed:
/// the page alerts with that answer and opens nothing.
#[tokio::test]
async fn cr3_a_create_answered_without_201_is_not_success() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    let scripted = r"[
      { status: 200, type: 'text/yaml', body: 'fulcrum: 1.0\nname: my_capability\nproviders: {}\n' },
      { status: 200, type: 'application/json', body: '{}' },
    ]";
    let got = press(addr, "not_made", scripted).await;
    assert_eq!(got["alerts"].as_array().map(Vec::len), Some(1), "{got}");
    assert_eq!(got["opened"], serde_json::json!([]), "{got}");
    assert_eq!(got["sent"].as_array().map(Vec::len), Some(2), "{got}");
}

/// CR4: a template answer with no `name:` line cannot be named for the file:
/// the page alerts and sends no create.
#[tokio::test]
async fn cr4_a_template_without_a_name_line_sends_no_create() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    let scripted = r"[{ status: 200, type: 'text/yaml', body: 'fulcrum: 1.0\nproviders: {}\n' }]";
    let got = press(addr, "unnamed", scripted).await;
    assert_eq!(got["alerts"].as_array().map(Vec::len), Some(1), "{got}");
    assert_eq!(got["sent"].as_array().map(Vec::len), Some(1), "{got}");
    assert_eq!(got["opened"], serde_json::json!([]), "{got}");
}

/// CR5: a typed name with capitals and a space becomes the one name a
/// capability may carry (CAP-001: lowercase, digits, '_'), used for both the
/// file and the capability, and the route accepts it.
#[tokio::test]
async fn cr5_a_typed_name_becomes_a_name_the_route_accepts() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    let got = press(addr, "My Tools", "null").await;
    let file = fx.file.with_file_name("my_tools.yaml");
    assert!(file.exists(), "no my_tools.yaml: {got}");
    let written = crate::capability::parse_capability_file(&file)
        .await
        .expect("the written file is a capability");
    assert_eq!(written.name, "my_tools");
    assert_eq!(got["alerts"], serde_json::json!([]), "{got}");
    assert_eq!(got["opened"], serde_json::json!(["my_tools"]), "{got}");
}

/// CR6: a typed name with no letter or digit left after the mapping is
/// refused on the page with its reason, before any request is sent.
#[tokio::test]
async fn cr6_a_name_with_no_letter_or_digit_is_refused_before_any_request() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    for typed in ["", "   ", "--", "_"] {
        let got = press(addr, typed, "null").await;
        let alerts = got["alerts"].as_array().expect("the alerts");
        assert_eq!(alerts.len(), 1, "{typed:?}: {got}");
        assert!(
            alerts[0]
                .as_str()
                .expect("text")
                .contains("letters or digits"),
            "{typed:?}: {got}"
        );
        assert_eq!(got["sent"], serde_json::json!([]), "{typed:?}: {got}");
    }
}

/// CR7: the page holds the route's 128-character name limit: 128 creates,
/// 129 is refused on the page before any request.
#[tokio::test]
async fn cr7_the_page_holds_the_routes_name_length_limit() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    let longest = "a".repeat(128);
    let got = press(addr, &longest, "null").await;
    assert!(
        fx.file.with_file_name(format!("{longest}.yaml")).exists(),
        "128 characters were not created: {got}"
    );
    assert_eq!(got["alerts"], serde_json::json!([]), "{got}");
    let got = press(addr, &"a".repeat(129), "null").await;
    let alerts = got["alerts"].as_array().expect("the alerts");
    assert_eq!(alerts.len(), 1, "{got}");
    assert!(alerts[0].as_str().expect("text").contains("128"), "{got}");
    assert_eq!(got["sent"], serde_json::json!([]), "{got}");
}

/// CR8 (a pin): names YAML could read as another type (a boolean, a null, a
/// number) each create a capability by that name; the loader reads the bare
/// scalar into the string field, so this passes with the name unquoted and
/// stands as a pin, not a red row.
#[tokio::test]
async fn cr8_names_yaml_would_read_as_another_type_create_by_that_name() {
    let fx = fixture(&capability(CANARY_BEFORE), AuditFailurePolicy::FailClosed).await;
    let addr = serve(&fx).await;
    // Booleans, nulls and every number form a loader could read the bare
    // scalar as, and then turn back into different text (007 as 7, 1e3 as
    // 1000, 0x10 as 16, 0o7 as 7, 1_000 as 1000).
    for typed in ["true", "null", "123", "007", "1e3", "0x10", "0o7", "1_000"] {
        let got = press(addr, typed, "null").await;
        let file = fx.file.with_file_name(format!("{typed}.yaml"));
        assert!(file.exists(), "{typed}: no file was written: {got}");
        let written = crate::capability::parse_capability_file(&file)
            .await
            .expect("the written file is a capability");
        assert_eq!(written.name, typed, "{typed}: {got}");
        assert_eq!(got["alerts"], serde_json::json!([]), "{typed}: {got}");
    }
}
