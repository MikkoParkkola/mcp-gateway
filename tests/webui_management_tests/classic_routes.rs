// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The calls the classic page makes, and that each one still reaches a handler.
//!
//! `/ui/classic` serves that page. An unmatched `GET` under `/ui` is the shell
//! document, and an unmatched path or method is an empty 404 or 405, so JSON
//! (or the one capability file) is what shows the handler ran.

use super::*;

/// The page's calls, in `(method, path)` order. A template or a concatenation
/// is `{name}`. A query is not part of the path.
const CALLS: &[(&str, &str)] = &[
    ("DELETE", "/ui/api/backends/{name}"),
    ("DELETE", "/ui/api/capabilities/{name}"),
    ("GET", "/ui/api/capabilities"),
    ("GET", "/ui/api/capabilities/{name}"),
    ("GET", "/ui/api/config"),
    ("GET", "/ui/api/control-plane"),
    ("GET", "/ui/api/costs"),
    ("GET", "/ui/api/registry"),
    ("GET", "/ui/api/status"),
    ("GET", "/ui/api/tools"),
    ("POST", "/ui/api/backends"),
    ("POST", "/ui/api/capabilities"),
    ("POST", "/ui/api/import/openapi"),
    ("POST", "/ui/api/import/openapi/preview"),
    ("POST", "/ui/api/key-server/audit/lookup-email"),
    ("POST", "/ui/api/previews"),
    ("POST", "/ui/api/reload"),
    ("PUT", "/ui/api/capabilities/{name}"),
];

const BACKEND: &str = "classic-backend";
const CAPABILITY: &str = "classic-cap";

struct Answer {
    status: StatusCode,
    content_type: String,
    body: Vec<u8>,
}

/// `send_raw` parses the body as JSON and drops the content type. The page is
/// HTML, and a handler is recognised by that type, so both checks keep the
/// bytes and the header.
async fn exchange(
    router: &Router,
    method: Method,
    uri: &str,
    body: Option<(&str, &str)>,
) -> Answer {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"));
    let request = match body {
        Some((content_type, text)) => builder
            .header("content-type", content_type)
            .body(Body::from(text.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status,
        content_type,
        body,
    }
}

fn media(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
}

fn capability_file() -> String {
    format!("/ui/api/capabilities/{CAPABILITY}")
}

/// Whether this answer came from the route's handler.
///
/// JSON is that answer. `GET` of one capability is the file (`text/yaml`):
/// the shell document is HTML, so YAML is still the handler. A 404 or a 405
/// counts only when its body is JSON. An empty 404, an empty 405 and the
/// shell's HTML do not.
fn handler_answered(method: &Method, path: &str, answer: &Answer) -> bool {
    // A route that answers but fails is not a route that works.
    if answer.status.is_server_error() {
        return false;
    }
    if *method == Method::GET && path == capability_file() {
        return media(&answer.content_type) == "text/yaml" && !answer.body.is_empty();
    }
    let json = media(&answer.content_type) == "application/json";
    if answer.status == StatusCode::NOT_FOUND || answer.status == StatusCode::METHOD_NOT_ALLOWED {
        return json && serde_json::from_slice::<Value>(&answer.body).is_ok();
    }
    json
}

fn concrete(path: &str) -> String {
    let name = if path.starts_with("/ui/api/backends/") {
        BACKEND
    } else {
        CAPABILITY
    };
    path.replace("{name}", name)
}

/// Creates first, deletes last, so the `{name}` routes address objects that
/// exist. The two creates are themselves calls the page makes.
fn send_order() -> Vec<(&'static str, &'static str)> {
    let mut order = vec![
        ("POST", "/ui/api/backends"),
        ("POST", "/ui/api/capabilities"),
    ];
    order.extend(
        CALLS
            .iter()
            .copied()
            .filter(|pair| !is_create(*pair) && !is_delete(*pair)),
    );
    order.extend(CALLS.iter().copied().filter(|pair| is_delete(*pair)));
    order
}

fn is_create(pair: (&str, &str)) -> bool {
    matches!(
        pair,
        ("POST", "/ui/api/backends") | ("POST", "/ui/api/capabilities")
    )
}

fn is_delete(pair: (&str, &str)) -> bool {
    pair.0 == "DELETE"
}

/// Body for a call that has one. Import is `{}` because a `url` would fetch a
/// spec, and the handler still answers JSON when neither field is set. Preview
/// omits `confirm` because that token is what starts the backend.
fn payload(method: &str, path: &str) -> Option<(&'static str, String)> {
    match (method, path) {
        ("POST", "/ui/api/backends") | ("POST", "/ui/api/previews") => Some((
            "application/json",
            json!({"name": BACKEND, "command": "echo hello"}).to_string(),
        )),
        ("POST", "/ui/api/capabilities") => Some((
            "application/json",
            json!({"yaml": VALID_YAML, "name": CAPABILITY}).to_string(),
        )),
        ("POST", "/ui/api/key-server/audit/lookup-email") => {
            Some(("application/json", json!({"email": "admin@example.com"}).to_string()))
        }
        ("POST", "/ui/api/import/openapi") | ("POST", "/ui/api/import/openapi/preview") => {
            Some(("application/json", "{}".to_string()))
        }
        // The page sends the file text. Without If-Match the handler refuses
        // before it writes, and that refusal is JSON.
        ("PUT", "/ui/api/capabilities/{name}") => {
            Some(("application/x-yaml", VALID_YAML.to_string()))
        }
        _ => None,
    }
}

fn owned_calls(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(method, path)| ((*method).to_string(), (*path).to_string()))
        .collect()
}

// ── The page text ────────────────────────────────────────────────────────────
//
// The three call shapes nest parentheses (`authHeaders()`, `${encodeURIComponent(...)}`),
// so a pattern that stops at the first `)` either cuts the call short or
// swallows the next one. The scan keeps strings and templates intact.

fn calls_in(page: &str) -> Vec<(String, String)> {
    let lookup = named_const(page, "KEY_LOOKUP_URL").unwrap_or_default();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some((at, name)) = next_call(page, from) {
        let open = at + name.len();
        // `function uiFetch` / `function apiFetch` are the wrappers. Their
        // bodies forward the caller's url, which is not a call of the page.
        if preceded_by_function(page, at) {
            from = open;
            continue;
        }
        let Some(end) = end_of_call(page, open) else {
            from = open + 1;
            continue;
        };
        if let Some(pair) = pair_from(&page[open + 1..end - 1], &lookup) {
            found.push(pair);
        }
        from = end;
    }
    found
}

fn next_call(page: &str, from: usize) -> Option<(usize, &'static str)> {
    let rest = page.get(from..)?;
    let mut best: Option<(usize, &'static str)> = None;
    for (token, name) in [
        ("apiFetch(", "apiFetch"),
        ("uiFetch(", "uiFetch"),
        ("fetch(", "fetch"),
    ] {
        if let Some(rel) = rest.find(token) {
            let at = from + rel;
            if best.is_none_or(|(earlier, _)| at < earlier) {
                best = Some((at, name));
            }
        }
    }
    best
}

fn preceded_by_function(page: &str, at: usize) -> bool {
    page[..at].trim_end().ends_with("function")
}

fn named_const(page: &str, name: &str) -> Option<String> {
    let marker = format!("const {name} = ");
    let at = page.find(&marker)?;
    let rest = page[at + marker.len()..].trim_start();
    let expr = rest.split(';').next()?.trim();
    strip_quotes(expr)
}

fn pair_from(inner: &str, lookup: &str) -> Option<(String, String)> {
    let args = split_on(inner, b',')?;
    let path = resolve_url(args.first()?.trim(), lookup)?;
    if !path.starts_with("/ui/api/") && path != "/ui/api" {
        return None;
    }
    let method = args
        .get(1)
        .map(|arg| arg.trim())
        .and_then(method_in)
        .unwrap_or_else(|| "GET".to_string());
    Some((method, path))
}

fn resolve_url(expr: &str, lookup: &str) -> Option<String> {
    let expr = expr.trim();
    let raw = if has_top_level(expr, b'+') {
        concat(expr)?
    } else if expr == "KEY_LOOKUP_URL" {
        lookup.to_string()
    } else if let Some(body) = strip_template(expr) {
        subst_template(body)?
    } else {
        strip_quotes(expr)?
    };
    Some(raw.split('?').next().unwrap_or(&raw).to_string())
}

fn concat(expr: &str) -> Option<String> {
    let mut out = String::new();
    for part in split_on(expr, b'+')? {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match strip_quotes(part) {
            Some(literal) => out.push_str(&literal),
            None => out.push_str("{name}"),
        }
    }
    Some(out)
}

fn subst_template(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            out.push_str("{name}");
            i = skip_braces(bytes, i + 1)?;
        } else {
            let ch = body[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Some(out)
}

fn method_in(opts: &str) -> Option<String> {
    let bytes = opts.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => i = skip_quoted(bytes, i, b'\'')?,
            b'"' => i = skip_quoted(bytes, i, b'"')?,
            b'`' => i = skip_template(bytes, i)?,
            b'm' if bytes[i..].starts_with(b"method") && word_boundary(bytes, i) => {
                let after = opts[i + "method".len()..].trim_start();
                let Some(rest) = after.strip_prefix(':') else {
                    i += "method".len();
                    continue;
                };
                let rest = rest.trim_start();
                let quote = *rest.as_bytes().first()?;
                if quote == b'\'' || quote == b'"' {
                    let end = rest[1..].find(quote as char)?;
                    return Some(rest[1..1 + end].to_string());
                }
                i += "method".len();
            }
            _ => i += 1,
        }
    }
    None
}

fn word_boundary(bytes: &[u8], at: usize) -> bool {
    at == 0 || !bytes[at - 1].is_ascii_alphanumeric()
}

fn has_top_level(expr: &str, sep: u8) -> bool {
    split_on(expr, sep).is_some_and(|parts| parts.len() > 1)
}

fn split_on(expr: &str, sep: u8) -> Option<Vec<&str>> {
    let bytes = expr.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let mut depth = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => i = skip_quoted(bytes, i, b'\'')?,
            b'"' => i = skip_quoted(bytes, i, b'"')?,
            b'`' => i = skip_template(bytes, i)?,
            b'(' | b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b')' | b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            found if found == sep && depth == 0 => {
                parts.push(expr[start..i].trim());
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    parts.push(expr[start..].trim());
    Some(parts)
}

fn end_of_call(page: &str, open: usize) -> Option<usize> {
    let bytes = page.as_bytes();
    let mut i = open;
    let mut depth = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' => i = skip_quoted(bytes, i, b'\'')?,
            b'"' => i = skip_quoted(bytes, i, b'"')?,
            b'`' => i = skip_template(bytes, i)?,
            _ => i += 1,
        }
    }
    None
}

fn strip_quotes(expr: &str) -> Option<String> {
    let bytes = expr.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let end = skip_quoted(bytes, 0, quote)?;
    if end != bytes.len() {
        return None;
    }
    Some(expr[1..end - 1].to_string())
}

fn strip_template(expr: &str) -> Option<&str> {
    let bytes = expr.as_bytes();
    if bytes.first().copied()? != b'`' {
        return None;
    }
    let end = skip_template(bytes, 0)?;
    if end != bytes.len() {
        return None;
    }
    Some(&expr[1..end - 1])
}

fn skip_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn skip_template(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'`' => return Some(i + 1),
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                i = skip_braces(bytes, i + 1)?;
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_braces(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut depth = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' => i = skip_quoted(bytes, i, b'\'')?,
            b'"' => i = skip_quoted(bytes, i, b'"')?,
            b'`' => i = skip_template(bytes, i)?,
            _ => i += 1,
        }
    }
    None
}

async fn files_router() -> (Router, TempDir, TempDir) {
    let files = TempDir::new().unwrap();
    let config_path = files.path().join("gateway.yaml");
    let cfg = Config::default();
    let yaml = crate::yaml::to_string(&cfg).unwrap();
    write_owner_only(&config_path, &yaml).unwrap();
    let cap_dir = files.path().join("capabilities");
    std::fs::create_dir(&cap_dir).unwrap();
    let (state, _live, store) = make_app_state_with_reload(
        cfg,
        Some(cap_dir.to_str().expect("the capability directory is utf-8")),
        config_path,
    )
    .await;
    (create_router(state), files, store)
}

// ── K1 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn classic_page_lists_these_api_calls() {
    let (state, _store) = make_app_state_with_auth_config(&admin_auth_config()).await;
    let router = create_router(state);

    let answer = exchange(&router, Method::GET, "/ui/classic", None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        media(&answer.content_type),
        "text/html",
        "the classic page is the document, got {}",
        answer.content_type
    );

    let page = String::from_utf8(answer.body).expect("the page is utf-8");
    let mut found = calls_in(&page);
    found.sort();
    found.dedup();
    assert_eq!(found, owned_calls(CALLS));
}

// ── K2 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn each_listed_call_is_answered_by_its_handler() {
    let mut sent = send_order();
    let mut listed = CALLS.to_vec();
    sent.sort();
    listed.sort();
    assert_eq!(sent, listed, "every listed call is sent once");

    let (router, _files, _store) = files_router().await;
    for (method, path) in send_order() {
        // The costs route exists only with cost-governance (src/gateway/ui/mod.rs);
        // without it the classic page's costs panel is meant to find nothing.
        if !cfg!(feature = "cost-governance") && (method, path) == ("GET", "/ui/api/costs") {
            continue;
        }
        let verb = Method::from_bytes(method.as_bytes()).unwrap();
        let uri = concrete(path);
        let owned = payload(method, path);
        let body = owned.as_ref().map(|(content_type, text)| (*content_type, text.as_str()));
        let answer = exchange(&router, verb.clone(), &uri, body).await;
        assert!(
            handler_answered(&verb, &uri, &answer),
            "{method} {path} did not answer from its handler: {} {} {}",
            answer.status,
            answer.content_type,
            String::from_utf8_lossy(&answer.body[..answer.body.len().min(180)]),
        );
    }
}

// ── K3 ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_answer_check_rejects_an_unknown_get_and_a_wrong_method() {
    let (state, _store) = make_app_state_with_auth_config(&admin_auth_config()).await;
    let router = create_router(state);

    for (method, path) in [
        (Method::GET, "/ui/api/no-such-route"),
        (Method::PATCH, "/ui/api/reload"),
    ] {
        let answer = exchange(&router, method.clone(), path, None).await;
        assert!(
            !handler_answered(&method, path, &answer),
            "{method} {path} was accepted as a handler: {} {}",
            answer.status, answer.content_type,
        );
    }
    // A handler that answers JSON but fails does not count as a working route.
    let failed = Answer {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "application/json".to_owned(),
        body: b"{}".to_vec(),
    };
    assert!(!handler_answered(&Method::GET, "/ui/api/status", &failed));
}
