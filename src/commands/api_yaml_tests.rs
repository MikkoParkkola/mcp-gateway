// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The api command sends a capability's YAML exactly as given, typed by the
//! route it goes to: the capability save and validate routes take raw YAML,
//! every other route keeps taking JSON only, and no option chooses the type.

use super::*;

/// YAML as an editor may save it: CRLF line ends, a non-ASCII character and
/// no final newline.
const YAML: &str = "name: caf\u{e4}_lookup\r\ndescription: Looks it up\r\nproviders:\r\n  primary: {service: rest}";
/// A YAML body that is also valid JSON, with spacing a JSON writer would drop.
const JSON_SHAPED: &str = "{ \"a\" :  1 } \r\n";
/// The refusal's remedy on a route that takes JSON.
const JSON_ONLY: &str = "Send JSON: only the capability save and validate routes take YAML.";

/// Where `--data` reads the body from.
#[derive(Clone, Copy, Debug)]
enum Input {
    Inline,
    File,
    Stdin,
}

/// One run of `method path` with `body` given by `input` (and `if_match`)
/// against `stand`: the outcome and how many requests went out.
async fn run(
    stand: &Stand,
    (method, path): (ApiMethod, &str),
    body: &[u8],
    input: Input,
    if_match: Option<&str>,
) -> (CliOutcome, usize) {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let file = dir.path().join("body.yaml");
    std::fs::write(&file, body).expect("the body file is written");
    let mut a = args(path);
    a.method = method;
    a.if_match = if_match.map(str::to_owned);
    a.data = Some(match input {
        Input::Inline => String::from_utf8(body.to_vec()).expect("an inline body is text"),
        Input::File => format!("@{}", file.display()),
        Input::Stdin => "-".to_owned(),
    });
    let sent = AtomicUsize::new(0);
    let stdin = body.to_vec();
    let out = run_api_with(
        &a,
        &stand.base,
        &LinkTls::default(),
        credential,
        move || Ok(stdin),
        |request| {
            sent.fetch_add(1, Ordering::SeqCst);
            send(request)
        },
    )
    .await;
    (out, sent.load(Ordering::SeqCst))
}

/// A run that must have sent `body` once, unchanged, typed `content_type`.
fn assert_sent(stand: &Stand, (out, sent): &(CliOutcome, usize), body: &[u8], content_type: &str) {
    assert_eq!(out.exit().code(), 0, "{}", out.stderr());
    assert!(out.stderr().is_empty(), "{}", out.stderr());
    assert_eq!(*sent, 1);
    let seen = stand.seen.lock().expect("requests");
    let last = seen.last().expect("one request");
    assert_eq!(last.content_type.as_deref(), Some(content_type));
    assert_eq!(last.body, body, "the bytes that arrived");
}

/// A run refused locally as a JSON route refuses a non-JSON body.
fn assert_json_only((out, sent): &(CliOutcome, usize), what: &str) {
    assert_error(
        out,
        false,
        2,
        "Usage",
        "Request body is not valid JSON.",
        JSON_ONLY,
        None,
        None,
    );
    assert_eq!(*sent, 0, "{what}: nothing may be sent");
}

async fn ok_stand() -> Stand {
    stand_in(StatusCode::OK, "application/json", "{}").await
}

/// T1: a save sends the body as given, from each input, with the `ETag`.
#[tokio::test]
async fn a_capability_save_sends_its_yaml_unchanged() {
    for body in [YAML, JSON_SHAPED] {
        for input in [Input::Inline, Input::File, Input::Stdin] {
            let stand = ok_stand().await;
            let path = "/ui/api/capabilities/a";
            let ran = run(
                &stand,
                (ApiMethod::Put, path),
                body.as_bytes(),
                input,
                Some("\"r1\""),
            )
            .await;
            assert_sent(&stand, &ran, body.as_bytes(), "application/x-yaml");
            let seen = stand.seen.lock().expect("requests");
            assert_eq!(seen[0].method, axum::http::Method::PUT, "{input:?}");
            assert_eq!(seen[0].path, path, "{input:?}");
            assert_eq!(seen[0].if_match.as_deref(), Some("\"r1\""), "{input:?}");
        }
    }
}

/// T2: both validate routes send the body as given.
#[tokio::test]
async fn a_capability_validate_sends_its_yaml_unchanged() {
    for (route, wire) in [
        (
            (ApiMethod::Put, "/ui/api/capabilities/a?validate=1"),
            axum::http::Method::PUT,
        ),
        (
            (ApiMethod::Post, "/ui/api/capabilities/a/validate"),
            axum::http::Method::POST,
        ),
    ] {
        for body in [YAML, JSON_SHAPED] {
            let stand = ok_stand().await;
            let ran = run(&stand, route.clone(), body.as_bytes(), Input::Inline, None).await;
            assert_sent(&stand, &ran, body.as_bytes(), "application/x-yaml");
            let seen = stand.seen.lock().expect("requests");
            assert_eq!(seen[0].method, wire, "{}", route.1);
            assert_eq!(seen[0].path, route.1);
        }
    }
}

/// T3a: a create stays a JSON request, and its yaml string arrives unchanged.
#[tokio::test]
async fn a_capability_create_delivers_its_yaml_string_unchanged() {
    let stand = ok_stand().await;
    let create = serde_json::json!({"name": "n", "yaml": YAML}).to_string();
    let ran = run(
        &stand,
        (ApiMethod::Post, "/ui/api/capabilities"),
        create.as_bytes(),
        Input::Inline,
        None,
    )
    .await;
    assert_eq!(ran.0.exit().code(), 0, "{}", ran.0.stderr());
    let seen = stand.seen.lock().expect("requests");
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    let received: serde_json::Value = serde_json::from_slice(&seen[0].body).expect("JSON sent");
    assert_eq!(received["yaml"].as_str(), Some(YAML));
}

/// T3b and T3c: a YAML body to a JSON route is refused with nothing sent; a
/// JSON body there still goes out as JSON.
#[tokio::test]
async fn a_json_route_refuses_yaml_and_still_takes_json() {
    for route in [
        (ApiMethod::Post, "/ui/api/capabilities"),
        (ApiMethod::Put, "/ui/api/config"),
    ] {
        let stand = ok_stand().await;
        let ran = run(&stand, route.clone(), YAML.as_bytes(), Input::Inline, None).await;
        assert_json_only(&ran, route.1);
    }
    let stand = ok_stand().await;
    let json = br#"{"k": [1, 2]}"#;
    let ran = run(
        &stand,
        (ApiMethod::Put, "/ui/api/config"),
        json,
        Input::Inline,
        None,
    )
    .await;
    assert_eq!(ran.0.exit().code(), 0, "{}", ran.0.stderr());
    let seen = stand.seen.lock().expect("requests");
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    let received: serde_json::Value = serde_json::from_slice(&seen[0].body).expect("JSON sent");
    assert_eq!(received, serde_json::json!({"k": [1, 2]}));
}

/// T4: only the router's two raw routes switch; every look-alike, and every
/// other method on those paths, keeps the JSON path.
#[tokio::test]
async fn only_the_save_and_validate_routes_take_yaml() {
    for route in [
        (ApiMethod::Put, "/ui/api/capabilities-x/a"),
        (ApiMethod::Put, "/ui/api/capabilities/a/b"),
        (ApiMethod::Put, "/ui/api/capabilities/a/"),
        (ApiMethod::Post, "/ui/api/capabilities//validate"),
        (ApiMethod::Put, "/ui/api/capabilities/a/validate"),
        (ApiMethod::Post, "/ui/api/capabilities/a"),
        (ApiMethod::Get, "/ui/api/capabilities/a"),
        (ApiMethod::Delete, "/ui/api/capabilities/a"),
        (ApiMethod::Patch, "/ui/api/capabilities/a"),
        // The validate query alone does not switch: only a PUT on the name.
        (ApiMethod::Post, "/ui/api/capabilities/a?validate=1"),
        (ApiMethod::Get, "/ui/api/capabilities/a?validate=1"),
    ] {
        let stand = ok_stand().await;
        let ran = run(&stand, route.clone(), YAML.as_bytes(), Input::Inline, None).await;
        assert_json_only(&ran, &format!("{:?} {}", route.0, route.1));
    }
    // The control: one name segment with an escaped character is still a name.
    let stand = ok_stand().await;
    let route = (ApiMethod::Put, "/ui/api/capabilities/a%2Db");
    let ran = run(&stand, route, YAML.as_bytes(), Input::Inline, None).await;
    assert_sent(&stand, &ran, YAML.as_bytes(), "application/x-yaml");
}

/// T5: the 16 MiB cap holds for YAML, counted from literal sizes.
#[tokio::test]
async fn the_body_cap_holds_for_yaml() {
    let route = (ApiMethod::Put, "/ui/api/capabilities/a");
    let stand = ok_stand().await;
    let over = vec![b'a'; 16_777_217];
    let (out, sent) = run(&stand, route.clone(), &over, Input::Stdin, None).await;
    assert_error(
        &out,
        false,
        2,
        "Usage",
        "Request body exceeds 16 MiB.",
        "Send a smaller body.",
        None,
        None,
    );
    assert_eq!(sent, 0);
    let at = vec![b'a'; 16_777_216];
    let ran = run(&stand, route, &at, Input::Stdin, None).await;
    assert_sent(&stand, &ran, &at, "application/x-yaml");
}

/// T6: a YAML body's Debug names its size, never its bytes, so a logged
/// request cannot carry a capability's text.
#[test]
fn a_yaml_body_debugs_as_its_size_only() {
    let body = crate::commands::dashboard_link::AdminBody::Yaml(YAML.as_bytes().to_vec());
    assert_eq!(
        format!("{body:?}"),
        format!("Yaml {{ bytes: {} }}", YAML.len())
    );
}

/// T7: the command's arguments are exactly today's: no option names a type
/// or a header.
#[test]
fn no_option_chooses_the_body_type() {
    let command = <ApiArgs as clap::Args>::augment_args(clap::Command::new("api"));
    let mut got: Vec<String> = command
        .get_arguments()
        .map(|a| {
            let aliases: Vec<&str> = a.get_all_aliases().unwrap_or_default();
            format!("{} {:?} {aliases:?}", a.get_id(), a.get_long())
        })
        .collect();
    got.sort();
    let mut want = vec![
        "ca_cert Some(\"ca-cert\") []",
        "client_cert Some(\"client-cert\") []",
        "client_key Some(\"client-key\") []",
        "data Some(\"data\") []",
        "if_match Some(\"if-match\") []",
        "json Some(\"json\") []",
        "limit Some(\"limit\") []",
        "method None []",
        "path None []",
        "url Some(\"gateway\") [\"url\"]",
    ];
    want.sort_unstable();
    assert_eq!(got, want);
}
