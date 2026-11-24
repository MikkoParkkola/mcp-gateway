// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An API key name its own routes cannot address. A standard URL parser (a
//! browser's, or reqwest over the `url` crate) drops a `.` or `..` path
//! segment, however it is spelled, before the request is sent, so revoking
//! such a key by its address reaches another route. A control character is
//! refused for the family's reason: it could start a forged line wherever the
//! name is printed. The create route refuses all three through the one shared
//! rule; the loader keeps accepting them, so a hand-written one still loads,
//! and the list marks such a key `addressable: false`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use super::keys_create_fixture_tests::{
    Call, Fixture, Setup, admin_client, item, root_item, spec, yaml_of,
};
use crate::config::{ApiKeyConfig, AuthConfig};

/// A name holding a control character (BEL).
const BEL: &str = "a\u{7}b";

/// `name` as one double-quoted YAML scalar (BEL as YAML's `\a`).
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('\u{7}', "\\a"))
}

/// One running-table key of `name`.
fn running_key(name: &str, secret: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        name: name.into(),
        key_sha256: Some(spec(secret)),
        backends: vec!["*".into()],
        admin,
        ..ApiKeyConfig::default()
    }
}

/// The gateway's own file and running table both hold `names` beside the
/// root admin key, so the list's file entry and live-table entry each see them.
fn seeded(names: &[&str]) -> Setup {
    let mut items = vec![root_item()];
    let mut running = vec![running_key(
        "root",
        super::keys_create_fixture_tests::ROOT,
        true,
    )];
    for (i, name) in names.iter().enumerate() {
        let secret = format!("key-name-row-secret-{i}");
        items.push(item(&quoted(name), &secret, ""));
        running.push(running_key(name, &secret, false));
    }
    Setup {
        text: yaml_of(&items),
        running: AuthConfig {
            enabled: true,
            api_keys: running,
            ..AuthConfig::default()
        },
        ..Setup::default()
    }
}

/// The paths the served router received, as received, in order.
type Seen = Arc<Mutex<Vec<String>>>;

/// The UI API router on a local listener, reached over real HTTP. In front of
/// it the caller and the live generation are added, as the gateway's own
/// layers would, and each request's path is recorded before dispatch.
fn serve(fx: &Fixture) -> (SocketAddr, Seen) {
    let seen: Seen = Arc::default();
    let live = Arc::clone(&fx.live);
    let record = Arc::clone(&seen);
    let app = super::admin_audit::audited_api_router(&fx.state)
        .with_state(Arc::clone(&fx.state))
        .layer(axum::middleware::from_fn(
            move |mut request: Request<Body>, next: axum::middleware::Next| {
                let live = Arc::clone(&live);
                let record = Arc::clone(&record);
                async move {
                    let path = request.uri().path().to_owned();
                    record.lock().expect("seen").push(path);
                    request.extensions_mut().insert(live.generation());
                    request.extensions_mut().insert(admin_client());
                    next.run(request).await
                }
            },
        ));
    let listener = fx
        .rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    fx.rt
        .spawn(async move { axum::serve(listener, app).await.expect("serve") });
    (addr, seen)
}

/// What one DELETE did: every path the router received for it, and its
/// answer.
struct Deleted {
    paths: Vec<String>,
    status: u16,
    answer: Value,
}

/// DELETE the key at `written` (the address as typed after
/// `/ui/api/keys/`), the URL parsed the standard way. Redirects are not
/// followed, so `paths` holds exactly what this one request reached.
fn delete_at(fx: &Fixture, addr: SocketAddr, seen: &Seen, written: &str) -> Deleted {
    let url = format!("http://{addr}/ui/api/keys/{written}");
    let body = json!({"revision": fx.revision()}).to_string();
    let from = seen.lock().expect("seen").len();
    let (status, text) = fx.rt.block_on(async {
        let reply = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client")
            .delete(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("an answer");
        let status = reply.status().as_u16();
        (status, reply.text().await.unwrap_or_default())
    });
    Deleted {
        paths: seen.lock().expect("seen")[from..].to_vec(),
        status,
        answer: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

/// POST a create for `name` with a secret of its own: the fixture's fixed
/// test secret would give a second key the first one's digest.
fn create(fx: &Fixture, name: &str) -> super::keys_create_fixture_tests::Sent {
    let known = format!("mcpgw_key-name-row-{}-0123456789abcdef", hex::encode(name));
    fx.post(Call {
        known: Some(known),
        ..Call::new(&fx.body(name))
    })
}

/// The list's entry for `name`, if it lists one.
fn listed(answer: &Value, name: &str) -> Option<Value> {
    answer["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["name"] == name))
        .cloned()
}

/// KEYNAME.1: a key named `.` or `..` cannot be revoked by its address, in
/// any spelling: the client sends another path. Keys named `a/b`, `a?b`,
/// `a#b` and one holding a control character can be, percent-encoded. The
/// refused names are seeded through gateway.yaml, which the loader accepts;
/// whether the key is still there is read from the list, not the DELETE's
/// status, so a miss is the URL's and not a refusal's.
#[test]
fn keyname1_a_dot_name_cannot_be_revoked_by_its_address() {
    let fx = Fixture::new(seeded(&[".", "..", BEL]));
    for name in ["a/b", "a?b", "a#b"] {
        let sent = create(&fx, name);
        assert_eq!(sent.status, StatusCode::CREATED, "{name}: {}", sent.body);
    }
    let (addr, seen) = serve(&fx);
    for (name, spellings, received) in [
        (".", &[".", "%2e", "%2E"][..], "/ui/api/keys/"),
        (
            "..",
            &["..", "%2e%2e", "%2E%2E", ".%2e", "%2e."][..],
            "/ui/api/",
        ),
    ] {
        for written in spellings {
            let sent = delete_at(&fx, addr, &seen, written);
            assert_eq!(sent.paths, [received], "{written}");
            assert!(
                listed(&fx.get(), name).is_some(),
                "{written} revoked {name}"
            );
        }
    }
    for (name, written) in [
        ("a/b", "a%2Fb"),
        ("a?b", "a%3Fb"),
        ("a#b", "a%23b"),
        (BEL, "a%07b"),
    ] {
        // This request, and only it, reached the key's own address and
        // revoked that key: not a collapsed path that removed another one.
        let sent = delete_at(&fx, addr, &seen, written);
        assert_eq!(sent.paths, [format!("/ui/api/keys/{written}")]);
        assert_eq!(sent.status, 200, "{written}: {}", sent.answer);
        assert_eq!(sent.answer["revoked"], true, "{written}: {}", sent.answer);
        assert_eq!(sent.answer["name"], name, "{written}: {}", sent.answer);
        assert!(
            listed(&fx.get(), name).is_none(),
            "{written} did not revoke"
        );
    }
}

/// KEYNAME.2: the create route refuses `.`, `..` and a name holding a control
/// character: 422 `name_not_addressable` with the shared rule's own message
/// (the escaped name, no raw control byte), and gateway.yaml untouched. Names
/// with `/`, `?` and `#` are created (and revoked by address, KEYNAME.1).
/// Mutant: drop the check, and the `..` leg writes a key.
#[test]
fn keyname2_the_create_route_refuses_an_unaddressable_name() {
    let fx = Fixture::new(Setup::default());
    for name in [".", "..", BEL] {
        let before = fx.bytes();
        let sent = create(&fx, name);
        assert_eq!(
            sent.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name:?}: {}",
            sent.body
        );
        let body = sent.json();
        assert_eq!(body["error"], "name_not_addressable", "{name:?}: {body}");
        let message = crate::config::name_refusal("API key name", name).expect("refused");
        assert_eq!(body["message"], message, "{name:?}");
        // Decoded: JSON escapes a raw control byte on the wire, so only the
        // parsed message can show one.
        let shown = body["message"].as_str().unwrap_or_default();
        assert!(!shown.contains('\u{7}'), "a raw control byte: {shown:?}");
        assert_eq!(fx.bytes(), before, "{name:?}: gateway.yaml changed");
    }
    for name in ["a/b", "a?b", "a#b"] {
        let sent = create(&fx, name);
        assert_eq!(sent.status, StatusCode::CREATED, "{name}: {}", sent.body);
    }
}

/// KEYNAME.3: a gateway.yaml holding keys named `..` and one with a control
/// character (by hand) loads, and the list serves each as written with
/// `addressable: false`, beside `ok` with `addressable: true`: from the file
/// entry, and from the live-table entry once the file stops loading.
/// Mutants: the rule in the loader (the file no longer loads); no
/// `addressable` in the live-table entry (the second leg finds none).
#[test]
fn keyname3_the_list_marks_a_hand_written_unaddressable_key() {
    let fx = Fixture::new(seeded(&["..", BEL, "ok"]));
    let expect = |answer: &Value, leg: &str| {
        for (name, addressable) in [("..", false), (BEL, false), ("ok", true)] {
            let entry = listed(answer, name).unwrap_or_else(|| panic!("{leg}: {name:?} unlisted"));
            assert_eq!(
                entry["addressable"], addressable,
                "{leg}: {name:?}: {entry}"
            );
        }
    };
    let from_file = fx.get();
    assert!(from_file["revision"].is_string(), "{from_file}");
    expect(&from_file, "file");
    std::fs::write(fx.path(), "auth: [not, a, mapping\n").expect("break the file");
    let from_live = fx.get();
    assert_eq!(from_live["file"], "unloadable", "{from_live}");
    assert_eq!(from_live["revision"], Value::Null, "{from_live}");
    expect(&from_live, "live table");
}

/// KEYNAME.4: one definition. The create route and the list ask the shared
/// rule, and neither file carries a dot or control-character test of its own.
#[test]
fn keyname4_the_routes_use_the_one_shared_rule() {
    let source = |file: &str| {
        std::fs::read_to_string(format!(
            "{}/src/gateway/ui/{file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("source")
    };
    for file in ["keys_create.rs", "keys.rs"] {
        let text = source(file);
        assert!(
            text.contains("name_refusal(\"API key name\""),
            "{file} does not ask the rule"
        );
        for copy in ["== \".\"", "== \"..\"", "is_control"] {
            assert!(!text.contains(copy), "{file} has its own copy: {copy}");
        }
    }
}
