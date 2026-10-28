// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A web UI backend edit of a comment-free gateway.yaml either edits the file
//! in place or is refused with nothing written; it never re-serialises the
//! whole file (ADR-024).
//!
//! Each fixture carries a flow-style `server` line outside `backends`. An
//! in-place edit leaves it alone; a whole-file rewrite turns it into block
//! style, so its loss marks the rewrite.

use super::*;

const CANARY: &str = "server: {port: 39401}";
const FLOW: &str = "server: {port: 39401}\nbackends: {alpha: {command: x}, beta: {command: y}}\n";
const ALIAS: &str =
    "server: {port: 39401}\nbackends:\n  alpha:\n    command: &c x\n  beta:\n    command: *c\n";

/// One write through `route`: `success` with every line that does not name
/// `name` kept in order, the canary among them, and `holds` true of the
/// reloaded config; or 409 with the file byte-identical.
async fn in_place_or_refused(
    yaml: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
    name: &str,
    success: &[StatusCode],
    holds: fn(&Config) -> bool,
) {
    for route in [Route::Live, Route::File] {
        let (router, path, _keep) = served(yaml, route).await;
        let (status, answer) = send_json(&router, method.clone(), uri, body.clone()).await;
        let after = read(&path);
        if status == StatusCode::CONFLICT {
            assert_eq!(after, yaml, "{route:?}: refused, but the file changed");
            let message = answer.to_string();
            assert!(
                message.contains("Not saved:") && message.contains("in place"),
                "{route:?}: not the in-place refusal: {message}"
            );
            continue;
        }
        assert!(success.contains(&status), "{route:?}: {status}: {answer}");
        assert!(
            after.contains(CANARY),
            "{route:?}: the file was re-serialised:\n{after}"
        );
        let marker = format!("{name}:");
        let untouched =
            yaml.lines()
                .filter(|l| !l.contains(&marker))
                .fold(String::new(), |mut kept, l| {
                    kept.push_str(l);
                    kept.push('\n');
                    kept
                });
        kept_in_order(&untouched, &after);
        let config = Config::load_literal(Some(&path)).expect("the written file loads");
        assert!(holds(&config), "{route:?}: the change is missing:\n{after}");
    }
}

const PATCHED: &[StatusCode] = &[StatusCode::OK];
const ADDED: &[StatusCode] = &[StatusCode::CREATED];
const REMOVED: &[StatusCode] = &[StatusCode::NO_CONTENT, StatusCode::OK];

fn described(config: &Config, name: &str) -> bool {
    config
        .backends
        .get(name)
        .is_some_and(|b| b.description == "new")
}

fn add_gamma() -> Value {
    json!({"name": "gamma", "command": "echo gamma"})
}

/// L1 INPLACE.1: a patch of a flow-mapping `backends`.
#[tokio::test]
async fn a_patch_of_a_comment_free_flow_file_is_in_place_or_refused() {
    let body = Some(json!({"description": "new"}));
    let holds: fn(&Config) -> bool = |c| described(c, "alpha");
    in_place_or_refused(
        FLOW,
        Method::PATCH,
        "/ui/api/backends/alpha",
        body,
        "alpha",
        PATCHED,
        holds,
    )
    .await;
}

/// L2 INPLACE.1: an addition to a flow-mapping `backends`.
#[tokio::test]
async fn an_add_to_a_comment_free_flow_file_is_in_place_or_refused() {
    let holds: fn(&Config) -> bool = |c| c.backends.contains_key("gamma");
    in_place_or_refused(
        FLOW,
        Method::POST,
        "/ui/api/backends",
        Some(add_gamma()),
        "gamma",
        ADDED,
        holds,
    )
    .await;
}

/// L3 INPLACE.1: a removal from a flow-mapping `backends`.
#[tokio::test]
async fn a_delete_from_a_comment_free_flow_file_is_in_place_or_refused() {
    let holds: fn(&Config) -> bool = |c| !c.backends.contains_key("beta");
    in_place_or_refused(
        FLOW,
        Method::DELETE,
        "/ui/api/backends/beta",
        None,
        "beta",
        REMOVED,
        holds,
    )
    .await;
}

/// L4 INPLACE.1: a patch of the backend holding an alias.
#[tokio::test]
async fn a_patch_of_an_aliased_backend_is_in_place_or_refused() {
    let body = Some(json!({"description": "new"}));
    let holds: fn(&Config) -> bool = |c| described(c, "beta");
    in_place_or_refused(
        ALIAS,
        Method::PATCH,
        "/ui/api/backends/beta",
        body,
        "beta",
        PATCHED,
        holds,
    )
    .await;
}

/// L5 INPLACE.1: an addition beside an anchor and its alias.
#[tokio::test]
async fn an_add_beside_an_anchor_is_in_place_or_refused() {
    let holds: fn(&Config) -> bool = |c| c.backends.contains_key("gamma");
    in_place_or_refused(
        ALIAS,
        Method::POST,
        "/ui/api/backends",
        Some(add_gamma()),
        "gamma",
        ADDED,
        holds,
    )
    .await;
}

/// L6 INPLACE.1: removing the anchor's owner would leave the alias dangling.
#[tokio::test]
async fn a_delete_of_an_anchors_owner_is_in_place_or_refused() {
    let holds: fn(&Config) -> bool = |c| !c.backends.contains_key("alpha");
    in_place_or_refused(
        ALIAS,
        Method::DELETE,
        "/ui/api/backends/alpha",
        None,
        "alpha",
        REMOVED,
        holds,
    )
    .await;
}

/// C1 control: a comment-free block-style file still takes a patch in place,
/// changing exactly one line.
#[tokio::test]
async fn a_patch_of_a_comment_free_block_file_changes_one_line() {
    let yaml = "server: {port: 39401}\nbackends:\n  alpha:\n    command: x\n    description: old\n";
    for route in [Route::Live, Route::File] {
        let (router, path, _keep) = served(yaml, route).await;
        let (status, body) = patch(&router, "alpha", json!({"description": "new"})).await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        assert_eq!(
            read(&path),
            yaml.replace("description: old", "description: new")
        );
    }
}

/// C2 control: a comment-free file without a `backends` key takes an add in place.
#[tokio::test]
async fn an_add_to_a_file_without_backends_is_in_place() {
    let yaml = "server: {port: 39401}\n";
    let (router, path, _keep) = served(yaml, Route::File).await;
    let (status, body) =
        send_json(&router, Method::POST, "/ui/api/backends", Some(add_gamma())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let after = read(&path);
    assert!(after.starts_with(CANARY), "re-serialised:\n{after}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert!(config.backends.contains_key("gamma"), "{after}");
}

/// L7: a UI edit of an existing file that does not parse writes nothing:
/// the route's own load fails before any write, offering no `--force` and
/// quoting no file text. The live route cannot even start on such a file.
#[tokio::test]
async fn an_edit_of_an_unparseable_file_writes_nothing() {
    let broken = "server: {port: 39401}\nbackends: [unclosed\n";
    let (router, path, _keep) = served(broken, Route::File).await;
    let (status, body) = patch(&router, "alpha", json!({"description": "new"})).await;
    assert!(!status.is_success(), "{status}: {body}");
    assert_eq!(read(&path), broken, "the file was written");
    let message = body.to_string();
    assert!(message.contains("Failed to load"), "{message}");
    assert!(!message.contains("--force"), "dead advice: {message}");
    assert!(!message.contains("unclosed"), "quotes the file: {message}");
}

/// C3 control: an empty file takes a UI add in place. It loads as the
/// default config, and the splice fills the missing `backends`.
#[tokio::test]
async fn an_add_to_an_empty_file_is_in_place() {
    let (router, path, _keep) = served("", Route::File).await;
    let (status, body) =
        send_json(&router, Method::POST, "/ui/api/backends", Some(add_gamma())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert!(config.backends.contains_key("gamma"), "{}", read(&path));
}

/// The lines of `text` outside backend `name`'s block, in order.
fn outside_entry(text: &str, name: &str) -> String {
    let head = format!("  {name}:");
    let mut inside = false;
    let mut kept = String::new();
    for line in text.lines() {
        let depth = line.len() - line.trim_start().len();
        if line == head {
            inside = true;
            continue;
        }
        if inside && !line.trim().is_empty() && depth <= 2 {
            inside = false;
        }
        if !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

/// A comment-free file the gateway wrote itself: `s` (stdio, with env, a
/// description, an idle stop and an `allowed_tools` list), `t` (stdio, bare)
/// and `h` (HTTP, bare).
fn gateway_written() -> String {
    let mut config = Config::default();
    let mut s = BackendConfig {
        description: "d".into(),
        transport: TransportConfig::Stdio {
            command: "echo s".into(),
            cwd: None,
            protocol_version: None,
        },
        stop_when_idle_for: Some(Duration::from_secs(300)),
        allowed_tools: Some(vec!["read_a".into()]),
        ..BackendConfig::default()
    };
    s.env.insert("A".into(), "1".into());
    let h = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".into(),
            streamable_http: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let t = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "echo t".into(),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    config.backends.insert("s".into(), s);
    config.backends.insert("t".into(), t);
    config.backends.insert("h".into(), h);
    crate::yaml::to_string(&config).expect("serialises")
}

/// Census: every field a UI backend PATCH can change, edited on a file the
/// gateway wrote itself, is made in place: 200, every line outside the
/// edited entry kept in order, and the change in the reloaded config.
#[tokio::test]
async fn every_patchable_field_edits_the_gateways_own_output_in_place() {
    type Check = fn(&BackendConfig) -> bool;
    let rows: &[(&str, &str, Value, Check)] = &[
        ("description", "s", json!({"description": "new"}), |b| {
            b.description == "new"
        }),
        (
            "description, unset before",
            "h",
            json!({"description": "new"}),
            |b| b.description == "new",
        ),
        (
            "command",
            "s",
            json!({"command": "echo t"}),
            |b| matches!(&b.transport, TransportConfig::Stdio { command, .. } if command == "echo t"),
        ),
        (
            "url",
            "h",
            json!({"url": "http://127.0.0.1:8/mcp"}),
            |b| matches!(&b.transport, TransportConfig::Http { http_url, .. } if http_url.contains(":8/")),
        ),
        (
            "env, merged into a map",
            "s",
            json!({"env": {"B": "2"}}),
            |b| {
                b.env.get("A").map(String::as_str) == Some("1")
                    && b.env.get("B").map(String::as_str) == Some("2")
            },
        ),
        ("env, a first map", "h", json!({"env": {"B": "2"}}), |b| {
            b.env.get("B").map(String::as_str) == Some("2")
        }),
        ("enabled", "s", json!({"enabled": false}), |b| !b.enabled),
        (
            "idle stop, changed",
            "s",
            json!({"stop_when_idle_for_secs": 60}),
            |b| b.stop_when_idle_for == Some(Duration::from_secs(60)),
        ),
        (
            "idle stop, cleared",
            "s",
            json!({"stop_when_idle_for_secs": 0}),
            |b| b.stop_when_idle_for.is_none(),
        ),
        (
            "idle stop, first set",
            "t",
            json!({"stop_when_idle_for_secs": 60}),
            |b| b.stop_when_idle_for == Some(Duration::from_secs(60)),
        ),
        (
            "allowed_tools, replaced",
            "s",
            json!({"allowed_tools": ["read_a", "write_b"]}),
            |b| {
                b.allowed_tools.as_deref() == Some(&["read_a".to_owned(), "write_b".to_owned()][..])
            },
        ),
        (
            "allowed_tools, cleared",
            "s",
            json!({"allowed_tools": null}),
            |b| b.allowed_tools.is_none(),
        ),
        (
            "allowed_tools, first set",
            "h",
            json!({"allowed_tools": ["read_a"]}),
            |b| b.allowed_tools.as_deref() == Some(&["read_a".to_owned()][..]),
        ),
    ];
    let yaml = gateway_written();
    let mut failed = Vec::new();
    for (label, name, body, holds) in rows {
        for route in [Route::Live, Route::File] {
            let (router, path, _keep) = served(&yaml, route).await;
            let (status, answer) = patch(&router, name, body.clone()).await;
            let after = read(&path);
            let mut rest = after.lines();
            let kept = outside_entry(&yaml, name)
                .lines()
                .all(|line| rest.any(|l| l == line));
            let config = Config::load_literal(Some(&path)).ok();
            let changed = config
                .as_ref()
                .and_then(|c| c.backends.get(*name))
                .is_some_and(holds);
            if status != StatusCode::OK || !kept || !changed {
                failed.push(format!(
                    "{label} ({route:?}): {status} kept={kept} changed={changed} {answer}"
                ));
            }
        }
    }
    assert!(failed.is_empty(), "not in place:\n{}", failed.join("\n"));
}
