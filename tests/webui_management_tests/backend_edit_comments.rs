// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7968: a web UI backend edit keeps the comments in gateway.yaml, and a
//! write that cannot keep them is refused (409) naming what would be lost.

use super::*;

/// Where the write lands: through a live `ReloadContext`, or straight to the
/// file with no gateway running.
#[derive(Clone, Copy, Debug)]
enum Route {
    Live,
    File,
}

/// A router over `yaml` written to a fresh gateway.yaml.
async fn served(yaml: &str, route: Route) -> (axum::Router, std::path::PathBuf, Vec<TempDir>) {
    let tmp = TempDir::new().expect("tmp");
    let path = tmp.path().join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write");
    let (state, store) = match route {
        Route::File => make_app_state(None, Some(path.clone())).await,
        Route::Live => {
            let config = Config::load_literal(Some(&path)).expect("fixture loads");
            let (state, _live, store) =
                make_app_state_with_reload(config, None, path.clone()).await;
            (state, store)
        }
    };
    (create_router(state), path, vec![tmp, store])
}

async fn patch(router: &axum::Router, name: &str, body: Value) -> (StatusCode, Value) {
    send_json(
        router,
        Method::PATCH,
        &format!("/ui/api/backends/{name}"),
        Some(body),
    )
    .await
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

/// Every line of `before` still in `after`, in order.
fn kept_in_order(before: &str, after: &str) {
    let mut rest = after.lines();
    for line in before.lines() {
        assert!(rest.any(|l| l == line), "{line:?} lost or moved:\n{after}");
    }
}

const SVC: &str = "# operator notes\nbackends:\n  # why svc exists\n  svc:\n    \
command: \"echo svc\"  # pinned for the demo\n    description: old\n    env:\n      \
# token from the vault\n      A: \"1\"\n  other:\n    command: \"echo other\"\n";

/// T1 KEEP.2: a description edit changes one line and nothing else.
#[tokio::test]
async fn an_edit_changes_only_its_own_line() {
    for route in [Route::Live, Route::File] {
        let (router, path, _keep) = served(SVC, route).await;
        let (status, body) = patch(&router, "svc", json!({"description": "new"})).await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        assert_eq!(
            read(&path),
            SVC.replace("description: old", "description: new"),
            "{route:?}"
        );
    }
}

/// T1 fixtures: CRLF line endings and a missing final newline.
#[tokio::test]
async fn an_edit_keeps_comments_in_crlf_and_unterminated_files() {
    for yaml in [SVC.replace('\n', "\r\n"), SVC.trim_end().to_owned()] {
        let (router, path, _keep) = served(&yaml, Route::File).await;
        let (status, body) = patch(&router, "svc", json!({"description": "new"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let after = read(&path);
        let untouched: Vec<&str> = yaml
            .lines()
            .filter(|l| !l.contains("description: old"))
            .collect();
        kept_in_order(&untouched.join("\n"), &after);
        let config = Config::load_literal(Some(&path)).expect("loads");
        assert_eq!(config.backends["svc"].description, "new");
    }
}

/// A CRLF file keeps its line endings: only the edited line changes.
#[tokio::test]
async fn an_edit_keeps_crlf_line_endings() {
    let yaml = SVC.replace('\n', "\r\n");
    let (router, path, _keep) = served(&yaml, Route::File).await;
    let (status, body) = patch(&router, "svc", json!({"description": "new"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        read(&path),
        yaml.replace("description: old", "description: new")
    );
}

/// T2 KEEP.2: an env key is appended inside the block `env:`, its comment kept.
#[tokio::test]
async fn an_env_edit_appends_inside_the_block() {
    let (router, path, _keep) = served(SVC, Route::File).await;
    let (status, body) = patch(&router, "svc", json!({"env": {"B": "2"}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = read(&path);
    kept_in_order(SVC, &after);
    let b = after
        .lines()
        .position(|l| l.trim_start().starts_with("B:"))
        .expect("B");
    let other = after.lines().position(|l| l == "  other:").expect("other");
    assert!(b < other, "B landed outside svc's env:\n{after}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert_eq!(
        config.backends["svc"].env.get("B").map(String::as_str),
        Some("2")
    );
}

/// No-op PATCH: the value is already there, so nothing is written. A live
/// gateway still reloads: retrying a PATCH whose reload failed finds its value
/// on disk, and skipping the reload would leave the runtime stale.
#[tokio::test]
async fn an_edit_that_changes_nothing_writes_nothing() {
    for route in [Route::Live, Route::File] {
        let (router, path, _keep) = served(SVC, route).await;
        let (status, body) = patch(&router, "svc", json!({"description": "old"})).await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        let reloaded = body["reload"].is_object();
        assert_eq!(reloaded, matches!(route, Route::Live), "{route:?}: {body}");
        assert_eq!(read(&path), SVC, "{route:?}");
    }
}

/// T3 KEEP.2: the inline comment on `enabled:` is carried onto the new value.
#[tokio::test]
async fn an_inline_comment_follows_its_edited_value() {
    let yaml = "backends:\n  svc:\n    command: x\n    enabled: true  # on for the pilot\n";
    let (router, path, _keep) = served(yaml, Route::File).await;
    let (status, body) = patch(&router, "svc", json!({"enabled": false})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(read(&path), yaml.replace("enabled: true", "enabled: false"));
}

/// T3b: a quote inside a plain value opens no quoted scalar, and escaped
/// quotes do not end one, so the comment after the value is still found and
/// carried onto the edited line.
#[tokio::test]
async fn an_apostrophe_does_not_hide_the_inline_comment() {
    for value in ["it's old", "say \"hello", "\"x \\\" y\"", "'it''s'"] {
        let yaml = format!(
            "backends:\n  svc:\n    command: x\n    description: {value}  # shown in the panel\n"
        );
        let (router, path, _keep) = served(&yaml, Route::File).await;
        let (status, body) = patch(&router, "svc", json!({"description": "new"})).await;
        assert_eq!(status, StatusCode::OK, "{value}: {body}");
        assert_eq!(read(&path), yaml.replace(value, "new"), "{value}");
    }
}

/// T4 KEEP.2: clearing `stop_when_idle_for` writes `null`; the comments around
/// it stay.
#[tokio::test]
async fn clearing_a_value_keeps_the_comments_around_it() {
    let yaml = "backends:\n  svc:\n    command: x\n    # stop when quiet\n    \
                stop_when_idle_for: 10m\n    # shown in the panel\n    description: d\n";
    let (router, path, _keep) = served(yaml, Route::File).await;
    let (status, body) = patch(&router, "svc", json!({"stop_when_idle_for_secs": 0})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        read(&path),
        yaml.replace("stop_when_idle_for: 10m", "stop_when_idle_for: null")
    );
}

/// T12: a stdio backend switched to a URL loses `command` with its inline
/// comment; the comment that leads it and every other field stay.
#[tokio::test]
async fn a_transport_switch_keeps_unrelated_comments() {
    let yaml = "backends:\n  svc:\n    # the local build\n    command: \"echo a\"  # until the remote is up\n    \
                description: d  # shown in the panel\n    env:\n      # vault\n      A: \"1\"\n";
    let (router, path, _keep) = served(yaml, Route::File).await;
    let url = "https://mcp.example.test/mcp";
    let (status, body) = patch(&router, "svc", json!({"url": url})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = read(&path);
    kept_in_order(
        &yaml.replace("    command: \"echo a\"  # until the remote is up\n", ""),
        &after,
    );
    assert!(!after.contains("until the remote is up"), "{after}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert!(
        matches!(&config.backends["svc"].transport, TransportConfig::Http { http_url, .. } if http_url == url),
        "{after}"
    );
}

/// A refusal on `route`: 409 naming the line of `comment`, never its text
/// (a `#` can sit inside a quoted secret), and the file byte-identical.
async fn refused(yaml: &str, name: &str, body: Value, comment: &str) {
    let line = 1 + yaml
        .lines()
        .position(|l| l.contains(comment))
        .expect("the fixture holds the comment");
    for route in [Route::Live, Route::File] {
        let (router, path, _keep) = served(yaml, route).await;
        let (status, answer) = patch(&router, name, body.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route:?}: {answer}");
        let answer = answer.to_string();
        assert!(
            answer.contains(&format!("line {line}")),
            "{route:?}: names line {line}: {answer}"
        );
        assert!(
            !answer.contains(comment),
            "{route:?}: echoes file text: {answer}"
        );
        assert_eq!(read(&path), yaml, "{route:?}: the file was written");
    }
}

/// T5 REFUSE.1: a flow-style `backends` cannot be spliced; the edit is refused.
#[tokio::test]
async fn an_edit_of_a_flow_style_file_with_comments_is_refused() {
    refused(
        "# top comment\nbackends: {a: {command: x}}\n",
        "a",
        json!({"description": "new"}),
        "# top comment",
    )
    .await;
}

/// T6 REFUSE.1: an interior comment in a flow `env` cannot be placed.
#[tokio::test]
async fn an_edit_through_a_commented_flow_mapping_is_refused() {
    refused(
        "backends:\n  a:\n    command: x\n    env: {\n      # secret\n      A: \"1\"\n    }\n",
        "a",
        json!({"env": {"B": "2"}}),
        "# secret",
    )
    .await;
}

/// The backstop: a comment the quote scanner misreads (the quote after `,`
/// looks like a scalar start) leaves a `#` in the replaced value, so the
/// edit is refused rather than dropping that comment.
#[tokio::test]
async fn a_misread_comment_is_refused_not_dropped() {
    refused(
        "backends:\n  svc:\n    command: x\n    description: say,\"hello  # keep\n",
        "svc",
        json!({"description": "new"}),
        "# keep",
    )
    .await;
}

/// A `#` inside a quoted secret counts as a possible comment, and the
/// refusal names its line without echoing the secret.
#[tokio::test]
async fn a_refusal_never_echoes_a_quoted_secret() {
    refused(
        "# top\nbackends: {a: {command: x, env: {TOKEN: \"#s3cr3t\"}}}\n",
        "a",
        json!({"description": "new"}),
        "#s3cr3t",
    )
    .await;
}

/// A file that stops loading after the gateway started: the load error can
/// quote the offending value, so the 500 must not carry it.
async fn load_error_hides_the_value(route: Route) {
    let (router, path, _keep) = served(SVC, route).await;
    write_owner_only(
        &path,
        "backends:\n  svc:\n    command: x\n    enabled: \"#secret\"\n",
    )
    .expect("write");
    let (status, answer) = patch(&router, "svc", json!({"description": "new"})).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{route:?}: {answer}"
    );
    let answer = answer.to_string();
    assert!(answer.contains("Failed to load"), "{route:?}: {answer}");
    assert!(
        !answer.contains("#secret"),
        "{route:?}: echoes the value: {answer}"
    );
}

/// Site `ReloadContext::mutate_locked` (live gateway).
#[tokio::test]
async fn a_live_load_error_never_echoes_a_value() {
    load_error_hides_the_value(Route::Live).await;
}

/// Site `mutate_config_and_reload_with` (no gateway running).
#[tokio::test]
async fn a_file_load_error_never_echoes_a_value() {
    load_error_hides_the_value(Route::File).await;
}

/// T10: a tab-separated inline comment counts as a comment.
#[tokio::test]
async fn a_tab_separated_comment_is_not_lost_silently() {
    refused(
        "backends: {a: {command: x}}\nserver:\n  port: 39400\t# tabbed\n",
        "a",
        json!({"description": "new"}),
        "# tabbed",
    )
    .await;
}

/// T7 guard: a file with no comments loses nothing, so the rewrite applies.
#[tokio::test]
async fn an_edit_of_a_comment_free_file_applies() {
    let (router, path, _keep) = served("backends: {a: {command: x}}\n", Route::File).await;
    let (status, body) = patch(&router, "a", json!({"description": "new"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert_eq!(config.backends["a"].description, "new");
}

/// T8 guard (green since #3090): add and remove over HTTP keep every comment.
#[tokio::test]
async fn add_and_remove_over_http_keep_comments() {
    let (router, path, _keep) = served(SVC, Route::File).await;
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({"name": "added", "command": "echo added"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    kept_in_order(SVC, &read(&path));
    let (status, body) = send_json(&router, Method::DELETE, "/ui/api/backends/added", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(read(&path), SVC);
}

/// T11 guard (lead ruling, option A): DELETE takes the entry and its own
/// interior comment; the comments leading it and the next entry stay.
#[tokio::test]
async fn delete_keeps_every_comment_outside_the_entry() {
    let yaml = "# lead\nbackends:\n  # why a\n  a:\n    command: x\n    # inside a\n    \
                description: d\n  # why b\n  b:\n    command: y\n";
    let (router, path, _keep) = served(yaml, Route::File).await;
    let (status, body) = send_json(&router, Method::DELETE, "/ui/api/backends/a", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let after = read(&path);
    for kept in ["# lead", "# why a", "# why b"] {
        assert!(after.contains(kept), "{kept:?} lost:\n{after}");
    }
    assert!(!after.contains("# inside a"), "{after}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert!(!config.backends.contains_key("a") && config.backends.contains_key("b"));
}
