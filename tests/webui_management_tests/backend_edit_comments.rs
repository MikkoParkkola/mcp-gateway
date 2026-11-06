// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7968: a web UI backend edit keeps the comments in gateway.yaml, and a
//! write that cannot keep them is refused (409) naming what would be lost.

use super::*;

/// A router over `yaml` written to a fresh gateway.yaml, with a live
/// `ReloadContext`: the backend routes write only through one.
async fn served(yaml: &str) -> (axum::Router, std::path::PathBuf, Vec<TempDir>) {
    let tmp = TempDir::new().expect("tmp");
    let path = tmp.path().join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write");
    let config = Config::load_literal(Some(&path)).expect("fixture loads");
    let (state, _live, store) = make_app_state_with_reload(config, None, path.clone()).await;
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
    let (router, path, _keep) = served(SVC).await;
    let (status, body) = patch(&router, "svc", json!({"description": "new"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        read(&path),
        SVC.replace("description: old", "description: new"),
        ""
    );
}

/// T1 fixtures: CRLF line endings and a missing final newline.
#[tokio::test]
async fn an_edit_keeps_comments_in_crlf_and_unterminated_files() {
    for yaml in [SVC.replace('\n', "\r\n"), SVC.trim_end().to_owned()] {
        let (router, path, _keep) = served(&yaml).await;
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
    let (router, path, _keep) = served(&yaml).await;
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
    let (router, path, _keep) = served(SVC).await;
    // A reference, which the panel keeps as typed (a literal goes to the
    // secret store and only its reference reaches the file).
    let (status, body) = patch(&router, "svc", json!({"env": {"B": "env:B_VALUE"}})).await;
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
        Some("env:B_VALUE")
    );
}

/// A plain value typed into the panel's edit goes to the secret store:
/// gateway.yaml holds only the store's reference, the same one the answer
/// lists under `secrets_stored`, and neither carries the value. Before 4.0.0
/// the value was written into the file as typed.
#[tokio::test]
async fn a_plain_env_value_edited_in_the_panel_is_stored_not_written() {
    const VALUE: &str = "panel-typed-7c1e";
    let (router, path, _keep) = served(SVC).await;
    let (status, body) = patch(&router, "svc", json!({"env": {"B": VALUE}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains(VALUE), "{body}");
    let after = read(&path);
    assert!(
        !after.contains(VALUE),
        "the value reached gateway.yaml:\n{after}"
    );
    kept_in_order(SVC, &after);
    let config = Config::load_literal(Some(&path)).expect("loads");
    let written = config.backends["svc"].env.get("B").cloned().expect("B");
    assert_eq!(body["secrets_stored"][0]["field"], "env.B", "{body}");
    assert_eq!(
        body["secrets_stored"][0]["reference"],
        written.as_str(),
        "{body}"
    );
}

/// No-op PATCH: the value is already there, so nothing is written. The
/// gateway still reloads: retrying a PATCH whose reload failed finds its value
/// on disk, and skipping the reload would leave the runtime stale.
#[tokio::test]
async fn an_edit_that_changes_nothing_writes_nothing() {
    let (router, path, _keep) = served(SVC).await;
    let (status, body) = patch(&router, "svc", json!({"description": "old"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["reload"].is_object(), "{body}");
    assert_eq!(read(&path), SVC);
}

/// T3 KEEP.2: the inline comment on `enabled:` is carried onto the new value.
#[tokio::test]
async fn an_inline_comment_follows_its_edited_value() {
    let yaml = "backends:\n  svc:\n    command: x\n    enabled: true  # on for the pilot\n";
    let (router, path, _keep) = served(yaml).await;
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
        let (router, path, _keep) = served(&yaml).await;
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
    let (router, path, _keep) = served(yaml).await;
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
    let (router, path, _keep) = served(yaml).await;
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

/// A refusal: 409 naming the line of `comment`, never its text
/// (a `#` can sit inside a quoted secret), and the file byte-identical.
async fn refused(yaml: &str, name: &str, body: Value, comment: &str) {
    let line = 1 + yaml
        .lines()
        .position(|l| l.contains(comment))
        .expect("the fixture holds the comment");
    let (router, path, _keep) = served(yaml).await;
    let (status, answer) = patch(&router, name, body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    let answer = answer.to_string();
    assert!(
        answer.contains(&format!("line {line}")),
        "names line {line}: {answer}"
    );
    assert!(!answer.contains(comment), "echoes file text: {answer}");
    assert_eq!(read(&path), yaml, "the file was written");
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
#[tokio::test]
async fn a_load_error_never_echoes_a_value() {
    let (router, path, _keep) = served(SVC).await;
    write_owner_only(
        &path,
        "backends:\n  svc:\n    command: x\n    enabled: \"#secret\"\n",
    )
    .expect("write");
    let files = mcp_gateway::gateway::test_helpers::ConfigFiles::snapshot(&path);
    let (status, answer) = patch(&router, "svc", json!({"description": "new"})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{answer}");
    files.assert_unchanged(&path, "the edit refused for a load error");
    let answer = answer.to_string();
    assert!(!answer.contains("#secret"), "echoes the value: {answer}");
}

/// No gateway running to reload (a config path, no `ReloadContext`): the
/// edit fails closed with 503 and the file is not written.
#[tokio::test]
async fn without_a_reload_context_an_edit_writes_nothing() {
    let tmp = TempDir::new().expect("tmp");
    let path = tmp.path().join("gateway.yaml");
    write_owner_only(&path, SVC).expect("write");
    let (state, _store) = make_app_state(None, Some(path.clone())).await;
    let router = create_router(state);
    let files = mcp_gateway::gateway::test_helpers::ConfigFiles::snapshot(&path);
    let (status, answer) = patch(&router, "svc", json!({"description": "new"})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(read(&path), SVC, "the file was written");
    files.assert_unchanged(&path, "the edit with no reload context");
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

/// T8 guard (green since #3090): add and remove over HTTP keep every comment.
#[tokio::test]
async fn add_and_remove_over_http_keep_comments() {
    let (router, path, _keep) = served(SVC).await;
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
    let (router, path, _keep) = served(yaml).await;
    let (status, body) = send_json(&router, Method::DELETE, "/ui/api/backends/a", None).await;
    // MIK-8051: the comment inside `a` (line 6) went with it, and the
    // response says so; DEL-NOTE.1.
    assert_eq!(status, StatusCode::OK, "{body}");
    let note = body["note"].as_str().unwrap_or_default();
    assert!(note.contains("line 6"), "{body}");
    let after = read(&path);
    for kept in ["# lead", "# why a", "# why b"] {
        assert!(after.contains(kept), "{kept:?} lost:\n{after}");
    }
    assert!(!after.contains("# inside a"), "{after}");
    let config = Config::load_literal(Some(&path)).expect("loads");
    assert!(!config.backends.contains_key("a") && config.backends.contains_key("b"));
}

/// MIK-8051 DEL-NOTE.2: the note names lines only; a quoted secret after a
/// `#` inside the removed entry never reaches the response.
#[tokio::test]
async fn a_delete_note_never_carries_comment_text() {
    let yaml = "backends:\n  a:\n    command: x  # token-s3cr3t-value\n  b:\n    command: y\n";
    let (router, _path, _keep) = served(yaml).await;
    let (status, body) = send_json(&router, Method::DELETE, "/ui/api/backends/a", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let text = body.to_string();
    assert!(text.contains("line 3"), "{text}");
    assert!(!text.contains("s3cr3t"), "comment text leaked: {text}");
}

/// MIK-8051 DEL-NOTE.3: a delete that drops no comment keeps today's 204.
#[tokio::test]
async fn a_delete_without_comments_keeps_no_content() {
    let yaml = "# lead\nbackends:\n  a:\n    command: x\n  b:\n    command: y\n";
    let (router, _path, _keep) = served(yaml).await;
    let (status, body) = send_json(&router, Method::DELETE, "/ui/api/backends/a", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[path = "backend_edit_layout.rs"]
mod layout;
