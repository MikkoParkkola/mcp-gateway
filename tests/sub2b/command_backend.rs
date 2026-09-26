// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// `S-02` against a `command:` (subprocess) backend.
//
// Included into `mik_7272_sub2b_acs.rs` rather than compiled as a test binary
// of its own: these rows need that file's harness (`stdio_session`, `invoke`,
// `progress_token_of`), and a separate binary would have to duplicate it.
// Split out so the parent stays under the file-size ceiling
// `scripts/dev/check-file-size.py` gates.

// ── S-02 against a `command:` backend ───────────────────────────────────────
//
// Every row in the parent file configures the backend with `http_url` + `streamable_http`,
// so the gateway's *backend-facing* leg is always HTTP. The rows named
// `_stdio_` describe where the harness sits — a stdio client session — not
// what the gateway talks to. The two rows below are the first to configure a
// backend with `command:`, which is the only way to exercise
// `StdioTransport`'s notification path end to end.

/// A stdio MCP peer that emits one progress notification and then blocks until
/// a release file appears, so a gateway that buffered notifications until the
/// response arrived can never reach the release.
const COMMAND_PEER: &str = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"__VERSION__","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"__TOOL__","description":"notifies, then waits","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >> __LOG__
      token=$(printf '%s' "$line" | sed -n 's/.*"progressToken":"\([^"]*\)".*/"\1"/p')
      if [ -z "$token" ]; then
        token=$(printf '%s' "$line" | sed -n 's/.*"progressToken":\([0-9][0-9]*\).*/\1/p')
      fi
      printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":%s,"progress":1,"total":2}}\n' "${token:-null}"
      for _ in $(seq 1 600); do [ -f __RELEASE__ ] && break; sleep 0.05; done
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"done"}]}}\n' "$id" ;;
  esac
done
"#;

/// Write `gateway.yaml` pointing the backend at a `command:` peer, and return
/// the release path the peer waits on.
fn write_command_config(home: &Path) -> std::path::PathBuf {
    let script = home.join("peer.sh");
    let log = home.join("frames.log");
    let release = home.join("release");
    let body = COMMAND_PEER
        .replace("__VERSION__", CLIENT_PROTOCOL_VERSION)
        .replace("__TOOL__", SLOW_TOOL)
        .replace("__LOG__", &log.display().to_string())
        .replace("__RELEASE__", &release.display().to_string());
    std::fs::write(&script, body).expect("write command peer");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.join("gateway.yaml"),
        format!(
            "backends:\n  {BACKEND}:\n    command: \"sh {}\"\n",
            script.display()
        ),
    )
    .expect("write gateway.yaml");
    release
}

/// What the `command:` peer recorded receiving. Empty means the peer never
/// ran — a spawn or config fault, not a notification fault — so both rows
/// below quote it rather than letting a dead backend read as a timing defect.
fn frames_logged(home: &Path) -> String {
    std::fs::read_to_string(home.join("frames.log")).unwrap_or_default()
}

/// `S-02`, progress half, against a `command:` backend: the notification must
/// reach the client while the backend call is still in flight.
///
/// GIVEN a `command:` backend that notifies and then blocks on a release file,
/// WHEN the client calls it and the test reads stdout *before* releasing,
/// THEN the progress notification is already there.
///
/// The release is the discriminator, exactly as in ADR-014 row 4: a gateway
/// that collects a backend's notifications and publishes them after the
/// response resolves never emits a line here, so this row times out rather
/// than failing an ordering assertion. Ordering rows cannot see that defect —
/// a post-resolution flush still precedes the result on the wire.
#[tokio::test]
async fn s02_progress_from_a_command_backend_reaches_the_client_before_the_result() {
    // GIVEN
    let home = tempfile::tempdir().expect("temp home");
    let release = write_command_config(home.path());
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let client_token = json!("client-token-command");
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": client_token}),
        ))
        .await;
    let (_, notification) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;

    // THEN
    let frames = frames_logged(home.path());
    assert!(
        notification.is_some(),
        "a `command:` backend's progress notification must reach the client \
         while its call is still blocked; nothing arrived before the read \
         bound, which is the collect-then-emit shape ADR-014 §1 rejects. \
         The peer logged: {frames:?} (empty means it never got the call, so \
         the fault is the backend config, not the notification path)"
    );
    assert_eq!(
        progress_token_of(notification.as_ref().expect("notification")),
        Some(&client_token),
        "the client must see its own token back, not the gateway's minted one"
    );

    std::fs::write(&release, b"go").expect("release the peer");
    let (_, response) = session.read_until(|frame| has_id(frame, 2)).await;
    assert!(response.is_some(), "the released call must still answer");
    session.shutdown().await;
}

/// The same row with a **numeric** progress token, through the real subprocess.
///
/// Separate from the string row because the failure it catches is a different
/// one: the registry is keyed by string, so a design that registered the
/// caller's own token would collapse `7` and `"7"` onto one key -- the first
/// of the three defects ADR-014 §2 names. The minting indirection is what
/// keeps them apart, and only an end-to-end row proves the caller's *type*
/// survives the round trip; the unit row asserts restoration in isolation and
/// cannot see the keyspace.
#[tokio::test]
async fn s02_a_numeric_progress_token_comes_back_numeric_from_a_command_backend() {
    // GIVEN
    let home = tempfile::tempdir().expect("temp home");
    let release = write_command_config(home.path());
    let mut session = stdio_session(home.path()).await;

    // WHEN
    let client_token = json!(7);
    session
        .send(&invoke(
            2,
            SLOW_TOOL,
            &json!({}),
            &json!({"progressToken": client_token}),
        ))
        .await;
    let (_, notification) = session
        .read_until(|frame| is_method(frame, "notifications/progress"))
        .await;

    // THEN
    let frames = frames_logged(home.path());
    assert!(
        notification.is_some(),
        "a numeric progress token must route like any other; nothing arrived \
         before the read bound. The peer logged: {frames:?}"
    );
    assert_eq!(
        progress_token_of(notification.as_ref().expect("notification")),
        Some(&client_token),
        "the token must come back as the number the client sent, not the \
         string the registry keyed it under"
    );

    std::fs::write(&release, b"go").expect("release the peer");
    let (_, response) = session.read_until(|frame| has_id(frame, 2)).await;
    assert!(response.is_some(), "the released call must still answer");
    session.shutdown().await;
}

/// Partner to the row above: a call that declares no progress token gets no
/// notification forwarded, even though the same peer still emits one.
///
/// Without this row the cheapest way to pass the row above is to forward every
/// backend notification to the client unattributed, which would hand one
/// call's progress to whoever happened to be listening.
#[tokio::test]
async fn a_command_backend_notification_with_no_client_token_is_not_forwarded() {
    // GIVEN
    let home = tempfile::tempdir().expect("temp home");
    let release = write_command_config(home.path());
    let mut session = stdio_session(home.path()).await;

    // WHEN
    session
        .send(&invoke(2, SLOW_TOOL, &json!({}), &json!({})))
        .await;
    std::fs::write(&release, b"go").expect("release the peer");
    let (seen, response) = session.read_until(|frame| has_id(frame, 2)).await;

    // THEN
    let response = response.expect("the call must answer");
    let frames = frames_logged(home.path());
    assert!(
        response.get("result").is_some(),
        "the `command:` backend must actually answer: an error here means the \
         peer never started, which would make this row green for the wrong \
         reason and leave its partner's timeout unexplained: {response}"
    );
    assert!(
        !frames.is_empty(),
        "the peer must have received the `tools/call` it is being judged on"
    );
    assert!(
        !seen
            .iter()
            .any(|frame| is_method(frame, "notifications/progress")),
        "a notification no client asked for must be dropped, not forwarded: {seen:?}"
    );
    session.shutdown().await;
}

include!("websocket_backend.rs");
