// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The secret echo and scrub rows run over real transports only. A test
//! double that claims to redact (`redacts_injected_values` returning `true`)
//! but scrubs nothing would mask the very leak those rows exist to catch, so
//! no row file may build, install or name one (lead ruling 2026-10-30).
//! Recording doubles that claim it are fine elsewhere: their rows check what
//! a call sends, never what its answer echoes.

/// Every file holding secret echo or scrub rows, read at build time.
const ROW_FILES: [(&str, &str); 11] = [
    (
        "src/gateway/router/secret_echo_tests.rs",
        include_str!("../../../../src/gateway/router/secret_echo_tests.rs"),
    ),
    (
        "src/gateway/router/secret_echo_stored_tests.rs",
        include_str!("../../../../src/gateway/router/secret_echo_stored_tests.rs"),
    ),
    (
        "src/transport/websocket_scrub_tests.rs",
        include_str!("../../../../src/transport/websocket_scrub_tests.rs"),
    ),
    (
        "src/transport/stdio_progress_tests.rs",
        include_str!("../../../../src/transport/stdio_progress_tests.rs"),
    ),
    (
        "src/transport/http/sse_decoder_tests.rs",
        include_str!("../../../../src/transport/http/sse_decoder_tests.rs"),
    ),
    (
        "src/transport/http/listen_stream_tests.rs",
        include_str!("../../../../src/transport/http/listen_stream_tests.rs"),
    ),
    (
        "src/transport/http/sse_listen_tests.rs",
        include_str!("../../../../src/transport/http/sse_listen_tests.rs"),
    ),
    (
        "src/a2a/transport_needles_tests.rs",
        include_str!("../../../../src/a2a/transport_needles_tests.rs"),
    ),
    (
        "src/gateway/meta_mcp/chain_withheld_tests.rs",
        include_str!("../../../../src/gateway/meta_mcp/chain_withheld_tests.rs"),
    ),
    (
        "src/gateway/ui/preview_secret_tests.rs",
        include_str!("../../../../src/gateway/ui/preview_secret_tests.rs"),
    ),
    (
        "src/security/needles_tests.rs",
        include_str!("../../../../src/security/needles_tests.rs"),
    ),
];

/// What a row file must not mention: an override claiming redaction, the
/// slot injection that installs a double, and the doubles and scripted
/// backends that claim it.
const BANNED: [&str; 7] = [
    "redacts_injected_values",
    "set_transport_for_test",
    "CountingBackend",
    "backend_transport(",
    "Backends::Scripted",
    "Recording {",
    "Recorder {",
];

fn violations(file: &str, text: &str) -> Vec<String> {
    BANNED
        .iter()
        .filter(|banned| text.contains(*banned))
        .map(|banned| format!("{file}: names `{banned}`"))
        .collect()
}

#[test]
fn echo_rows_never_use_a_double_that_claims_to_redact() {
    let mut wrong = Vec::new();
    for (file, text) in ROW_FILES {
        wrong.extend(violations(file, text));
    }
    assert!(
        wrong.is_empty(),
        "an echo or scrub row reaches a test double that claims to redact:\n{}",
        wrong.join("\n")
    );
}

/// The check's own proof: a row file installing a double is caught.
#[test]
fn a_row_installing_a_double_is_caught() {
    let planted = "backend.set_transport_for_test(Arc::new(CountingBackend { calls }));";
    assert_eq!(violations("planted.rs", planted).len(), 2);
    assert!(violations("clean.rs", "let url = echo_server(calls, reply).await;").is_empty());
}
