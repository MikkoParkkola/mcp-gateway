// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan T11 (design D9): `api` is moved, not changed. Its failure matrix runs here, and every case's
//! whole exit, stdout and stderr must equal the literal captured from the release line before the move
//! (88772b2615, `api_matrix_capture.tsv`), with only the three declared remedy lines (missing token, 401, 403)
//! rewritten. The capture is never regenerated from this tree: a change here shows as a changed case.

use super::*;

/// The request origin every case uses; it appears in the credential remedies.
const ORIGIN: &str = "http://127.0.0.1:1";
/// The statuses D9 names.
const STATUSES: [u16; 10] = [200, 401, 403, 404, 409, 422, 428, 429, 500, 503];
/// Body dispositions: none, not_run, may_have_run.
const DISPOSITIONS: [Option<&str>; 3] = [None, Some("not_run"), Some("may_have_run")];
/// Gateway codes: none, state_uncertain, may_have_run, unsupported_version.
const CODES: [Option<&str>; 4] = [
    None,
    Some("state_uncertain"),
    Some("may_have_run"),
    Some("unsupported_version"),
];
const KINDS: [AdminFailureKind; 8] = [
    AdminFailureKind::Target,
    AdminFailureKind::LocalIo,
    AdminFailureKind::Settings,
    AdminFailureKind::Dns,
    AdminFailureKind::Connect,
    AdminFailureKind::Tls,
    AdminFailureKind::ResponseLost,
    AdminFailureKind::ResponseTooLarge,
];

/// One case: what the sender answers, with which token.
enum Answer {
    Status(u16, Vec<u8>),
    Transport(AdminFailureKind),
    NoToken,
}

/// Runs one case and renders it as one capture line: `case<TAB>exit<TAB>stdout<TAB>stderr`, both outputs
/// ASCII-escaped so the line holds no tab or newline of its own.
async fn line(
    case: &str,
    method: ApiMethod,
    json_output: bool,
    token: &str,
    answer: Answer,
) -> String {
    let mut a = args("/ui/api/keys");
    a.method = method;
    a.json = json_output;
    let token = token.to_string();
    let no_token = matches!(answer, Answer::NoToken);
    let out = run_api_with(
        &a,
        ORIGIN,
        &LinkTls::default(),
        move |_| (!no_token).then(|| token.clone()),
        no_stdin,
        move |_| {
            let reply = match answer {
                Answer::Status(status, body) => Ok(AdminResponse {
                    status: reqwest::StatusCode::from_u16(status).expect("status"),
                    headers: reqwest::header::HeaderMap::new(),
                    body,
                }),
                Answer::Transport(kind) => Err(AdminCallError {
                    kind,
                    detail: "matrix transport detail".to_string(),
                    status: None,
                    request_id: None,
                }),
                Answer::NoToken => unreachable!("no request without a token"),
            };
            async move { reply }
        },
    )
    .await;
    format!(
        "{case}\t{}\t{}\t{}",
        out.exit().code(),
        out.stdout().escape_ascii(),
        out.stderr().as_bytes().escape_ascii()
    )
}

/// The grid body for one disposition and code.
fn grid_body(disposition: Option<&str>, code: Option<&str>) -> Vec<u8> {
    let mut body = serde_json::Map::new();
    if let Some(disposition) = disposition {
        body.insert("disposition".into(), disposition.into());
    }
    if let Some(code) = code {
        body.insert("error".into(), json!({ "code": code }));
    }
    serde_json::to_vec(&body).expect("body")
}

/// Every case of D9's matrix, in a fixed order.
async fn matrix() -> Vec<String> {
    let mut lines = Vec::new();
    for json_output in [false, true] {
        let form = if json_output { "json" } else { "human" };
        let methods = [("GET", ApiMethod::Get), ("POST", ApiMethod::Post)];
        lines.push(
            line(
                &format!("{form} GET no-token"),
                ApiMethod::Get,
                json_output,
                TOKEN,
                Answer::NoToken,
            )
            .await,
        );
        for (verb, method) in &methods {
            for kind in KINDS {
                let case = format!("{form} {verb} transport {kind:?}");
                lines.push(
                    line(
                        &case,
                        method.clone(),
                        json_output,
                        TOKEN,
                        Answer::Transport(kind),
                    )
                    .await,
                );
            }
            for status in STATUSES {
                for disposition in DISPOSITIONS {
                    for code in CODES {
                        let case = format!(
                            "{form} {verb} {status} disposition={} code={}",
                            disposition.unwrap_or("-"),
                            code.unwrap_or("-")
                        );
                        let answer = Answer::Status(status, grid_body(disposition, code));
                        lines.push(line(&case, method.clone(), json_output, TOKEN, answer).await);
                    }
                }
            }
            let rpc = br#"{"jsonrpc":"2.0","error":{"code":-32003,"message":"backend unavailable"},"id":null}"#;
            let case = format!("{form} {verb} 503 jsonrpc -32003");
            lines.push(
                line(
                    &case,
                    method.clone(),
                    json_output,
                    TOKEN,
                    Answer::Status(503, rpc.to_vec()),
                )
                .await,
            );
        }
        let lossy = br##"{"#":"first","[redacted]":"second"}"##.to_vec();
        let case = format!("{form} GET 200 entry-losing body, token #");
        lines.push(
            line(
                &case,
                ApiMethod::Get,
                json_output,
                "#",
                Answer::Status(200, lossy),
            )
            .await,
        );
        for token in [":", "{"] {
            let case = format!("{form} GET 200 success, token {token}");
            let body = br#"{"note":"a:b{c","n":1}"#.to_vec();
            lines.push(
                line(
                    &case,
                    ApiMethod::Get,
                    json_output,
                    token,
                    Answer::Status(200, body),
                )
                .await,
            );
        }
    }
    lines
}

/// The three remedy lines D4 changes, as (before, after). Every other byte of every case stays as captured.
fn declared_changes() -> [(String, String); 2] {
    [
        (
            format!("Run mcp-gateway login --gateway {ORIGIN}, then retry."),
            format!("Set MCP_GATEWAY_TOKEN to a valid token for {ORIGIN}, then retry."),
        ),
        (
            format!(
                "Use an entitled credential; run mcp-gateway login --gateway {ORIGIN} with an account permitted to perform this operation, then retry."
            ),
            format!("Use a token permitted to perform this operation for {ORIGIN}, then retry."),
        ),
    ]
}

/// T11: every case equals its capture from before the move, with only the declared remedy lines rewritten.
#[tokio::test]
async fn api_matches_its_capture_from_before_the_move() {
    let mut expected: Vec<String> = include_str!("api_matrix_capture.tsv")
        .lines()
        .map(str::to_string)
        .collect();
    for line in &mut expected {
        for (before, after) in declared_changes() {
            *line = line.replace(&before, &after);
        }
    }
    let actual = matrix().await;
    let misses: Vec<String> = expected
        .iter()
        .zip(&actual)
        .filter(|(want, got)| want != got)
        .map(|(want, got)| format!(" want: {want}\n  got: {got}"))
        .collect();
    assert_eq!(
        (expected.len(), misses.len()),
        (actual.len(), 0),
        "case count, then mismatches:\n{}",
        misses.join("\n")
    );
}

/// T12: api's three changed remedy lines (missing token, 401, 403) are D4's `MCP_GATEWAY_TOKEN` sentences, written
/// out whole (no login command exists yet).
#[tokio::test]
async fn api_credential_remedies_name_the_token_variable() {
    let get = |case: &'static str, answer| line(case, ApiMethod::Get, false, TOKEN, answer);
    let got = [
        get("no-token", Answer::NoToken).await,
        get("401", Answer::Status(401, b"{}".to_vec())).await,
        get("403", Answer::Status(403, b"{}".to_vec())).await,
    ];
    assert_eq!(
        got,
        [
            "no-token\t3\t\terror: No gateway credential is available.\\nSet MCP_GATEWAY_TOKEN to a valid token for http://127.0.0.1:1, then retry.\\n",
            "401\t3\t\terror: The gateway rejected this credential.\\nSet MCP_GATEWAY_TOKEN to a valid token for http://127.0.0.1:1, then retry.\\n",
            "403\t3\t\terror: This credential is not permitted to perform this operation.\\nUse a token permitted to perform this operation for http://127.0.0.1:1, then retry.\\n",
        ]
    );
}
