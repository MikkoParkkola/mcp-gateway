// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Code review round 1 rows: the remedies name only the gateway's origin, a refusal's reason is bounded, replay's
//! answer rules (over 16 MiB, a 2xx without JSON, exactly 16 MiB), and lookup's answer is redacted, with every
//! secret the run read handed to the emitter.

use super::*;

/// The credential remedy names the gateway's origin, never userinfo, a path or a query token from `--url`.
#[tokio::test]
async fn remedies_name_only_the_gateway_origin() {
    use super::super::dashboard_link::TokenError;
    let gw = gateway(json(200, r#"{"link":"https://gw/x"}"#)).await;
    let port = gw.base.rsplit(':').next().expect("a port").to_string();
    let dirty = format!("http://user:PW1@127.0.0.1:{port}/x?token=Q1");
    let remedy = format!("{TOKEN_REMEDY_PREFIX}http://127.0.0.1:{port}, then retry.");
    for (case, out) in [
        (
            "dashboard-link",
            link(&["--url", &dirty], Err(TokenError::Missing)).await,
        ),
        (
            "events",
            events(&["list", "--url", &dirty], Err(TokenError::Missing)).await,
        ),
        (
            "lookup",
            lookup(&["--url", &dirty], EMAIL.as_bytes(), None).await,
        ),
    ] {
        failed(
            &out,
            CliExit::AuthRefused,
            "No gateway credential is available.",
            &remedy,
            case,
        );
    }
    finish();
}

/// A refusal's reason holding a control character, or longer than 4 KiB, is named instead of printed; the
/// longest printable reason prints whole (both sides of the bound).
#[tokio::test]
async fn a_refusal_reason_is_bounded() {
    let long = "r".repeat(4097);
    let longest = "r".repeat(4096);
    for (case, reason, printed) in [
        (
            "newline",
            "line1\nline2".to_string(),
            "its reason cannot be printed".to_string(),
        ),
        (
            "escape",
            "red\u{1b}[31m".to_string(),
            "its reason cannot be printed".to_string(),
        ),
        (
            "over 4 KiB",
            long,
            "its reason cannot be printed".to_string(),
        ),
        ("4 KiB", longest.clone(), longest),
    ] {
        let body = serde_json::json!({ "message": reason }).to_string();
        let (_, outs) = all_three(json(400, &body)).await;
        for (command, out) in &outs {
            failed(
                out,
                CliExit::Gateway,
                &format!("The gateway answered HTTP 400: {printed}"),
                RESOLVE,
                &format!("{command} {case}"),
            );
        }
    }
    finish();
}

/// Replay is a mutation (design D3, D4): an answer over 16 MiB and a 2xx without JSON are 8 with the
/// uncertain-outcome sentences, since the replay may have run; an answer of exactly 16 MiB prints.
#[tokio::test]
async fn replay_answers_over_the_limit_or_without_json_are_uncertain() {
    const MIB16: usize = 16 * 1024 * 1024;
    let uncertain_what = "The gateway may have applied this change.";
    let mut exact = br#"{"items":[]}"#.to_vec();
    exact.resize(MIB16, b' ');
    for (case, body, want_ok) in [
        ("over 16 MiB", vec![b' '; MIB16 + 1], false),
        ("2xx without JSON", b"not json".to_vec(), false),
        ("exactly 16 MiB", exact, true),
    ] {
        let gw = gateway(Reply::Http {
            status: 200,
            headers: vec![("content-type", "application/json".to_string())],
            body,
        })
        .await;
        let out = events(&["replay", "dl-1", "--url", &gw.base], ok_token()).await;
        if want_ok {
            check_eq!(
                (out.exit(), out.stdout(), out.stderr()),
                (CliExit::Ok, &b"{\n  \"items\": []\n}\n"[..], ""),
                "{case}"
            );
        } else {
            failed(
                &out,
                CliExit::UncertainOutcome,
                uncertain_what,
                UNCERTAIN,
                case,
            );
        }
        check_eq!(
            gw.requests()
                .iter()
                .map(|seen| (seen.method.clone(), seen.path.clone()))
                .collect::<Vec<_>>(),
            vec![(
                "POST".to_string(),
                "/ui/api/events/dead-letters/dl-1/replay".to_string()
            )],
            "{case}: the replay reached the gateway once"
        );
    }
    finish();
}

/// A lookup answer echoing the token prints redacted (exit 0), as the other commands' answers do; a token holding a
/// quote is redacted before JSON escaping, so neither its raw nor its escaped form reaches stdout.
#[tokio::test]
async fn lookup_answers_are_redacted_before_printing() {
    for token in [TOKEN, "tok\"q"] {
        let answer = serde_json::json!({
            "rows": [{
                "timestamp": null, "token_jti": null, "subject": format!("held by {token}"),
                "issuer": null, "backends": null, "tools": null, "segment": 0
            }],
            "next_cursor": null, "scan_exhausted": true, "cursor_reset": false, "unreadable": 0, "scope": "all"
        });
        let gw = gateway(json(200, &answer.to_string())).await;
        let out = lookup(&["--url", &gw.base], EMAIL.as_bytes(), Some(token)).await;
        let printed = String::from_utf8_lossy(out.stdout()).to_string();
        let subject = serde_json::from_str::<serde_json::Value>(&printed)
            .ok()
            .and_then(|value| value["rows"][0]["subject"].as_str().map(str::to_string));
        check_eq!(
            (out.exit(), out.stderr(), subject.as_deref()),
            (CliExit::Ok, "", Some("held by [redacted]")),
            "{token:?}"
        );
        let escaped = token.replace('"', "\\\"");
        check!(
            !printed.contains(token) && !printed.contains(&escaped),
            "{token:?}: the token reached stdout"
        );
    }
    finish();
}

/// The run hands the emitter every secret it read: the token, then the email (design D5), so a write failure while
/// printing is gated on both; a run that stops at stdin read only the token.
#[tokio::test]
async fn lookup_hands_every_secret_it_read_to_the_emitter() {
    use super::input::Unreadable;
    let gw = gateway(json(200, LOOKUP_ANSWER)).await;
    let token = |name: &str| (name == "MCP_GATEWAY_TOKEN").then(|| TOKEN.to_string());
    let args = || {
        let Command::Audit(AuditCommand::LookupEmail(args)) =
            parse(&["audit", "lookup-email", "--email-stdin", "--url", &gw.base])
        else {
            panic!("not lookup-email")
        };
        args
    };
    let (out, secrets) =
        super::super::audit_lookup::lookup_run(args(), loaded, None, None, EMAIL.as_bytes(), token)
            .await;
    check_eq!(
        (out.exit(), secrets),
        (CliExit::Ok, vec![TOKEN.to_string(), EMAIL.to_string()]),
        "a full run"
    );
    let (out, secrets) =
        super::super::audit_lookup::lookup_run(args(), loaded, None, None, Unreadable, token).await;
    check_eq!(
        (out.exit(), secrets),
        (CliExit::LocalFailure, vec![TOKEN.to_string()]),
        "stopped at stdin"
    );
    finish();
}
