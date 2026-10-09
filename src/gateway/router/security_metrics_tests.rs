// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D4 (MIK-7570.METRICS.2): authentication failures and authorization
//! denials are counted by kind and route, with constant labels only.
//! A child of `direct_audit_tests`, whose fixture drives the real router.

use super::*;

/// Run `f` with a recorder scoped to this thread; return its output and the
/// Prometheus text. A per-test recorder: the global one is shared across
/// parallel tests and would make every delta flake.
fn scrape<F: std::future::Future>(f: F) -> (F::Output, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let out = telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    });
    (out, handle.render())
}

/// Sample lines of `name`: `# HELP`/`# TYPE` lines never start with it.
fn samples<'a>(rendered: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let prefix = format!("{name}{{");
    rendered.lines().filter(move |l| l.starts_with(&prefix))
}

/// A sample's value. The exposition format writes numbers as floats.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn value(line: &str) -> u64 {
    let v: f64 = line
        .rsplit(' ')
        .next()
        .unwrap_or_default()
        .parse()
        .expect("sample value");
    v as u64
}

/// The value of the `name` series carrying every `k="v"` pair in `labels`
/// (comma separated, in any order), 0 when absent.
fn series(rendered: &str, name: &str, labels: &str) -> u64 {
    samples(rendered, name)
        .find(|l| labels.split(',').all(|pair| l.contains(pair)))
        .map_or(0, value)
}

/// Sum of every `name` sample whose line contains `needle`.
fn sum_where(rendered: &str, name: &str, needle: &str) -> u64 {
    samples(rendered, name)
        .filter(|l| l.contains(needle))
        .map(value)
        .sum()
}

const AUTH: &str = "mcp_auth_failures_total";
const DENY: &str = "mcp_authz_denials_total";

fn expiring_key(expires_at: Option<chrono::DateTime<chrono::Utc>>, rate_limit: u32) -> AuthConfig {
    let mut auth = key_for_alpha(None);
    auth.api_keys[0].expires_at = expires_at;
    auth.api_keys[0].rate_limit = rate_limit;
    auth
}

async fn raw(fx: &Fixture, method: &str, uri: &str, bearer: Option<&str>) -> StatusCode {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = builder
        .body(axum::body::Body::from(tools_call("t")))
        .unwrap();
    fx.router.clone().oneshot(request).await.unwrap().status()
}

/// D4-T1. No credential, then a wrong one, each counted once by kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_and_invalid_credential_are_counted_by_kind() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let ((none, wrong), text) = scrape(async {
        (
            raw(&fx, "POST", "/mcp/alpha", None).await,
            raw(&fx, "POST", "/mcp/alpha", Some("wrong")).await,
        )
    });
    assert_eq!(
        (none, wrong),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        series(&text, AUTH, r#"kind="missing_credential""#),
        1,
        "{text}"
    );
    assert_eq!(
        series(&text, AUTH, r#"kind="invalid_credential""#),
        1,
        "{text}"
    );
}

/// An expired key is its own kind, and not also an invalid credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_api_key_is_counted_once_as_expired() {
    let past = chrono::Utc::now() - crate::duration_bound::delta!(seconds, 5);
    let fx = fixture(Setup {
        auth: Some(expiring_key(Some(past), 0)),
        ..Setup::default()
    })
    .await;
    let (status, text) = scrape(raw(&fx, "POST", "/mcp/alpha", Some("k")));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        series(&text, AUTH, r#"kind="expired_api_key""#),
        1,
        "{text}"
    );
    assert_eq!(
        series(&text, AUTH, r#"kind="invalid_credential""#),
        0,
        "{text}"
    );
}

/// D4-T3 (positive control). A rate-limited key authenticated; it is not an
/// auth failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_is_not_an_auth_failure() {
    let fx = fixture(Setup {
        auth: Some(expiring_key(None, 1)),
        ..Setup::default()
    })
    .await;
    let (statuses, text) = scrape(async {
        let mut out = Vec::new();
        for _ in 0..3 {
            out.push(raw(&fx, "POST", "/mcp/alpha", Some("k")).await);
        }
        out
    });
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
    assert_eq!(sum_where(&text, AUTH, ""), 0, "{text}");
}

/// A refused dashboard bootstrap link is an auth failure of its own kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_bootstrap_is_counted() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    // No connect info: not a local peer, so the link is refused (401).
    let (status, text) = scrape(raw(&fx, "GET", "/dashboard?bootstrap=nope", None));
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        series(&text, AUTH, r#"kind="bootstrap_refused""#),
        1,
        "{text}"
    );
}

/// D4-T2. Token-exchange refusals are counted where they are emitted, and an
/// issued token is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_exchange_refusals_are_counted() {
    use crate::key_server::audit::{AuditEvent, emit};
    let ((), text) = scrape(async {
        emit(&AuditEvent::denied("policy miss", None));
        emit(&AuditEvent::invalid("bad jwt", None));
        emit(&AuditEvent::revoked("jti-1", None));
    });
    assert_eq!(
        sum_where(&text, AUTH, ""),
        2,
        "only the refusals count: {text}"
    );
    assert_eq!(
        series(&text, AUTH, r#"kind="token_exchange_denied""#),
        1,
        "{text}"
    );
    assert_eq!(
        series(&text, AUTH, r#"kind="token_exchange_invalid""#),
        1,
        "{text}"
    );
}

/// D4-T5. A direct-route scope refusal is one `direct` denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_scope_denial_counted() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let ((status, _), text) = scrape(post(&fx, "beta", &tools_call("t"), &Caller::Key));
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        series(&text, DENY, r#"reason="backend_scope",route="direct""#),
        1,
        "{text}"
    );
    assert_eq!(
        sum_where(&text, DENY, ""),
        1,
        "one denial, one count: {text}"
    );
}

fn deny_all_caller() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        authorizer: &crate::gateway::authz::DenyAll,
        is_modern: false,
        era: crate::protocol::meta::Era::Legacy,
        ..anonymous_caller()
    }
}

async fn meta_invoke(meta: &MetaMcp) {
    let _ = meta
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_invoke",
            json!({"server": "alpha", "tool": "t", "arguments": {}}),
            None,
            deny_all_caller(),
        )
        .await;
}

/// D4-T4 shape: a meta-route refusal is counted exactly once, beside its
/// `denied` record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_denial_counted_once() {
    let fx = fixture(Setup::default()).await;
    let ((), text) = scrape(meta_invoke(&fx.state.meta_mcp));
    assert_eq!(only_invocation(&fx)["outcome"], "denied");
    assert_eq!(
        series(&text, DENY, r#"reason="backend_scope",route="meta""#),
        1,
        "{text}"
    );
    assert_eq!(sum_where(&text, DENY, ""), 1, "{text}");
}

/// D4-T6. With auth off and no audit log, a refusal is still counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denial_counted_with_auth_off_and_no_log() {
    let fx = fixture(Setup::default()).await;
    let meta = MetaMcp::new(Arc::clone(&fx.state.backends));
    let ((), text) = scrape(meta_invoke(&meta));
    assert_eq!(sum_where(&text, DENY, r#"route="meta""#), 1, "{text}");
}

/// The admin meta-tool gate counts a refusal, with or without a log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_gate_refusal_counted_without_a_log() {
    let (verdict, text) = scrape(super::super::authorization::require_admin_tool_access(
        None,
        None,
        None,
        "gateway_kill_server",
    ));
    assert!(verdict.is_err());
    assert_eq!(
        series(&text, DENY, r#"reason="admin_required",route="admin""#),
        1,
        "{text}"
    );
}

/// An admin UI mutation by a non-admin is a `ui` denial; a control-plane
/// refusal is its own route, never also `ui`.
#[cfg(feature = "webui")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_ui_and_control_plane_denials_counted_by_route() {
    let fx = fixture(Setup::default()).await;
    let ((reload, grants), text) = scrape(async {
        (
            raw(&fx, "POST", "/ui/api/reload", None).await,
            raw(&fx, "POST", "/ui/api/control-plane/grants", None).await,
        )
    });
    assert!(
        matches!(reload, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
        "{reload}"
    );
    assert!(
        matches!(grants, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
        "{grants}"
    );
    assert_eq!(
        series(&text, DENY, r#"reason="admin_required",route="ui""#),
        1,
        "{text}"
    );
    assert_eq!(
        series(&text, DENY, r#"reason="rbac",route="control_plane""#),
        1,
        "{text}"
    );
    assert_eq!(sum_where(&text, DENY, ""), 2, "each refusal once: {text}");
}

/// D4-T7. Labels are constants: no key name, backend, tool or path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metric_labels_carry_no_caller_data() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let ((), text) = scrape(async {
        let _ = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
        let _ = raw(&fx, "POST", "/mcp/alpha", Some("wrong-SECRET")).await;
    });
    assert!(
        sum_where(&text, DENY, "") > 0 && sum_where(&text, AUTH, "") > 0,
        "nothing counted: {text}"
    );
    for line in samples(&text, DENY).chain(samples(&text, AUTH)) {
        for leak in ["alpha-client", "beta", "SECRET", "/mcp", "\"t\""] {
            assert!(!line.contains(leak), "{leak} in {line}");
        }
    }
}

/// A scope refusal on `POST /mcp` is answered by the router before the meta
/// layer runs; it is still one `meta` denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_meta_scope_refusal_counted_once() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"tool": "beta:t", "arguments": {}}}});
    let (status, text) = scrape(async {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", "Bearer k")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        fx.router.clone().oneshot(request).await.unwrap().status()
    });
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(sum_where(&text, DENY, r#"route="meta""#), 1, "{text}");
    assert_eq!(sum_where(&text, DENY, ""), 1, "{text}");
}
