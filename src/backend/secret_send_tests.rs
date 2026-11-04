// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's own rules on its send: where each target goes, and what the
//! send refuses for a backend built in code, which config load never saw.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::secrets::SecretResolver;

/// The value every rule here holds unless a row says otherwise.
const SECRET: &str = "send-side-secret-ab07";

fn rule(inject_as: InjectTarget, key: &str, value: &str) -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: value.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    }
}

/// Backend `svc` over `transport` holding `rules`, stamped with a resolver
/// when `resolved` (as the gateway's registry stamps every backend).
fn backend(transport: TransportConfig, rules: Vec<CredentialRule>, resolved: bool) -> Backend {
    let backend = Backend::new(
        "svc",
        BackendConfig {
            transport,
            secrets: rules,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    if resolved {
        backend.stamp_secret_resolver(Arc::new(SecretResolver::new()));
    }
    backend
}

fn http() -> TransportConfig {
    TransportConfig::default()
}

/// What a send carries: its params and its headers.
type Sent = (Option<Value>, Vec<(String, String)>);

/// The params and headers `backend` sends for `params`, given `headers`.
fn send(backend: &Backend, params: Value, headers: Vec<(String, String)>) -> crate::Result<Sent> {
    let (params, headers, _) = backend
        .prepare_secrets("tools/call", Some(params))?
        .apply(headers);
    Ok((params, headers))
}

#[test]
fn a_call_with_no_arguments_member_still_gets_the_argument() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        true,
    );
    let (params, _) = send(&backend, json!({"name": "read"}), Vec::new()).expect("sent");
    assert_eq!(
        params.and_then(|p| p.pointer("/arguments/api_key").cloned()),
        Some(json!(SECRET))
    );
}

#[test]
fn a_header_replaces_one_of_the_same_name_whatever_its_case() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    let held = vec![
        ("x-api-key".to_string(), "caller-held".to_string()),
        ("X-Other".to_string(), "kept".to_string()),
    ];
    let (_, headers) =
        send(&backend, json!({"name": "read", "arguments": {}}), held).expect("sent");
    let named: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("X-Api-Key"))
        .collect();
    assert_eq!(
        named,
        [&("X-Api-Key".to_string(), SECRET.to_string())],
        "{headers:?}"
    );
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "X-Other" && value == "kept")
    );
}

#[test]
fn a_rule_that_resolves_empty_injects_nothing_and_still_drops_the_caller_value() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", "")],
        true,
    );
    let params = json!({"name": "read", "arguments": {"api_key": "caller-chosen", "q": 1}});
    let (params, _) = send(&backend, params, Vec::new()).expect("sent");
    let arguments = params.expect("params").pointer("/arguments").cloned();
    assert_eq!(arguments, Some(json!({"q": 1})));
}

/// The refusal: a configuration error naming the backend and the rule, and
/// never the value.
fn refused(backend: &Backend, why: &str) {
    let error = send(
        backend,
        json!({"name": "read", "arguments": {}}),
        Vec::new(),
    )
    .expect_err("the call is refused")
    .to_string();
    assert!(
        error.contains("backend 'svc' secret rule 'api'") && error.contains(why),
        "{error}"
    );
    assert!(
        !error.contains(SECRET),
        "the refusal echoed the value: {error}"
    );
}

/// A backend transport that counts every request it receives.
struct Counting(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [], "isError": false}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Set in the nested run's process environment only.
const PROCESS_KEY: &str = "SEND_SIDE_PROCESS_KEY";
/// The value the process environment holds for [`PROCESS_KEY`].
const PROCESS_VALUE: &str = "process-env-value-ef09";
/// Present in the nested run, which makes the assertions.
const SCENARIO_ENV: &str = "MCP_GATEWAY_TEST_UNSTAMPED_RESOLVER_SCENARIO";
const SCENARIO: &str = "backend::secret_send::tests::unstamped_resolver_scenario";

/// A backend no registry stamped refuses a call its rule applies to, and
/// never reads the process environment in place of the gateway's: the test
/// binary reruns with a variable the rule names set in its own environment,
/// since setting one in-process needs `unsafe`.
#[tokio::test]
async fn a_backend_no_registry_stamped_refuses_rather_than_resolve_the_process_environment() {
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", SCENARIO, "--nocapture"])
        .env(SCENARIO_ENV, "1")
        .env(PROCESS_KEY, PROCESS_VALUE)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the scenario");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed") && stdout.contains(SCENARIO),
        "the scenario failed or did not run; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
fn unstamped_resolver_scenario() {
    if std::env::var_os(SCENARIO_ENV).is_none() {
        return;
    }
    assert_eq!(
        std::env::var(PROCESS_KEY).as_deref(),
        Ok(PROCESS_VALUE),
        "premise: the process environment holds the value"
    );
    let reference = format!("{{env.{PROCESS_KEY}}}");
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", &reference)],
        false,
    );
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(&received))));
    let mut result = None;
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let params = json!({"name": "read", "arguments": {}});
        result = Some(runtime.block_on(backend.request("tools/call", Some(params))));
    });
    let error = match result.expect("the call ran") {
        Err(error) => error,
        Ok(answer) => panic!("the call was not refused: {answer:?}"),
    };
    assert_eq!(
        received.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the backend received a request"
    );
    assert!(
        matches!(error, crate::Error::Config(_)),
        "not the non-retryable configuration error: {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("backend 'svc' secret rule 'api'")
            && message.contains("has no secret resolver"),
        "{message}"
    );
    assert!(
        !message.contains(PROCESS_VALUE),
        "the refusal holds the value: {message}"
    );
    let logged = serde_json::to_string(&records).expect("records serialise");
    assert!(
        !logged.contains(PROCESS_VALUE),
        "a log record holds the value"
    );
}

#[test]
fn a_query_rule_is_refused_on_the_send() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Query, "api_key", SECRET)],
        true,
    );
    refused(&backend, "URL query parameter");
}

#[test]
fn a_header_rule_on_a_transport_without_request_headers_is_refused_on_the_send() {
    let stdio = TransportConfig::Stdio {
        command: "/bin/true".to_string(),
        cwd: None,
        protocol_version: None,
    };
    let backend = backend(
        stdio,
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    refused(&backend, "sends no request headers");
}

#[cfg(feature = "a2a")]
#[test]
fn any_rule_on_an_a2a_backend_is_refused_on_the_send() {
    let a2a = TransportConfig::A2a {
        a2a_url: "https://agent.example.com".to_string(),
        a2a_agent_card_path: None,
    };
    let backend = backend(
        a2a,
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        true,
    );
    refused(&backend, "A2A backend");
}

#[test]
fn a_header_value_that_is_not_a_valid_header_value_is_refused_without_echoing_it() {
    let value = "line-one\nline-two-cd08";
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", value)],
        true,
    );
    let mut error = String::new();
    // The refusal comes before the audit line, so a refused call is never
    // logged as injected.
    let logged = crate::test_log_capture::records(|| {
        error = send(
            &backend,
            json!({"name": "read", "arguments": {}}),
            Vec::new(),
        )
        .expect_err("the call is refused")
        .to_string();
    });
    assert!(
        error.contains("secret rule 'api'") && error.contains("not a valid HTTP header value"),
        "{error}"
    );
    assert!(
        !error.contains("line-two-cd08"),
        "the refusal echoed the value: {error}"
    );
    let injected: Vec<_> = logged
        .iter()
        .filter(|record| record["fields"]["message"] == "Secret injected")
        .collect();
    assert!(
        injected.is_empty(),
        "a refused call was logged as injected: {injected:?}"
    );
    assert!(
        !logged
            .iter()
            .any(|record| record.to_string().contains("line-two-cd08")),
        "a log record holds the value"
    );
}

#[test]
fn a_call_no_rule_matches_is_sent_untouched() {
    let mut scoped = rule(InjectTarget::Argument, "api_key", SECRET);
    scoped.tools = vec!["write_*".to_string()];
    let backend = backend(http(), vec![scoped], false);
    let params = json!({"name": "read", "arguments": {"api_key": "caller"}});
    let (sent, _) = send(&backend, params.clone(), Vec::new()).expect("sent");
    assert_eq!(sent, Some(params));
}

#[test]
fn a_header_rule_that_resolves_empty_still_keeps_its_header_off_the_call() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", "")],
        true,
    );
    let held = vec![("x-api-key".to_string(), "caller-held".to_string())];
    let (_, headers) =
        send(&backend, json!({"name": "read", "arguments": {}}), held).expect("sent");
    assert!(
        !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("X-Api-Key")),
        "a header the rule owns went out: {headers:?}"
    );
}

#[test]
fn an_argument_rule_refuses_arguments_that_are_not_an_object() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        true,
    );
    let error = send(
        &backend,
        json!({"name": "read", "arguments": [1]}),
        Vec::new(),
    )
    .expect_err("the call is refused")
    .to_string();
    assert!(
        error.contains("secret rule 'api'") && error.contains("not an object"),
        "{error}"
    );
    assert!(
        !error.contains(SECRET),
        "the refusal echoed the value: {error}"
    );
}

/// What a deferred task's poll renews: each value the dispatch sent, in the
/// form it was sent, so an unchanged secret older than its grace is still
/// removed from the answer. Without the renewal the same value retires.
#[tokio::test(start_paused = true)]
async fn a_renewal_keeps_an_unchanged_value_redacted_past_its_grace() {
    use crate::security::needles::{NeedleSet, scrub_text};
    const GRACE: Duration = Duration::from_secs(60);
    // Inside one grace, and two of them together past it.
    const STEP: Duration = Duration::from_secs(50);
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    let needles = Arc::new(NeedleSet::with_grace(GRACE));
    backend.stamp_needles(Arc::clone(&needles));
    let arguments = json!({"q": "kept"});
    send(
        &backend,
        json!({"name": "read", "arguments": arguments}),
        Vec::new(),
    )
    .expect("sent");
    let echoed = || {
        let mut text = format!("echo {SECRET}");
        scrub_text(&needles, &mut text);
        text.contains(SECRET)
    };
    assert!(!echoed(), "premise: a sent value is redacted");

    tokio::time::advance(STEP).await;
    let stored = crate::security::dispatched::Dispatched::of(
        "svc",
        &[("api".to_owned(), SECRET.to_owned())],
    )
    .stored();
    assert!(backend.vouch_and_renew("read", &arguments, Some(&stored)));
    tokio::time::advance(STEP).await;
    assert!(
        !echoed(),
        "a renewed value is redacted past the dispatch's grace"
    );

    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(echoed(), "premise: an unrenewed value retires on its grace");
}

/// A deferring dispatch resolves its rules once: what its slot fingerprints
/// and what it injects are one resolution, so a rotation between two
/// lookups cannot fingerprint one value and send another. The slot is armed
/// as `with_upstream_submission` arms it, so the fingerprint is taken.
#[tokio::test]
async fn a_deferring_send_resolves_its_rules_once() {
    use crate::security::dispatched::{Dispatched, Slot, scope};
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    let slot = Arc::new(Slot::armed_for("svc", "read"));
    let before = crate::secrets::lookup_probe::calls();
    let (_, headers) = scope(Arc::clone(&slot), async {
        send(
            &backend,
            json!({"name": "read", "arguments": {}}),
            Vec::new(),
        )
        .expect("sent")
    })
    .await;
    assert_eq!(crate::secrets::lookup_probe::calls() - before, 1);
    assert!(
        headers.iter().any(|(_, value)| value == SECRET),
        "premise: it was sent"
    );
    assert_eq!(
        slot.value(),
        Some(Dispatched::of(
            "svc",
            &[("api".to_owned(), SECRET.to_owned())]
        )),
        "the slot fingerprints the value sent"
    );
}

/// Rules that do not apply to the tool, or resolve empty, sit between the
/// applying ones: the fingerprint, the injection and the redaction set each
/// take exactly the applying, non-empty values, each from its own rule.
#[tokio::test]
async fn a_deferring_send_keeps_each_value_with_its_own_rule() {
    use crate::security::dispatched::{Dispatched, Slot, scope};
    use crate::security::needles::{NeedleSet, scrub_text};
    const ARG: &str = "mixed-argument-secret-77d0";
    const HEAD: &str = "mixed-header-secret-77d0";
    const OTHER: &str = "mixed-other-tool-secret-77d0";
    let mut argument = rule(InjectTarget::Argument, "api_key", ARG);
    argument.name = "arg".to_owned();
    let mut other = rule(InjectTarget::Argument, "other_key", OTHER);
    other.name = "other".to_owned();
    other.tools = vec!["write".to_owned()];
    let mut empty = rule(
        InjectTarget::Argument,
        "empty_key",
        "{env.MIXED_RULES_NEVER_SET_77d0:-}",
    );
    empty.name = "empty".to_owned();
    let mut header = rule(InjectTarget::Header, "X-Api-Key", HEAD);
    header.name = "head".to_owned();
    let backend = backend(http(), vec![argument, other, empty, header], true);
    let needles = Arc::new(NeedleSet::default());
    backend.stamp_needles(Arc::clone(&needles));
    let slot = Arc::new(Slot::armed_for("svc", "read"));
    let (params, headers) = scope(Arc::clone(&slot), async {
        send(
            &backend,
            json!({"name": "read", "arguments": {}}),
            Vec::new(),
        )
        .expect("sent")
    })
    .await;
    assert_eq!(
        slot.value(),
        Some(Dispatched::of(
            "svc",
            &[
                ("arg".to_owned(), ARG.to_owned()),
                ("head".to_owned(), HEAD.to_owned()),
            ]
        ))
    );
    let arguments = params.and_then(|p| p.get("arguments").cloned());
    assert_eq!(
        arguments,
        Some(json!({"api_key": ARG})),
        "only the applying argument"
    );
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "X-Api-Key" && value == HEAD)
    );
    for (value, held) in [(ARG, true), (HEAD, true), (OTHER, false)] {
        let mut text = format!("echo {value}");
        scrub_text(&needles, &mut text);
        assert_eq!(!text.contains(value), held, "{value}: {text}");
    }
}

/// A call whose rules fail both to resolve and to inject reports the
/// resolution failure: every rule is resolved before any is injected, so a
/// dispatch never injects from a partial resolution.
#[test]
fn a_resolution_failure_is_reported_before_an_injection_refusal() {
    let mut bad_header = rule(InjectTarget::Header, "X-Api-Key", "bad\nvalue");
    bad_header.name = "first".to_owned();
    let mut unresolvable = rule(
        InjectTarget::Argument,
        "api_key",
        "{env.PRECEDENCE_NEVER_SET_77d0}",
    );
    unresolvable.name = "second".to_owned();
    let backend = backend(http(), vec![bad_header, unresolvable], true);
    let error = send(
        &backend,
        json!({"name": "read", "arguments": {}}),
        Vec::new(),
    )
    .expect_err("refused");
    let text = error.to_string();
    assert!(
        text.contains("Failed to resolve credential 'second'"),
        "{text}"
    );
}
