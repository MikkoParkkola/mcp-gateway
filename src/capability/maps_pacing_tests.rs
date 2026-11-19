// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pacing rows (RL): per-host pacing, driven through `CapabilityBackend` over
//! the `.test`-hostname harness (`maps_harness`). Every row has its own
//! hostname, so its own host key; definitions carry no `cache:` block unless
//! the row is about the cache, and repeated calls use distinct arguments.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::capability::maps_harness::{Names, Reply, Stub, executor};
use crate::capability::pacing::{HostKey, host_key};
use crate::capability::{CapabilityBackend, CapabilityDefinition};

/// A REST capability `name` calling `url`, paced at `interval_ms` when given,
/// cached when `cached`.
fn cap(name: &str, url: &str, interval_ms: Option<u64>, cached: bool) -> CapabilityDefinition {
    cap_full(name, url, interval_ms, cached, "")
}

/// [`cap`] with `extra` lines under the provider (each indented 4 spaces).
fn cap_full(
    name: &str,
    url: &str,
    interval_ms: Option<u64>,
    cached: bool,
    extra: &str,
) -> CapabilityDefinition {
    let rate = match interval_ms {
        Some(ms) => format!("{extra}    rate_limit:\n      interval_ms: {ms}\n"),
        None => extra.to_owned(),
    };
    let cache = if cached {
        // `is_cacheable` needs both (definition/mod.rs:636).
        "metadata:\n  read_only: true\ncache:\n  strategy: exact\n  ttl: 600\n"
    } else {
        ""
    };
    let yaml = format!(
        r#"fulcrum: "1.0"
name: {name}
description: d
schema:
  input:
    type: object
    properties:
      q:
        type: string
{cache}providers:
  primary:
    service: rest
{rate}    config:
      endpoint: {url}
      method: GET
      params:
        q: "{{q}}"
"#
    );
    let def = crate::capability::parse_capability(&yaml).expect("capability");
    // Premise (W3-2): only a row about the cache can be answered from it.
    assert_eq!(
        def.is_cacheable(),
        cached,
        "cacheability premise for {name}"
    );
    def
}

fn backend(names: Names, caps: Vec<CapabilityDefinition>) -> CapabilityBackend {
    let backend = CapabilityBackend::new("maps", Arc::new(executor(names)));
    for c in caps {
        backend.register_capability(c).expect("registered");
    }
    backend
}

async fn call(backend: &CapabilityBackend, name: &str, q: &str) -> crate::Result<()> {
    backend.call_tool(name, json!({ "q": q })).await.map(|_| ())
}

/// The refusal text for `host` at `interval_ms`, up to the retry-after
/// number, and that number.
fn refusal_wait(err: &crate::Error, host: &str, interval_ms: u64) -> u64 {
    let text = err.to_string();
    let head = format!(
        "Rate limit exceeded for backend '{host}: one request per {interval_ms} ms; retry after "
    );
    let rest = text
        .strip_prefix(&head)
        .unwrap_or_else(|| panic!("refusal text: {text}"));
    let wait = rest
        .strip_suffix(" ms'")
        .unwrap_or_else(|| panic!("refusal text: {text}"));
    wait.parse()
        .unwrap_or_else(|_| panic!("retry-after: {text}"))
}

/// Premise: the key pacing seeded for `url` is the key of the dispatched URL.
fn assert_key(url: &str, host: &str, port: u16) {
    assert_eq!(
        host_key(url),
        Some(HostKey {
            host: host.to_owned(),
            port,
        })
    );
}

// ── R0: the harness reaches the stub ────────────────────────────────

#[tokio::test]
async fn r0_an_unpaced_call_reaches_the_stub_once() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![cap("r0", &stub.url("r0.test", "/s"), None, false)],
    );
    call(&b, "r0", "a").await.expect("admitted");
    assert_eq!(stub.count(), 1);
    assert_eq!(stub.seen()[0].query, vec![("q".to_owned(), "a".to_owned())]);
}

// ── RL1-RL5 ──────────────────────────────────────────────────────────

#[tokio::test]
async fn rl1_the_first_paced_call_is_admitted() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl1.test", "/s");
    assert_key(&url, "rl1.test", stub.port);
    let b = backend(
        Names::default(),
        vec![cap("rl1", &url, Some(30_000), false)],
    );
    call(&b, "rl1", "a").await.expect("admitted");
    assert_eq!(stub.count(), 1);
}

#[tokio::test]
async fn rl2_a_second_call_within_the_interval_is_refused() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![cap("rl2", &stub.url("rl2.test", "/s"), Some(30_000), false)],
    );
    call(&b, "rl2", "a").await.expect("admitted");
    let err = call(&b, "rl2", "b").await.expect_err("refused");
    let wait = refusal_wait(&err, "rl2.test", 30_000);
    assert!(wait > 0 && wait <= 30_000, "retry-after {wait}");
    assert_eq!(stub.count(), 1, "the refused call never reached the stub");
}

#[tokio::test]
async fn rl3_a_call_after_the_interval_is_admitted() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![cap("rl3", &stub.url("rl3.test", "/s"), Some(300), false)],
    );
    call(&b, "rl3", "a").await.expect("admitted");
    // timing-oracle: vs 300 ms rate_limit interval (why: a slow runner only lengthens the sleep, so the 300 ms interval has always passed)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    call(&b, "rl3", "b")
        .await
        .expect("admitted after the interval");
    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn rl4_another_host_has_its_own_bucket() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl4a", &stub.url("rl4a.test", "/s"), Some(30_000), false),
            cap("rl4b", &stub.url("rl4b.test", "/s"), Some(30_000), false),
        ],
    );
    call(&b, "rl4a", "a").await.expect("admitted");
    call(&b, "rl4b", "b")
        .await
        .expect("another host is admitted");
    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn rl5_capabilities_on_one_host_share_its_bucket() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl5p", &stub.url("rl5.test", "/p"), Some(30_000), false),
            // No rate_limit of its own: the host's policy still applies.
            cap("rl5u", &stub.url("rl5.test", "/u"), None, false),
        ],
    );
    call(&b, "rl5p", "a").await.expect("admitted");
    let err = call(&b, "rl5u", "b").await.expect_err("same host, refused");
    refusal_wait(&err, "rl5.test", 30_000);
    assert_eq!(stub.count(), 1);
}

// ── RL6: the strictest interval on a host wins, both sides ───────────

/// Two capabilities on `host`, paced at `a` and `b` ms, registered in that
/// order; the first call, then a probe after `probe_ms`.
async fn rl6_probe(host: &str, a: u64, b: u64, probe_ms: u64) -> crate::Result<()> {
    let stub = Stub::start(Reply::json("{}")).await;
    let backend = backend(
        Names::default(),
        vec![
            cap("rl6a", &stub.url(host, "/a"), Some(a), false),
            cap("rl6b", &stub.url(host, "/b"), Some(b), false),
        ],
    );
    call(&backend, "rl6a", "first").await.expect("admitted");
    tokio::time::sleep(Duration::from_millis(probe_ms)).await;
    call(&backend, "rl6b", "probe").await
}

#[tokio::test]
async fn rl6_the_stricter_interval_refuses_in_both_load_orders() {
    assert!(rl6_probe("rl6-r1.test", 3000, 6000, 4500).await.is_err());
    assert!(rl6_probe("rl6-r2.test", 6000, 3000, 4500).await.is_err());
}

#[tokio::test]
async fn rl6_the_stricter_interval_admits_once_it_passes() {
    assert!(rl6_probe("rl6-a1.test", 3000, 6000, 7500).await.is_ok());
    assert!(rl6_probe("rl6-a2.test", 6000, 3000, 7500).await.is_ok());
}

#[tokio::test]
async fn rl6_a7_a_longer_stricter_interval_moves_the_window() {
    // Admitted at 7500 ms under 6000 (above); refused there under 9000.
    assert!(rl6_probe("rl6-m.test", 3000, 9000, 7500).await.is_err());
}

// ── RL8: concurrent calls, exactly one admitted, and which ───────────

#[tokio::test]
async fn rl8_of_eight_concurrent_calls_exactly_one_is_admitted() {
    let stub = Stub::start(Reply::json("{}")).await;
    let backend = Arc::new(backend(
        Names::default(),
        vec![cap("rl8", &stub.url("rl8.test", "/s"), Some(30_000), false)],
    ));
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let calls = (0..8).map(|i| {
        let backend = Arc::clone(&backend);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            (i, call(&backend, "rl8", &format!("caller-{i}")).await)
        })
    });
    let results: Vec<_> = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|r| r.expect("joined"))
        .collect();
    let admitted: Vec<usize> = results
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(i, _)| *i)
        .collect();
    assert_eq!(admitted.len(), 1, "admitted: {admitted:?}");
    for (_, r) in results.iter().filter(|(_, r)| r.is_err()) {
        let err = r.as_ref().expect_err("refused");
        refusal_wait(err, "rl8.test", 30_000);
    }
    let seen = stub.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].query,
        vec![("q".to_owned(), format!("caller-{}", admitted[0]))],
        "the one request is the admitted caller's"
    );
}

// ── RL9: a cache hit takes no permit ─────────────────────────────────

#[tokio::test]
async fn rl9_a_cache_hit_is_served_while_the_bucket_is_spent() {
    let stub = Stub::start(Reply::json(r#"{"answer":"call-1"}"#)).await;
    let backend = backend(
        Names::default(),
        vec![cap("rl9", &stub.url("rl9.test", "/s"), Some(30_000), true)],
    );
    let first = backend
        .call_tool("rl9", json!({ "q": "a" }))
        .await
        .expect("admitted and stored");
    // The bucket is spent for 30 s: only the cache can answer now.
    let second = backend
        .call_tool("rl9", json!({ "q": "a" }))
        .await
        .expect("served from the cache, not refused by admission");
    assert_eq!(
        serde_json::to_value(&second).expect("json"),
        serde_json::to_value(&first).expect("json"),
        "call 2 returns call 1's value"
    );
    assert_eq!(stub.count(), 1);
}

// ── RL10/RL11: a paced call is one attempt ───────────────────────────

const TIMEOUT_1S: &str = "    timeout: 1\n";

#[tokio::test]
async fn rl10_a_stalled_paced_call_is_attempted_once() {
    let stub = Stub::start(Reply::Stall).await;
    let b = backend(
        Names::default(),
        vec![cap_full(
            "rl10",
            &stub.url("rl10.test", "/s"),
            Some(30_000),
            false,
            TIMEOUT_1S,
        )],
    );
    assert!(call(&b, "rl10", "a").await.is_err(), "the stall times out");
    assert_eq!(stub.count(), 1);
}

#[tokio::test]
async fn rl10_control_an_unpaced_get_retries_its_timeouts() {
    // A GET is idempotent, so send_with_retry retries its timeouts
    // (client.rs:227-229) up to MAX_SEND_ATTEMPTS, which is 3 (client.rs:214).
    let stub = Stub::start(Reply::Stall).await;
    let b = backend(
        Names::default(),
        vec![cap_full(
            "rl10c",
            &stub.url("rl10c.test", "/s"),
            None,
            false,
            TIMEOUT_1S,
        )],
    );
    assert!(call(&b, "rl10c", "a").await.is_err());
    assert_eq!(stub.count(), 3);
}

#[tokio::test]
async fn rl10b_an_undeclared_provider_on_a_paced_host_is_attempted_once() {
    let stub = Stub::start(Reply::Stall).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl10bp", &stub.url("rl10b.test", "/p"), Some(30_000), false),
            cap_full(
                "rl10bu",
                &stub.url("rl10b.test", "/u"),
                None,
                false,
                TIMEOUT_1S,
            ),
        ],
    );
    assert!(call(&b, "rl10bu", "a").await.is_err());
    assert_eq!(stub.count(), 1);
}

/// The calls a failing resolver saw, and every error a connect error, never
/// an SSRF refusal (W3-3).
async fn connect_failures(name: &str, host: &str, interval_ms: Option<u64>) -> usize {
    let names = Names::failing();
    let b = backend(
        names.clone(),
        vec![cap(name, &format!("http://{host}:9/s"), interval_ms, false)],
    );
    let err = call(&b, name, "a").await.expect_err("no address");
    let text = err.to_string();
    assert!(
        !text.contains("SSRF"),
        "a connect failure, not a refusal: {text}"
    );
    names.lookups()
}

#[tokio::test]
async fn rl11_a_paced_connect_failure_is_attempted_once() {
    assert_eq!(connect_failures("rl11", "rl11.test", Some(30_000)).await, 1);
}

#[tokio::test]
async fn rl11_control_an_unpaced_connect_failure_is_retried() {
    assert_eq!(connect_failures("rl11c", "rl11c.test", None).await, 3);
}

#[tokio::test]
async fn rl11b_an_undeclared_provider_on_a_paced_host_is_attempted_once() {
    let names = Names::failing();
    let b = backend(
        names.clone(),
        vec![
            cap("rl11bp", "http://rl11b.test:9/p", Some(30_000), false),
            cap("rl11bu", "http://rl11b.test:9/u", None, false),
        ],
    );
    assert!(call(&b, "rl11bu", "a").await.is_err());
    assert_eq!(names.lookups(), 1);
}

// ── RL12/RL13: redirects ─────────────────────────────────────────────

/// A stub that answers 302 to `target`, and a backend with `caps`.
async fn redirect_to(target: &str) -> Stub {
    Stub::start(Reply::Redirect(target.to_owned())).await
}

#[tokio::test]
async fn rl12_control_an_unpaced_redirect_is_followed() {
    let target = Stub::start(Reply::json("{}")).await;
    let from = redirect_to(&target.url("rl12t.test", "/t")).await;
    let b = backend(
        Names::default(),
        vec![cap("rl12u", &from.url("rl12u.test", "/s"), None, false)],
    );
    call(&b, "rl12u", "a").await.expect("followed");
    assert_eq!(target.count(), 1);
}

#[tokio::test]
async fn rl12_a_paced_provider_does_not_follow_a_redirect() {
    let target = Stub::start(Reply::json("{}")).await;
    // A Location carrying a signed token: only its host may be named.
    let to = target.url("rl12pt.test", "/t?token=s3cr3t-sig");
    let from = redirect_to(&to).await;
    let b = backend(
        Names::default(),
        vec![cap(
            "rl12p",
            &from.url("rl12p.test", "/s"),
            Some(30_000),
            false,
        )],
    );
    let err = call(&b, "rl12p", "a").await.expect_err("not followed");
    assert!(
        err.to_string().contains("rl12pt.test"),
        "names the target's host: {err}"
    );
    assert!(
        !err.to_string().contains("s3cr3t-sig"),
        "never the Location's query: {err}"
    );
    assert_eq!(target.count(), 0);
}

#[tokio::test]
async fn rl12b_an_undeclared_provider_on_a_paced_host_does_not_follow() {
    let target = Stub::start(Reply::json("{}")).await;
    let from = redirect_to(&target.url("rl12bt.test", "/t")).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl12bp", &from.url("rl12b.test", "/p"), Some(30_000), false),
            cap("rl12bu", &from.url("rl12b.test", "/u"), None, false),
        ],
    );
    assert!(call(&b, "rl12bu", "a").await.is_err());
    assert_eq!(target.count(), 0);
}

#[tokio::test]
async fn rl13_control_a_redirect_into_an_unpaced_host_is_followed() {
    let target = Stub::start(Reply::json("{}")).await;
    let from = redirect_to(&target.url("rl13u.test", "/t")).await;
    let b = backend(
        Names::default(),
        vec![cap("rl13c", &from.url("rl13c.test", "/s"), None, false)],
    );
    call(&b, "rl13c", "a").await.expect("followed");
    assert_eq!(target.count(), 1);
}

#[tokio::test]
async fn rl13_a_redirect_into_a_paced_host_is_refused() {
    let target = Stub::start(Reply::json("{}")).await;
    let paced = target.url("rl13p.test", "/t");
    assert_key(&paced, "rl13p.test", target.port);
    let from = redirect_to(&paced).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl13p", &paced, Some(30_000), false),
            cap("rl13r", &from.url("rl13r.test", "/s"), None, false),
        ],
    );
    assert!(call(&b, "rl13r", "a").await.is_err(), "refused at the hop");
    assert_eq!(target.count(), 0);
}

#[tokio::test]
async fn rl12c_a_relative_location_names_the_request_host() {
    let from = redirect_to("/elsewhere?token=s3cr3t-sig").await;
    let b = backend(
        Names::default(),
        vec![cap(
            "rl12c",
            &from.url("rl12c.test", "/s"),
            Some(30_000),
            false,
        )],
    );
    let err = call(&b, "rl12c", "a").await.expect_err("not followed");
    assert!(
        err.to_string().contains("pointing to rl12c.test"),
        "a relative Location resolves against the request: {err}"
    );
    assert!(
        !err.to_string().contains("s3cr3t-sig"),
        "never the query: {err}"
    );
}

// ── RL14: reload ─────────────────────────────────────────────────────

/// The YAML [`cap`] parses, for writing to a directory the backend loads.
fn cap_yaml(name: &str, url: &str, interval_ms: u64) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: {name}\ndescription: d\nschema:\n  input:\n    type: object\n    \
         properties:\n      q:\n        type: string\nproviders:\n  primary:\n    service: rest\n    \
         rate_limit:\n      interval_ms: {interval_ms}\n    config:\n      endpoint: {url}\n      \
         method: GET\n      params:\n        q: \"{{q}}\"\n"
    )
}

/// A backend over its own executor, loading `dir`.
async fn loaded(
    dir: &std::path::Path,
) -> (
    CapabilityBackend,
    Arc<crate::capability::CapabilityExecutor>,
) {
    let executor = Arc::new(executor(Names::default()));
    let backend = CapabilityBackend::new("maps", Arc::clone(&executor));
    backend
        .load_from_directory(dir.to_str().expect("utf-8 path"))
        .await
        .expect("loaded");
    (backend, executor)
}

#[tokio::test]
async fn rl14a_an_unchanged_interval_keeps_its_bucket_across_a_reload() {
    let stub = Stub::start(Reply::json("{}")).await;
    let dir = tempfile::TempDir::new().expect("dir");
    let url = stub.url("rl14a.test", "/s");
    std::fs::write(
        dir.path().join("rl14a.yaml"),
        cap_yaml("rl14a", &url, 30_000),
    )
    .expect("write");
    let (backend, _) = loaded(dir.path()).await;
    call(&backend, "rl14a", "a").await.expect("admitted");
    backend.reload().await.expect("reloaded");
    let err = call(&backend, "rl14a", "b")
        .await
        .expect_err("same bucket, refused");
    refusal_wait(&err, "rl14a.test", 30_000);
    assert_eq!(stub.count(), 1);
}

#[tokio::test]
async fn rl14b_a_changed_interval_starts_spent_and_rl14c_a_retained_definition_obeys_it() {
    let stub = Stub::start(Reply::json("{}")).await;
    let dir = tempfile::TempDir::new().expect("dir");
    let url = stub.url("rl14b.test", "/s");
    let twin_stub = Stub::start(Reply::json("{}")).await;
    let twin = twin_stub.url("rl14b-twin.test", "/s");
    let file = dir.path().join("rl14b.yaml");
    std::fs::write(&file, cap_yaml("rl14b", &url, 300)).expect("write");
    std::fs::write(
        dir.path().join("rl14btwin.yaml"),
        cap_yaml("rl14btwin", &twin, 300),
    )
    .expect("write");
    let (backend, executor) = loaded(dir.path()).await;
    let retained = crate::capability::parse_capability(&cap_yaml("rl14b", &url, 300)).expect("cap");
    call(&backend, "rl14b", "a").await.expect("admitted");
    call(&backend, "rl14btwin", "a").await.expect("admitted");
    // timing-oracle: vs 300 ms rate_limit interval (why: past the old 300 ms interval; the refusal after it needs the call inside the new 30000 ms interval, which no stall reaches)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    // Premise: the old 300 ms bucket would admit now (its twin does).
    call(&backend, "rl14btwin", "b")
        .await
        .expect("the old interval has passed");
    std::fs::write(&file, cap_yaml("rl14b", &url, 30_000)).expect("rewrite");
    backend.reload().await.expect("reloaded");
    let err = call(&backend, "rl14b", "b")
        .await
        .expect_err("the new bucket starts spent");
    refusal_wait(&err, "rl14b.test", 30_000);
    // RL14c: the definition held from before the reload is paced by the live map.
    assert_eq!(
        retained
            .providers
            .get("primary")
            .expect("primary")
            .config
            .endpoint,
        url
    );
    let err = executor
        .execute(&retained, json!({ "q": "c" }))
        .await
        .expect_err("the retained definition is refused too");
    refusal_wait(&err, "rl14b.test", 30_000);
    assert_eq!(stub.count(), 1, "only call a reached rl14b");
    assert_eq!(twin_stub.count(), 2);
}

#[tokio::test]
async fn rl14b_a_changed_interval_admits_once_the_new_interval_passes() {
    let stub = Stub::start(Reply::json("{}")).await;
    let dir = tempfile::TempDir::new().expect("dir");
    let url = stub.url("rl14b2.test", "/s");
    let file = dir.path().join("rl14b2.yaml");
    std::fs::write(&file, cap_yaml("rl14b2", &url, 300)).expect("write");
    let (backend, _) = loaded(dir.path()).await;
    call(&backend, "rl14b2", "a").await.expect("admitted");
    // timing-oracle: vs 300 ms rate_limit interval (why: a slow runner only lengthens the sleep, so the old bucket's 300 ms interval has always passed)
    tokio::time::sleep(Duration::from_millis(1800)).await;
    std::fs::write(&file, cap_yaml("rl14b2", &url, 400)).expect("rewrite");
    backend.reload().await.expect("reloaded");
    assert!(
        call(&backend, "rl14b2", "b").await.is_err(),
        "spent at the switch"
    );
    // timing-oracle: vs 400 ms rate_limit interval (why: a slow runner only lengthens the sleep, so the new 400 ms interval has always passed)
    tokio::time::sleep(Duration::from_millis(1900)).await;
    call(&backend, "rl14b2", "c")
        .await
        .expect("admitted after the new interval");
    assert_eq!(stub.count(), 2);
}

#[tokio::test]
async fn rl14d_two_executors_share_one_bucket_per_host() {
    let stub = Stub::start(Reply::json("{}")).await;
    let url = stub.url("rl14d.test", "/s");
    let one = backend(
        Names::default(),
        vec![cap("rl14d", &url, Some(30_000), false)],
    );
    let two = backend(
        Names::default(),
        vec![cap("rl14d", &url, Some(30_000), false)],
    );
    call(&one, "rl14d", "a").await.expect("admitted");
    let err = call(&two, "rl14d", "b")
        .await
        .expect_err("one process, one bucket");
    refusal_wait(&err, "rl14d.test", 30_000);
    assert_eq!(stub.count(), 1);
}

#[tokio::test]
async fn rl14e_a_host_dropped_by_a_reload_still_refuses_within_its_interval() {
    let stub = Stub::start(Reply::json("{}")).await;
    let dir = tempfile::TempDir::new().expect("dir");
    let url = stub.url("rl14e.test", "/s");
    let file = dir.path().join("rl14e.yaml");
    std::fs::write(&file, cap_yaml("rl14e", &url, 30_000)).expect("write");
    let (backend, executor) = loaded(dir.path()).await;
    let retained =
        crate::capability::parse_capability(&cap_yaml("rl14e", &url, 30_000)).expect("cap");
    call(&backend, "rl14e", "a").await.expect("admitted");
    std::fs::remove_file(&file).expect("remove");
    backend.reload().await.expect("reloaded");
    assert!(
        !backend.has_capability("rl14e"),
        "premise: dropped from the catalog"
    );
    let err = executor
        .execute(&retained, json!({ "q": "b" }))
        .await
        .expect_err("the host keeps its bucket until restart");
    refusal_wait(&err, "rl14e.test", 30_000);
    assert_eq!(stub.count(), 1);
}

// ── RL17: upstream statuses on a paced call (baseline green) ─────────

#[tokio::test]
async fn rl17_a_paced_429_or_503_is_one_request_and_surfaces() {
    for (status, host) in [(429, "rl17a.test"), (503, "rl17b.test")] {
        let stub = Stub::start(Reply::status(status)).await;
        let b = backend(
            Names::default(),
            vec![cap("rl17", &stub.url(host, "/s"), Some(30_000), false)],
        );
        let err = call(&b, "rl17", "a").await.expect_err("an error status");
        assert!(
            err.to_string().contains(&status.to_string()),
            "surfaces {status}: {err}"
        );
        assert_eq!(stub.count(), 1, "{status}: one request");
    }
    // Control: a 200 returns its body.
    let ok = Stub::start(Reply::json(r#"{"v":1}"#)).await;
    let b = backend(
        Names::default(),
        vec![cap(
            "rl17ok",
            &ok.url("rl17c.test", "/s"),
            Some(30_000),
            false,
        )],
    );
    call(&b, "rl17ok", "a").await.expect("a 200 is a result");
}

// ── RL7b: host case on the wire ──────────────────────────────────────

#[tokio::test]
async fn rl7b_an_upper_case_spelling_shares_the_bucket() {
    let stub = Stub::start(Reply::json("{}")).await;
    let b = backend(
        Names::default(),
        vec![
            cap("rl7lower", &stub.url("rl7.test", "/a"), Some(30_000), false),
            cap("rl7upper", &stub.url("RL7.test", "/b"), None, false),
        ],
    );
    call(&b, "rl7lower", "a").await.expect("admitted");
    let err = call(&b, "rl7upper", "b")
        .await
        .expect_err("one host, one bucket");
    refusal_wait(&err, "rl7.test", 30_000);
    assert_eq!(stub.count(), 1);
}

// ── RL20: no permit is spent on a call that never reaches the wire ───

/// A call that fails while its credential is prepared takes no permit: it
/// is admitted only after every await but the send.
#[tokio::test]
async fn rl20_a_call_failing_before_the_send_takes_no_permit() {
    let stub = Stub::start(Reply::json("{}")).await;
    // A loopback literal: a credential may go over plain http only to a
    // loopback host, so the call clears that rule and fails at its credential.
    let url = stub.url("127.0.0.1", "/s");
    let needs_key = format!(
        "fulcrum: \"1.0\"\nname: rl20key\ndescription: d\nschema:\n  input:\n    type: object\n    \
         properties:\n      q:\n        type: string\nauth:\n  required: true\n  key: \
         env:MAPS_RL20_UNSET_KEY_FOR_TEST\n  param: key\nproviders:\n  primary:\n    service: rest\n    \
         rate_limit:\n      interval_ms: 30000\n    config:\n      endpoint: {url}\n      method: GET\n"
    );
    let b = CapabilityBackend::new(
        "rl20",
        Arc::new(executor(Names::default()).with_test_loopback_egress()),
    );
    b.register_capability(crate::capability::parse_capability(&needs_key).expect("capability"))
        .expect("registered");
    b.register_capability(cap("rl20open", &url, None, false))
        .expect("registered");
    let err = call(&b, "rl20key", "a").await.expect_err("no key");
    assert!(
        err.to_string()
            .contains("Environment variable 'MAPS_RL20_UNSET_KEY_FOR_TEST' not set or empty"),
        "premise: the call fails at its credential step, not an earlier rule: {err}"
    );
    call(&b, "rl20open", "b")
        .await
        .expect("the failed call took no permit");
    assert_eq!(stub.count(), 1);
}

#[path = "maps_pacing_backends_tests.rs"]
mod backends;
