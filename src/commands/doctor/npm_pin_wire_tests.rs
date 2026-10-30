// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8512 red tests, network rows: an HTTPS fake registry on 127.0.0.1
//! with a test CA, and a recording CONNECT proxy. No row reaches the
//! internet. Every client is built by the production `client`, with only data
//! (base URL, roots, proxy snapshot) swapped.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use mcp_gateway::config::{BackendConfig, Config};

use super::super::*;
use super::stdio;
use crate::commands::doctor::CheckStatus;

#[path = "npm_pin_wire_fixture.rs"]
mod fixture;
use fixture::{
    Cert, Fake, HANG_GUARD, Proxy, Reply, STALL_OUTLASTS_BUDGET, assert_all_released,
    assert_budget_ended, check_within_guard, lookup_within_guard,
};

// ── fixtures ────────────────────────────────────────────────────────────────

const MEMORY_PATH: &str = "/@modelcontextprotocol%2Fserver-memory";
const FILESYSTEM_PATH: &str = "/@modelcontextprotocol%2Fserver-filesystem";
const DEPRECATED: &str = "Date-based versions are no longer published";

/// The memory document: `2026.8.31` deprecated, `1.0.0` current.
fn memory_doc() -> Vec<u8> {
    super::doc(&[("2026.8.31", Some(DEPRECATED)), ("1.0.0", None)])
}

fn config_of(backends: &[(&str, BackendConfig)]) -> Config {
    let mut config = Config::default();
    for (name, backend) in backends {
        config.backends.insert((*name).to_string(), backend.clone());
    }
    config
}

fn memory_on(version: &str) -> BackendConfig {
    stdio(
        &format!("npx -y @modelcontextprotocol/server-memory@{version}"),
        &[],
    )
}

fn warns(rows: &[CheckResult]) -> Vec<&CheckResult> {
    rows.iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .collect()
}

// ── DOCTOR.2: the falsifier ─────────────────────────────────────────────────

#[tokio::test]
async fn a_deprecated_memory_pin_warns_and_the_current_one_does_not() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let config = config_of(&[
        ("memory", memory_on("2026.8.31")),
        ("fresh", memory_on("1.0.0")),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    let warned = warns(&rows);
    assert_eq!(warned.len(), 1, "only the deprecated pin warns: {rows:?}");
    let row = warned[0];
    assert_eq!(row.label, "memory: npm pin");
    assert_eq!(row.category, "backend_stdio");
    assert!(
        row.detail
            .contains("@modelcontextprotocol/server-memory@2026.8.31"),
        "{}",
        row.detail
    );
    assert!(
        row.detail.contains(&format!("npm says: \"{DEPRECATED}\"")),
        "{}",
        row.detail
    );
    assert!(
        row.hint
            .as_deref()
            .is_some_and(|h| h.contains("MEMORY_FILE_PATH"))
    );
    assert!(
        rows.iter().all(|r| r.status != CheckStatus::Fail),
        "never Fail"
    );
    assert_eq!(fake.requests().len(), 1, "one request per distinct package");
}

// ── the request: what is sent, and only that ───────────────────────────────

#[tokio::test]
async fn the_request_carries_only_the_package_name_and_fixed_headers() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let mut backend = memory_on("2026.8.31");
    backend
        .env
        .insert("API_TOKEN".into(), "secret-value-canary".into());
    let config = config_of(&[("private-backend-name", backend)]);
    let _ = check(&config, &fake.cfg(&[]), Lookup::On).await;
    let seen = fake.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, MEMORY_PATH, "the version stays local");
    assert_eq!(
        request.headers.get("user-agent").map(String::as_str),
        Some(USER_AGENT)
    );
    assert_eq!(
        request.headers.get("accept").map(String::as_str),
        Some(ACCEPT)
    );
    for forbidden in ["authorization", "cookie", "proxy-authorization"] {
        assert!(!request.headers.contains_key(forbidden), "{forbidden} sent");
    }
    let wire = format!("{request:?}");
    for leak in ["secret-value-canary", "private-backend-name", "2026.8.31"] {
        assert!(!wire.contains(leak), "{leak} left the machine: {wire}");
    }
}

// ── scope: the allowlist and dedup ──────────────────────────────────────────

#[tokio::test]
async fn a_package_outside_the_registry_is_never_sent() {
    let fake = Fake::start(&[]).await;
    let config = config_of(&[
        (
            "internal",
            stdio("npx -y @company/internal-tool@1.2.3", &[]),
        ),
        (
            "ranged",
            stdio("npx -y @modelcontextprotocol/server-memory@latest", &[]),
        ),
        (
            "other-runner",
            stdio("pnpm dlx @modelcontextprotocol/server-memory@1.0.0", &[]),
        ),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    assert!(warns(&rows).is_empty());
    assert_eq!(
        fake.requests().len(),
        0,
        "nothing outside the allowlist is sent"
    );
}

#[tokio::test]
async fn one_request_per_package_with_a_row_per_backend() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let config = config_of(&[
        ("b-old", memory_on("2026.8.31")),
        ("a-old", memory_on("2026.8.31")),
        ("c-new", memory_on("1.0.0")),
    ]);
    let rows = check(&config, &fake.cfg(&[]), Lookup::On).await;
    assert_eq!(fake.requests().len(), 1, "one request for three backends");
    let labels: Vec<&str> = warns(&rows).iter().map(|r| r.label.as_str()).collect();
    assert_eq!(
        labels,
        ["a-old: npm pin", "b-old: npm pin"],
        "sorted backend order"
    );
}

#[tokio::test]
async fn a_disabled_backend_is_not_checked() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let mut off = memory_on("2026.8.31");
    off.enabled = false;
    let rows = check(&config_of(&[("off", off)]), &fake.cfg(&[]), Lookup::On).await;
    assert!(warns(&rows).is_empty());
    assert_eq!(fake.requests().len(), 0);
}

// ── the off switch ──────────────────────────────────────────────────────────

#[tokio::test]
async fn every_off_reason_sends_nothing_and_prints_one_skipped_pass() {
    for lookup in [Lookup::OffByFlag, Lookup::OffByPosture] {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            lookup,
        )
        .await;
        assert_eq!(fake.requests().len(), 0, "{lookup:?}");
        assert_eq!(rows.len(), 1, "{lookup:?}: {rows:?}");
        assert_eq!(rows[0].status, CheckStatus::Pass);
        assert_eq!(rows[0].label, SKIPPED_LABEL);
        assert!(rows[0].detail.contains("skipped"), "{}", rows[0].detail);
    }
}

// ── fail-soft: every failure is silence, inside the budget ─────────────────

#[test]
fn the_bounds_nest_budget_hang_guard_stall() {
    assert_eq!(
        BUDGET,
        Duration::from_secs(4),
        "the budget is the policy value"
    );
    assert!(BUDGET < HANG_GUARD, "the guard sits past the budget");
    assert!(
        HANG_GUARD < STALL_OUTLASTS_BUDGET,
        "a stall outlives the guard, so only the budget ends a check"
    );
}

#[test]
fn production_keeps_its_request_bounds() {
    assert_eq!(ClientCfg::production().bounds_override, None);
    assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(2));
    assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(3));
}

/// One stalled lookup on the production request bounds, with no budget
/// around it: only the request bound can end it.
#[tokio::test]
async fn the_request_timeout_alone_ends_one_stalled_lookup() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Stall)]).await;
    let cfg = fake.cfg(&[]);
    let http = client(&cfg).expect("the fake builds a client");
    let started = Instant::now();
    let doc = lookup_within_guard(&http, &cfg, "@modelcontextprotocol/server-memory").await;
    let took = started.elapsed();
    eprintln!("the lookup took {took:?}");
    assert!(doc.is_none(), "a stalled lookup is no answer");
    assert!(
        took >= REQUEST_TIMEOUT.saturating_sub(Duration::from_millis(200)),
        "the request bound ran out: {took:?}"
    );
    assert_eq!(fake.requests().len(), 1, "the stall was reached");
    assert_all_released(&fake).await;
}

#[tokio::test]
async fn offline_is_silent() {
    // TCP port 1 (tcpmux) has no listener on a test host, so the connect is
    // refused at once; no port is picked and released, so nothing can race.
    let cfg = ClientCfg {
        base: Url::parse("https://127.0.0.1:1/").expect("parses"),
        roots: rustls::RootCertStore::empty(),
        proxy: ProxyEnv::default(),
        bounds_override: None,
    };
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &cfg,
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
}

/// Five stalled packages at four in flight, each outlasting every request
/// bound: only the budget can end the check, and it lets go of every stall.
#[tokio::test]
async fn stalls_end_inside_the_budget_and_never_exceed_the_concurrency() {
    let packages = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        ("@modelcontextprotocol/server-memory", MEMORY_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let replies: Vec<(&str, Reply)> = packages
        .iter()
        .map(|(_, path)| (*path, Reply::Stall))
        .collect();
    let fake = Fake::start(&replies).await;
    let backends: Vec<(String, BackendConfig)> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("b{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let (rows, took) = check_within_guard(&config_of(&named), &fake.cfg_outlasting_budget()).await;
    assert!(rows.is_empty(), "{rows:?}");
    assert_budget_ended(took);
    assert_eq!(
        fake.requests().len(),
        CONCURRENCY,
        "the first wave reached the stalls"
    );
    assert_eq!(fake.peak.load(Ordering::SeqCst), CONCURRENCY);
    assert_all_released(&fake).await;
}

/// Eight packages that each answer after 300 ms: never more than four in
/// flight, and four at once (the pool is used, not run one by one).
#[tokio::test]
async fn at_most_four_requests_are_in_flight() {
    let packages = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        ("@modelcontextprotocol/server-memory", MEMORY_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("airtable-mcp-server", "/airtable-mcp-server"),
        ("exa-mcp-server", "/exa-mcp-server"),
        ("slack-mcp-server", "/slack-mcp-server"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let slow = Duration::from_millis(300);
    let replies: Vec<(&str, Reply)> = packages
        .iter()
        .map(|(_, path)| (*path, Reply::Delay(slow, br#"{"versions":{}}"#.to_vec())))
        .collect();
    let fake = Fake::start(&replies).await;
    let backends: Vec<(String, BackendConfig)> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("b{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let _ = check(&config_of(&named), &fake.cfg(&[]), Lookup::On).await;
    assert_eq!(
        fake.requests().len(),
        packages.len(),
        "every package asked once"
    );
    assert_eq!(fake.peak.load(Ordering::SeqCst), CONCURRENCY);
}

/// The memory warning finishes at once; seven stalled packages, each
/// outlasting every request bound, keep the pool busy until the budget ends
/// the check. The finished row must survive that.
#[tokio::test]
async fn a_finished_warning_survives_the_budget_running_out() {
    let stalled = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
        ("airtable-mcp-server", "/airtable-mcp-server"),
        ("exa-mcp-server", "/exa-mcp-server"),
        ("slack-mcp-server", "/slack-mcp-server"),
        ("tavily-mcp", "/tavily-mcp"),
    ];
    let mut replies: Vec<(&str, Reply)> = stalled
        .iter()
        .map(|(_, path)| (*path, Reply::Stall))
        .collect();
    replies.push((MEMORY_PATH, Reply::Json(memory_doc())));
    let fake = Fake::start(&replies).await;
    let mut backends: Vec<(String, BackendConfig)> = stalled
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("s{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    backends.push(("memory".to_string(), memory_on("2026.8.31")));
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let (rows, took) = check_within_guard(&config_of(&named), &fake.cfg_outlasting_budget()).await;
    assert_budget_ended(took);
    let labels: Vec<&str> = warns(&rows).iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["memory: npm pin"], "{rows:?}");
    // The memory answer freed one slot; the next stalled package took it.
    assert_eq!(
        fake.requests().len(),
        CONCURRENCY + 1,
        "{:?}",
        fake.requests()
    );
    assert_all_released(&fake).await;
}

/// The first four packages answer at once, so airtable-mcp-server and
/// tavily-mcp start in the second wave. airtable stalls past the budget;
/// tavily's warning, which lands while airtable still stalls, must not be
/// held behind it.
#[tokio::test]
async fn a_second_wave_warning_is_not_held_behind_a_stalled_request() {
    let first_wave = [
        ("@modelcontextprotocol/server-filesystem", FILESYSTEM_PATH),
        ("@modelcontextprotocol/server-memory", MEMORY_PATH),
        (
            "@modelcontextprotocol/server-sequential-thinking",
            "/@modelcontextprotocol%2Fserver-sequential-thinking",
        ),
        ("@playwright/mcp", "/@playwright%2Fmcp"),
    ];
    let mut replies: Vec<(&str, Reply)> = first_wave
        .iter()
        .map(|(_, path)| (*path, Reply::Json(br#"{"versions":{}}"#.to_vec())))
        .collect();
    replies.push(("/airtable-mcp-server", Reply::Stall));
    replies.push((
        "/tavily-mcp",
        Reply::Json(br#"{"versions":{"1.0.0":{"deprecated":"use 2"}}}"#.to_vec()),
    ));
    let fake = Fake::start(&replies).await;
    let mut backends: Vec<(String, BackendConfig)> = first_wave
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (format!("s{i}"), stdio(&format!("npx -y {name}@1.0.0"), &[])))
        .collect();
    backends.push((
        "a".to_string(),
        stdio("npx -y airtable-mcp-server@1.0.0", &[]),
    ));
    backends.push(("t".to_string(), stdio("npx -y tavily-mcp@1.0.0", &[])));
    let named: Vec<(&str, BackendConfig)> = backends
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let (rows, took) = check_within_guard(&config_of(&named), &fake.cfg_outlasting_budget()).await;
    assert_budget_ended(took);
    let labels: Vec<&str> = warns(&rows).iter().map(|r| r.label.as_str()).collect();
    assert_eq!(labels, ["t: npm pin"], "{rows:?}");
    assert_eq!(fake.requests().len(), 6, "every package was asked");
    assert_all_released(&fake).await;
}

#[tokio::test]
async fn a_non_200_answer_is_silent_even_with_a_valid_document() {
    for code in [404u16, 500, 203] {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Status(code, memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "HTTP {code}: {rows:?}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let fake = Fake::start(&[
        (MEMORY_PATH, Reply::Redirect("/elsewhere".to_string())),
        ("/elsewhere", Reply::Json(memory_doc())),
    ])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let targets: Vec<String> = fake.requests().into_iter().map(|r| r.target).collect();
    assert_eq!(
        targets,
        [MEMORY_PATH],
        "the redirect target was never asked"
    );
}

#[tokio::test]
async fn an_endless_body_is_cut_early_and_silent() {
    let fake = Fake::start(&[(
        MEMORY_PATH,
        Reply::Drip {
            chunk: 64 * 1024,
            total: 8 * MAX_DOC_BYTES,
        },
    )])
    .await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
    let written = fake.dripped.load(Ordering::SeqCst);
    assert!(
        written < 4 * MAX_DOC_BYTES,
        "the client kept reading: {written} bytes"
    );
}

#[tokio::test]
async fn a_compressed_body_counts_its_decoded_size() {
    // A deprecated pin padded past the cap once decoded, tiny on the wire.
    let mut body = memory_doc();
    body.pop(); // the closing brace
    body.extend_from_slice(br#","padding":""#);
    body.extend(std::iter::repeat_n(b'a', 2 * MAX_DOC_BYTES));
    body.extend_from_slice(br#""}"#);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(
        rows.is_empty(),
        "the decoded size is over the cap: {rows:?}"
    );

    // The same document under the cap, compressed, is read.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Gzip(memory_doc()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
}

#[tokio::test]
async fn invalid_json_is_silent() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(b"{not json".to_vec()))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");
}

#[tokio::test]
async fn hostile_text_prints_sanitized() {
    let hostile = "\u{1b}[2J\u{1b}[31mPWNED\u{1b}[0m\nfake\u{202e}line";
    let body = super::doc(&[("2026.8.31", Some(hostile))]);
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(body))]).await;
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[]),
        Lookup::On,
    )
    .await;
    let detail = &warns(&rows)[0].detail;
    assert!(detail.contains("npm says: \"PWNED fakeline\""), "{detail}");
    assert!(
        !detail.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{detail:?}"
    );
}

// ── TLS: the injected roots are the only roots ─────────────────────────────

#[tokio::test]
async fn a_wrong_name_or_an_untrusted_ca_is_silent() {
    for cert in [Cert::WrongName, Cert::UntrustedCa] {
        let fake = Fake::start_with(cert, &[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(&[]),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "{rows:?}");
        assert_eq!(
            fake.requests().len(),
            0,
            "no request over a refused handshake"
        );
        // The server sees the client's rejection a moment after the client
        // gives up: wait for it, bounded.
        let deadline = Instant::now() + Duration::from_secs(5);
        while fake.handshakes_failed.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            fake.handshakes_failed.load(Ordering::SeqCst) >= 1,
            "the handshake was refused"
        );
    }
}

// ── proxy: through the production builder, never bypassed ──────────────────

#[tokio::test]
async fn https_proxy_carries_the_lookup_through_connect() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("REQUEST_METHOD", "GET")]),
        Lookup::On,
    )
    .await;
    assert_eq!(
        warns(&rows).len(),
        1,
        "the lookup went through the proxy: {rows:?}"
    );
    assert_eq!(proxy.connects(), [format!("CONNECT {}", fake.addr)]);
}

#[tokio::test]
async fn no_proxy_covering_the_host_goes_direct() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "127.0.0.1")]),
        Lookup::On,
    )
    .await;
    assert_eq!(warns(&rows).len(), 1, "{rows:?}");
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());

    // A NO_PROXY that does not cover the host keeps the proxy.
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let _ = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &fake.cfg(&[("HTTPS_PROXY", url.as_str()), ("NO_PROXY", "other.example")]),
        Lookup::On,
    )
    .await;
    assert_eq!(proxy.connects().len(), 1);
}

#[tokio::test]
async fn an_unusable_proxy_sends_nothing_anywhere() {
    let proxy = Proxy::start().await;
    let with_userinfo = format!("http://user:pass@{}", proxy.addr);
    let socks = format!("socks5://{}", proxy.addr);
    let broken = format!("http://proxy{{typo}}:{}", proxy.addr.port());
    let cases: [&[(&str, &str)]; 4] = [
        &[("HTTPS_PROXY", with_userinfo.as_str())],
        &[("ALL_PROXY", socks.as_str())],
        &[("HTTPS_PROXY", broken.as_str())],
        &[("HTTPS_PROXY", "::not a url::")],
    ];
    for pairs in cases {
        let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
        let rows = check(
            &config_of(&[("memory", memory_on("2026.8.31"))]),
            &fake.cfg(pairs),
            Lookup::On,
        )
        .await;
        assert!(rows.is_empty(), "{pairs:?}: {rows:?}");
        assert_eq!(fake.requests().len(), 0, "{pairs:?}: went direct");
        assert_eq!(
            fake.handshakes_failed.load(Ordering::SeqCst),
            0,
            "{pairs:?}: reached the fake"
        );
    }
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());
}

// ── the process environment: reached only through the snapshot ─────────────
//
// Setting the environment in-process is unsafe in edition 2024, so these rows
// run this test binary again as a child with a controlled environment. The
// child half is inert unless the parent marks it.

const CHILD_TEST: &str = "commands::doctor::npm_pin::tests::wire::child_runs_one_lookup";

/// The child half: one lookup against the parent's fake, with either an empty
/// snapshot or the process snapshot; prints how many rows warned.
#[tokio::test]
async fn child_runs_one_lookup() {
    let Ok(mode) = std::env::var("NPM_PIN_CHILD") else {
        return;
    };
    let base = Url::parse(&std::env::var("NPM_PIN_BASE").expect("a base")).expect("parses");
    let hex = std::env::var("NPM_PIN_CA").expect("a CA");
    let der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der))
        .expect("the CA is a root");
    let proxy = match mode.as_str() {
        "empty" => ProxyEnv::default(),
        "process" => ProxyEnv::from_process(),
        other => panic!("unexpected child mode {other}"),
    };
    let rows = check(
        &config_of(&[("memory", memory_on("2026.8.31"))]),
        &ClientCfg {
            base,
            roots,
            proxy,
            bounds_override: None,
        },
        Lookup::On,
    )
    .await;
    println!("CHILD-WARNS {}", warns(&rows).len());
}

/// Run the child half with `mode` and `env`; its stdout.
async fn child(fake: &Fake, mode: &str, env: &[(&str, &str)]) -> String {
    let hex = fake.ca_der.iter().fold(String::new(), |mut hex, b| {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
        hex
    });
    let exe = std::env::current_exe().expect("the test binary");
    let mut command = tokio::process::Command::new(exe);
    command
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("NPM_PIN_CHILD", mode)
        .env("NPM_PIN_BASE", fake.base().as_str())
        .env("NPM_PIN_CA", hex);
    if let Ok(root) = std::env::var("SystemRoot") {
        command.env("SystemRoot", root);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .expect("the child ends")
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "child failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// The builder never reads the environment itself (`no_proxy()`): with an
/// empty snapshot, a process `HTTPS_PROXY` is not used.
#[tokio::test]
async fn an_empty_snapshot_ignores_the_process_proxy() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let out = child(
        &fake,
        "empty",
        &[("HTTPS_PROXY", url.as_str()), ("ALL_PROXY", url.as_str())],
    )
    .await;
    assert!(out.contains("CHILD-WARNS 1"), "{out}");
    assert!(proxy.connects().is_empty(), "{:?}", proxy.connects());
    assert_eq!(fake.requests().len(), 1);
}

/// `from_process` reads the real environment, and `REQUEST_METHOD` changes
/// nothing: the lookup goes through the process proxy.
#[tokio::test]
async fn the_process_snapshot_uses_the_process_proxy() {
    let fake = Fake::start(&[(MEMORY_PATH, Reply::Json(memory_doc()))]).await;
    let proxy = Proxy::start().await;
    let url = proxy.url();
    let out = child(
        &fake,
        "process",
        &[("HTTPS_PROXY", url.as_str()), ("REQUEST_METHOD", "GET")],
    )
    .await;
    assert!(out.contains("CHILD-WARNS 1"), "{out}");
    assert_eq!(proxy.connects(), [format!("CONNECT {}", fake.addr)]);
}
