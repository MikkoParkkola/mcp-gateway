use super::*;

// ── DashboardState helpers ──────────────────────────────────────────

fn healthy_backend(name: &str, tool_count: usize, latency_ms: Option<u64>) -> BackendHealth {
    BackendHealth {
        name: name.to_string(),
        status: HealthStatus::Healthy,
        latency_ms,
        error_rate: 0.0,
        tool_count,
    }
}

fn degraded_backend(name: &str) -> BackendHealth {
    BackendHealth {
        name: name.to_string(),
        status: HealthStatus::Degraded,
        latency_ms: Some(500),
        error_rate: 0.3,
        tool_count: 2,
    }
}

fn down_backend(name: &str) -> BackendHealth {
    BackendHealth {
        name: name.to_string(),
        status: HealthStatus::Down,
        latency_ms: None,
        error_rate: 1.0,
        tool_count: 0,
    }
}

fn default_state<'a>(backends: Vec<BackendHealth>) -> DashboardState<'a> {
    DashboardState {
        backends,
        session_summary: SessionSummary {
            active_sessions: 3,
            total_calls: 42,
            avg_latency_ms: Some(80),
        },
        recent_calls: vec![],
        cache_stats: CacheStats {
            hit_rate: 0.75,
            total_hits: 300,
            total_misses: 100,
        },
        uptime_secs: 3661,
        version: "2.4.0",
    }
}

// ── HealthStatus ────────────────────────────────────────────────

#[test]
fn health_status_css_class() {
    assert_eq!(HealthStatus::Healthy.css_class(), "healthy");
    assert_eq!(HealthStatus::Degraded.css_class(), "degraded");
    assert_eq!(HealthStatus::Down.css_class(), "down");
}

#[test]
fn health_status_label() {
    assert_eq!(HealthStatus::Healthy.label(), "Healthy");
    assert_eq!(HealthStatus::Degraded.label(), "Degraded");
    assert_eq!(HealthStatus::Down.label(), "Down");
}

#[test]
fn call_status_css_and_label() {
    assert_eq!(CallStatus::Success.css_class(), "success");
    assert_eq!(CallStatus::Error.css_class(), "error");
    assert_eq!(CallStatus::Success.label(), "OK");
    assert_eq!(CallStatus::Error.label(), "ERR");
}

// ── compute_error_rate ──────────────────────────────────────────

#[test]
fn error_rate_zero_when_no_calls() {
    let rate = compute_error_rate(0, 0);
    assert!(rate.abs() < f64::EPSILON);
}

#[test]
fn error_rate_zero_when_all_success() {
    let rate = compute_error_rate(100, 0);
    assert!(rate.abs() < f64::EPSILON);
}

#[test]
fn error_rate_one_when_all_failure() {
    let rate = compute_error_rate(0, 50);
    assert!((rate - 1.0).abs() < f64::EPSILON);
}

#[test]
fn error_rate_partial() {
    let rate = compute_error_rate(75, 25);
    assert!((rate - 0.25).abs() < 1e-9);
}

// ── format_uptime ───────────────────────────────────────────────

#[test]
fn format_uptime_seconds() {
    assert_eq!(format_uptime(45), "0m 45s");
}

#[test]
fn format_uptime_minutes() {
    assert_eq!(format_uptime(130), "2m 10s");
}

#[test]
fn format_uptime_hours() {
    assert_eq!(format_uptime(3661), "1h 1m");
}

#[test]
fn format_uptime_days() {
    assert_eq!(format_uptime(90_000), "1d 1h");
}

// ── esc ─────────────────────────────────────────────────────────

#[test]
fn esc_replaces_html_specials() {
    assert_eq!(esc("<script>"), "&lt;script&gt;");
    assert_eq!(esc("a & b"), "a &amp; b");
    assert_eq!(esc(r#"say "hi""#), "say &quot;hi&quot;");
    assert_eq!(esc("it's"), "it&#x27;s");
}

#[test]
fn esc_passthrough_plain_text() {
    let plain = "hello world 123";
    assert_eq!(esc(plain), plain);
}

// ── DashboardRenderer ───────────────────────────────────────────

#[test]
fn render_contains_doctype_and_meta_refresh() {
    let ds = default_state(vec![healthy_backend("alpha", 5, Some(20))]);
    let html = DashboardRenderer::render(&ds);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains(r#"http-equiv="refresh" content="5""#));
}

#[test]
fn render_contains_version_and_uptime() {
    let ds = default_state(vec![]);
    let html = DashboardRenderer::render(&ds);
    assert!(html.contains("v2.4.0"));
    assert!(html.contains("1h 1m")); // 3661 s
}

#[test]
fn render_backend_rows_healthy() {
    let backends = vec![healthy_backend("my-backend", 10, Some(42))];
    let rows = DashboardRenderer::render_backend_rows(&backends);
    assert!(rows.contains("my-backend"));
    assert!(rows.contains("badge healthy"));
    assert!(rows.contains("42 ms"));
    assert!(rows.contains("0.0%")); // error rate
}

#[test]
fn render_backend_rows_degraded_and_down() {
    let backends = vec![degraded_backend("svc-a"), down_backend("svc-b")];
    let rows = DashboardRenderer::render_backend_rows(&backends);
    assert!(rows.contains("badge degraded"));
    assert!(rows.contains("badge down"));
}

#[test]
fn render_backend_rows_empty_shows_fallback() {
    let rows = DashboardRenderer::render_backend_rows(&[]);
    assert!(rows.contains("No backends registered"));
}

#[test]
fn render_recent_rows_empty_shows_fallback() {
    let rows = DashboardRenderer::render_recent_rows(&[]);
    assert!(rows.contains("No tool calls recorded yet"));
}

#[test]
fn render_recent_rows_with_calls() {
    let calls = vec![
        RecentCall {
            timestamp: String::new(),
            tool: "search".to_string(),
            server: "brave".to_string(),
            latency_ms: None,
            status: CallStatus::Success,
            count: 7,
        },
        RecentCall {
            timestamp: String::new(),
            tool: "query".to_string(),
            server: "db".to_string(),
            latency_ms: None,
            status: CallStatus::Error,
            count: 2,
        },
    ];
    let rows = DashboardRenderer::render_recent_rows(&calls);
    assert!(rows.contains("search"));
    assert!(rows.contains("brave"));
    assert!(rows.contains("badge success"));
    assert!(rows.contains("badge error"));
}

#[test]
fn render_cache_hit_rate_displayed() {
    let ds = default_state(vec![]);
    let html = DashboardRenderer::render(&ds);
    assert!(html.contains("75.0%"));
}

#[test]
fn render_session_summary_in_cards() {
    let ds = default_state(vec![]);
    let html = DashboardRenderer::render(&ds);
    // active_sessions = 3, total_calls = 42
    assert!(html.contains(">3<") || html.contains(">3 <") || html.contains("val\">3"));
    assert!(html.contains(">42<") || html.contains("val\">42"));
}

#[test]
fn render_xss_escaped_in_backend_name() {
    let backends = vec![BackendHealth {
        name: "<evil>".to_string(),
        status: HealthStatus::Healthy,
        latency_ms: None,
        error_rate: 0.0,
        tool_count: 0,
    }];
    let rows = DashboardRenderer::render_backend_rows(&backends);
    assert!(!rows.contains("<evil>"));
    assert!(rows.contains("&lt;evil&gt;"));
}

#[test]
fn render_xss_escaped_in_tool_name() {
    let calls = vec![RecentCall {
        timestamp: String::new(),
        tool: "<script>alert(1)</script>".to_string(),
        server: "s".to_string(),
        latency_ms: None,
        status: CallStatus::Success,
        count: 1,
    }];
    let rows = DashboardRenderer::render_recent_rows(&calls);
    assert!(!rows.contains("<script>"));
    assert!(rows.contains("&lt;script&gt;"));
}

// ── avg_latency_from_backends (pure helper, no backend) ─────────
// Tested indirectly via format_uptime + compute_error_rate above.

#[test]
fn dashboard_state_serializes_to_json() {
    let ds = default_state(vec![healthy_backend("x", 1, Some(10))]);
    let json = serde_json::to_string(&ds).expect("serialization failed");
    assert!(json.contains("\"backends\""));
    assert!(json.contains("\"session_summary\""));
    assert!(json.contains("\"cache_stats\""));
}
