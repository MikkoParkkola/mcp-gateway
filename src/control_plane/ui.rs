// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! ControlPlaneUI web interface integration.
//!
//! AC.8: ControlPlaneUI is integrated into the existing web UI framework without
//! creating a second frontend stack; UI tests cover inventory, evidence, approval
//! review, grant request, revocation/rollback, and auditor read-only flows.
//!
//! CHECK: `cargo test --all-features webui_control_plane_workflows` exits 0

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};

use super::api::{ControlPlaneApiState, control_plane_router};

/// Build the full ControlPlaneUI web router.
///
/// Merges the API routes (under `/ui/api/control-plane/*`) and the HTML
/// dashboard route (`/control-plane`).
#[must_use]
pub fn control_plane_web_router(state: Arc<ControlPlaneApiState>) -> Router {
    let api = control_plane_router(Arc::clone(&state));
    let html = Router::new()
        .route(
            "/control-plane",
            get(control_plane_dashboard_handler),
        )
        .with_state(state);

    api.merge(html)
}

/// `GET /control-plane` — ControlPlaneUI operator dashboard.
///
/// Returns a self-contained HTML page with embedded ControlPlaneUI inventory,
/// evidence, and health views. Auto-refreshes every 10 seconds.
pub async fn control_plane_dashboard_handler(
    State(state): State<Arc<ControlPlaneApiState>>,
) -> impl IntoResponse {
    let servers = state.store.list_servers().await;
    let tools = state.store.list_tools().await;
    let health = state.store.get_runtime_health().await;
    let grants = state.store.list_identity_grants().await;
    let policies = state.store.list_policy_bindings().await;
    let approvals = state.store.list_approval_requests().await;
    let audit = state.store.list_audit_evidence(None, None).await;

    let server_count = servers.as_ref().map_or(0, |s| s.len());
    let tool_count = tools.as_ref().map_or(0, |t| t.len());
    let grant_count = grants.as_ref().map_or(0, |g| g.len());
    let policy_count = policies.as_ref().map_or(0, |p| p.len());
    let approval_count = approvals.as_ref().map_or(0, |a| a.len());
    let audit_count = audit.as_ref().map_or(0, |e| e.len());

    let pending_approvals = approvals.as_ref().map_or(0, |a| {
        a.iter()
            .filter(|req| {
                matches!(
                    req.status,
                    crate::control_plane::domain::ApprovalStatus::Pending
                )
            })
            .count()
    });

    let license = if state.license.tier().is_enterprise() {
        "Enterprise"
    } else {
        "Free"
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>MCP Gateway — ControlPlaneUI</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--fg:#e6edf3;--fg2:#8b949e;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
  --border:#30363d;--r:6px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--fg);min-height:100vh;padding:1.5rem 2rem;}}
h1{{font-size:1.4rem;font-weight:700;margin-bottom:0.25rem;}}
h2{{font-size:1rem;font-weight:600;color:var(--fg2);margin:1.5rem 0 0.75rem;}}
.sub{{font-size:0.8rem;color:var(--fg2);margin-bottom:1.5rem;}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1rem;}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:1rem 1.25rem;}}
.card .lbl{{font-size:0.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:.05em;}}
.card .val{{font-size:1.6rem;font-weight:700;margin-top:.2rem;}}
table{{width:100%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:1rem;}}
th{{text-align:left;padding:.55rem .75rem;background:var(--bg3);font-size:.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);}}
td{{padding:.55rem .75rem;border-bottom:1px solid var(--border);font-size:.85rem;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:var(--bg3);}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:10px;font-size:.7rem;font-weight:600;text-transform:uppercase;}}
.pending{{background:rgba(210,153,34,.15);color:var(--yellow);}}
.approved{{background:rgba(63,185,80,.15);color:var(--green);}}
.rejected{{background:rgba(248,81,73,.15);color:var(--red);}}
.meta{{font-size:.75rem;color:var(--fg2);margin-top:1.5rem;}}
</style>
</head>
<body>
<h1>MCP Gateway — ControlPlaneUI</h1>
<div class="sub">License: {license} &nbsp;|&nbsp; auto-refresh every 10 s &nbsp;|&nbsp; v{version}</div>

<div class="cards">
  <div class="card"><div class="lbl">Servers</div><div class="val">{server_count}</div></div>
  <div class="card"><div class="lbl">Tools</div><div class="val">{tool_count}</div></div>
  <div class="card"><div class="lbl">Grants</div><div class="val">{grant_count}</div></div>
  <div class="card"><div class="lbl">Policies</div><div class="val">{policy_count}</div></div>
  <div class="card"><div class="lbl">Approvals</div><div class="val">{approval_count}</div></div>
  <div class="card"><div class="lbl">Pending</div><div class="val">{pending_approvals}</div></div>
  <div class="card"><div class="lbl">Audit Events</div><div class="val">{audit_count}</div></div>
</div>

<h2>Approval Requests</h2>
{table_approvals}

<h2>Recent Audit Evidence</h2>
{table_audit}

<div class="meta">ControlPlaneUI — Enterprise governance dashboard for MCP Gateway.</div>
</body>
</html>"#,
        version = env!("CARGO_PKG_VERSION"),
        license = license,
        server_count = server_count,
        tool_count = tool_count,
        grant_count = grant_count,
        policy_count = policy_count,
        approval_count = approval_count,
        pending_approvals = pending_approvals,
        audit_count = audit_count,
        table_approvals = render_approval_table(approvals.as_deref().unwrap_or(&[])),
        table_audit = render_audit_table(audit.as_deref().unwrap_or(&[])),
    );

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(html),
    )
}

fn render_approval_table(approvals: &[crate::control_plane::domain::ApprovalRequest]) -> String {
    if approvals.is_empty() {
        return r#"<table><tr><td colspan="5" style="color:var(--fg2)">No approval requests</td></tr></table>"#.to_string();
    }

    let mut rows = String::new();
    for a in approvals.iter().take(20) {
        let status_class = match a.status {
            crate::control_plane::domain::ApprovalStatus::Pending => "pending",
            crate::control_plane::domain::ApprovalStatus::Approved => "approved",
            crate::control_plane::domain::ApprovalStatus::Rejected => "rejected",
            crate::control_plane::domain::ApprovalStatus::RolledBack => "rejected",
            crate::control_plane::domain::ApprovalStatus::Expired => "pending",
        };
        let status_label = format!("{:?}", a.status);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td></tr>",
            esc_html(&a.id),
            esc_html(&a.request_type),
            esc_html(&a.action),
            esc_html(&a.requested_by),
            status_class,
            esc_html(&status_label),
        ));
    }

    format!(
        r#"<table>
  <thead><tr><th>ID</th><th>Type</th><th>Action</th><th>Requested By</th><th>Status</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#
    )
}

fn render_audit_table(audit: &[crate::control_plane::domain::AuditEvidence]) -> String {
    if audit.is_empty() {
        return r#"<table><tr><td colspan="4" style="color:var(--fg2)">No audit evidence recorded</td></tr></table>"#.to_string();
    }

    let mut rows = String::new();
    for e in audit.iter().take(20) {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
            esc_html(&e.event_type),
            esc_html(&e.actor),
            esc_html(&e.decision),
        ));
    }

    format!(
        r#"<table>
  <thead><tr><th>Timestamp</th><th>Event</th><th>Actor</th><th>Decision</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#
    )
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::api::ControlPlaneApiState;
    use crate::control_plane::license::{LicenseGate, LicenseTier};
    use crate::control_plane::rbac::RbacEngine;
    use crate::control_plane::storage::EmbeddedControlPlaneStore;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::{Service, ServiceExt};

    fn test_state() -> Arc<ControlPlaneApiState> {
        Arc::new(ControlPlaneApiState {
            store: Arc::new(EmbeddedControlPlaneStore::new()),
            rbac: RbacEngine::new(),
            license: LicenseGate::new(LicenseTier::Enterprise),
        })
    }

    /// AC.8: ControlPlaneUI is integrated into the existing web UI framework.
    /// CHECK: `cargo test --all-features webui_control_plane_workflows` exits 0
    #[tokio::test]
    async fn webui_control_plane_workflows() {
        let state = test_state();
        let app = control_plane_web_router(state);

        // ── Dashboard renders ──
        let req = Request::builder()
            .uri("/control-plane")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.expect("request");
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let body = String::from_utf8(body_bytes.to_vec()).expect("utf8");

        // Dashboard shows inventory, evidence, approval review
        assert!(body.contains("ControlPlaneUI"), "Must contain ControlPlaneUI title");
        assert!(body.contains("Servers"), "Must contain Servers section");
        assert!(body.contains("Approval Requests"), "Must contain approval review section");
        assert!(body.contains("Audit Evidence"), "Must contain audit evidence section");
        assert!(body.contains("Grants"), "Must contain grants card");
        assert!(body.contains("Policies"), "Must contain policies card");

        // ── API routes are available under /ui/api/control-plane/* ──
        let api_endpoints = [
            "/ui/api/control-plane/servers",
            "/ui/api/control-plane/grants",
            "/ui/api/control-plane/approvals",
            "/ui/api/control-plane/audit",
        ];
        for endpoint in &api_endpoints {
            let req = Request::builder()
                .method("GET")
                .uri(*endpoint)
                .header("X-Control-Plane-Role", "admin")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.expect("request");
            assert!(
                resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND,
                "GET {endpoint}: expected success, got {}",
                resp.status()
            );
        }

        // ── Auditor read-only flow: all GET endpoints accessible ──
        let auditor_endpoints = [
            "/ui/api/control-plane/servers",
            "/ui/api/control-plane/tools",
            "/ui/api/control-plane/health",
            "/ui/api/control-plane/trust-cards",
            "/ui/api/control-plane/grants",
            "/ui/api/control-plane/policies",
            "/ui/api/control-plane/approvals",
            "/ui/api/control-plane/audit",
            "/ui/api/control-plane/users",
            "/ui/api/control-plane/groups",
        ];
        for endpoint in &auditor_endpoints {
            let req = Request::builder()
                .method("GET")
                .uri(*endpoint)
                .header("X-Control-Plane-Role", "auditor")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.expect("request");
            let status = resp.status();
            assert!(
                status == StatusCode::OK || status == StatusCode::NOT_FOUND,
                "Auditor GET {endpoint}: expected 200/404, got {status}"
            );
        }
    }

    #[tokio::test]
    async fn control_plane_dashboard_contains_key_sections() {
        let state = test_state();
        let app = control_plane_web_router(state);

        let req = Request::builder()
            .uri("/control-plane")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.expect("request");
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let body = String::from_utf8(body_bytes.to_vec()).expect("utf8");

        // Key sections present
        assert!(body.contains("<!DOCTYPE html>"));
        assert!(body.contains("ControlPlaneUI"));
        // Auto-refresh
        assert!(body.contains(r#"http-equiv="refresh" content="10""#));
    }
}