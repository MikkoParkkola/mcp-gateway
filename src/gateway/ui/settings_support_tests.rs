// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real files and reloads shared by the settings route rows.
use super::*;
use crate::config::{AuthConfig, Config, FailsafeConfig};
use crate::config_reload::{FileRevision, LiveConfig, ReloadContext};
use crate::gateway::{auth::AuthenticatedClient, routes, test_helpers::write_owner_only};
use axum::{
    body::{Body, to_bytes},
    extract::FromRequest,
    http::{Method, Request, StatusCode},
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub(super) const BASE: &str = "# operator's note\nenvironment: \"dev\" # where\nsecrets:\n  store: files\nauth:\n  enabled: false\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n    owner: \"team\"\n";
#[cfg(feature = "cost-governance")]
pub(super) const BUDGET: &str = "# operator's note\nsecrets:\n  store: files\ncost_governance:\n  enabled: true\n  budgets:\n    daily: 10.0 # daily cap\nbackends: {}\n";

pub(super) struct Route {
    pub(super) dir: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
    pub(super) state: Arc<AppState>,
    pub(super) ctx: Arc<ReloadContext>,
    pub(super) store: Option<SettingsStoreForTest>,
}
impl Route {
    pub(super) async fn new(text: &str) -> Self {
        Self::with_reload(text, false).await
    }
    pub(super) async fn with_reload(text: &str, refusing: bool) -> Self {
        let dir = Arc::new(tempfile::tempdir().expect("dir"));
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("config");
        let running = Config::load(Some(&path)).expect("fixture loads");
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        )
        .await;
        Arc::get_mut(&mut state).expect("unique state").config_path = Some(path.clone());
        let ctx = ReloadContext::new(
            path,
            Arc::new(LiveConfig::new(running)),
            Arc::clone(&state.backends),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("context");
        let ctx = Arc::new(if refusing {
            ctx.refusing_reloads_for_test()
        } else {
            ctx
        });
        state.meta_mcp.set_reload_context(Arc::clone(&ctx));
        Self {
            dir,
            _store: store,
            state,
            ctx,
            store: None,
        }
    }
    /// The same config file on a gateway with no reload context.
    pub(super) async fn without_reload(mut self) -> Self {
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        )
        .await;
        Arc::get_mut(&mut state).expect("unique state").config_path = Some(self.path());
        self.state = state;
        self._store = store;
        self
    }
    pub(super) fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }
    pub(super) fn text(&self) -> String {
        std::fs::read_to_string(self.path()).expect("file")
    }
    pub(super) fn write(&self, text: &str) {
        write_owner_only(self.path(), text).expect("outside edit");
    }
    pub(super) fn revision(&self) -> String {
        FileRevision::of(self.text().as_bytes()).as_str().into()
    }
    pub(super) fn saved_body(&self, fields: &Value) -> Value {
        json!({"base_revision": self.revision(), "fields": fields})
    }
    pub(super) async fn diff(&self, fields: Value) -> (StatusCode, Value) {
        self.raw(false, &json!({"fields": fields}).to_string(), client(true))
            .await
    }
    pub(super) async fn save(&self, fields: Value) -> (StatusCode, Value) {
        self.raw(true, &self.saved_body(&fields).to_string(), client(true))
            .await
    }
    pub(super) async fn raw(
        &self,
        save: bool,
        body: &str,
        who: AuthenticatedClient,
    ) -> (StatusCode, Value) {
        decode(self.response(save, body, who).await).await
    }
    pub(super) async fn response(
        &self,
        save: bool,
        body: &str,
        who: AuthenticatedClient,
    ) -> Response {
        let route = if save {
            routes::UI_SETTINGS
        } else {
            routes::UI_SETTINGS_DIFF
        };
        let request = Request::builder()
            .method("POST")
            .uri(route)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request");
        let guard = Guard::for_route(route, &Method::POST, Some(who));
        let store = self.store.clone().map(Extension);
        if save {
            let body = Json::<SaveBody>::from_request(request, &()).await;
            settings_save(State(self.state.clone()), store, guard, body).await
        } else {
            let body = Json::<DiffBody>::from_request(request, &()).await;
            settings_diff(State(self.state.clone()), store, guard, body).await
        }
    }
    pub(super) fn audit(&mut self) -> Arc<crate::security::TransparencyLogger> {
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: self
                        .dir
                        .path()
                        .join("audit.jsonl")
                        .to_string_lossy()
                        .into_owned(),
                    key_id: "settings-test".into(),
                    ..Default::default()
                },
            ))
            .expect("log"),
        );
        log.keep_test_dir(Arc::clone(&self.dir));
        Arc::get_mut(&mut self.state)
            .expect("unique state")
            .transparency_log = Some(log.clone());
        log
    }
}
pub(super) fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "settings-route".into(),
        rate_limit: 0,
        backends: vec!["*".into()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        principal: crate::gateway::auth::principal_of("settings-route-key"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}
pub(super) async fn decode(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (status, serde_json::from_slice(&bytes).expect("JSON answer"))
}
pub(super) fn set(field: &str, value: &Value) -> Value {
    json!({"field": field, "value": {"set": value}})
}
pub(super) fn secret(value: &str) -> Value {
    json!({"field": "auth.bearer_token", "value": {"secret": value}})
}
pub(super) fn refused(answer: (StatusCode, Value), status: StatusCode, code: &str) -> Value {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(answer.1["error"], code);
    answer.1
}
