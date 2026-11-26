// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`: create an API key in gateway.yaml.
//!
//! The caller names the key, its scope and the gateway.yaml revision it saw.
//! The route checks, in order: admin, a config file, reload and a loadable
//! file, a free name, a current revision, then the values themselves. Every
//! refusal is fixed text that names a field at most, never the body or a
//! value. One refusal quotes a name: a name its own routes cannot address
//! gets the shared name rule's message, the name escaped (a key's name is
//! no secret). The secret is generated here and nowhere else (see `write`).

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use super::config_file::{Gateway, read_gateway};
use super::errors::{flat_error, gate_refusal, stale, structured_error};
use super::guard::Guard;
use super::settings::caller_is_cli_key;
use crate::config::{ApiKeyConfig, AuthConfig, Config, EnvOverlay};
use crate::config_persistence::keyedit::{
    Change, FieldPath, Scalar, Segment, Template, edit_in_place,
};
use crate::config_reload::{
    AuditPosture, Expected, FileRevision, GatewayAuth, IntentKind, LiveConfig, NO_AUDIT_LOG,
    RELOAD_LOCK_WAIT, Replace, ReplaceError, ReplaceOutcome, ReplaceReload, Replaced, StatusChange,
    Waiting, replace_audited, restart_pending_guard, waiting_first_key, waiting_names,
};
use crate::gateway::auth::SessionMintedBy;
use crate::gateway::router::AppState;

/// Under test, a request may carry the secret the route hands out, so a row
/// knows it and its digest.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct KnownSecret(pub(super) String);

/// Under test, a request may carry a hook that runs after the route's checks
/// and just before it asks the writer for the config lock.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct BeforeLock(pub(super) Arc<dyn Fn() + Send + Sync>);

/// Under test, a request may carry the writer's answer, standing in for the
/// writer so a row reaches every `ReplaceError` variant.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct InjectWriter(
    pub(super) Arc<dyn Fn() -> Result<ReplaceOutcome, ReplaceError> + Send + Sync>,
);

/// The create body: strict, so a key outside the list is refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBody {
    name: String,
    backends: Vec<String>,
    allowed_tools: Option<Vec<String>>,
    denied_tools: Option<Vec<String>>,
    admin: Option<bool>,
    rate_limit: Option<u32>,
    expires_at: Option<DateTime<Utc>>,
    revision: String,
}

fn fixed(status: StatusCode, message: &'static str) -> Response {
    flat_error(status, message).into_response()
}

/// A write whose outcome the gateway could not observe: the key may or may
/// not be in gateway.yaml. Its secret was never returned, so the way out is
/// to re-read the list, never to retry blindly.
fn state_uncertain() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "state_uncertain",
            "recovery": "the key may or may not have been written: read GET /ui/api/keys before creating it again; a key listed there was never handed out and cannot be used, so remove it from gateway.yaml and reload first",
        })),
    )
        .into_response()
}

/// The one refusal every unreadable body gets.
fn invalid_body() -> Response {
    structured_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_body",
        "the body must be {\"name\", \"backends\", \"revision\"} and the optional \
         allowed_tools, denied_tools, admin, rate_limit and expires_at, and nothing else",
    )
    .into_response()
}

/// A value the loader or the clock refuses: the field is named, the value never.
fn invalid_field(field: &'static str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "invalid_field",
            "field": field,
            "message": "the value is not accepted",
        })),
    )
        .into_response()
}

/// Whether the loader accepts a config holding only `key`.
fn loader_accepts(key: ApiKeyConfig) -> bool {
    let config = Config {
        auth: AuthConfig {
            api_keys: vec![key],
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    config.validate_with_env(&EnvOverlay::none()).is_ok()
}

/// The first body field the loader would refuse, judged one field at a time
/// over an entry that is otherwise valid, so no loader text is parsed.
fn refused_field(body: &CreateBody) -> Option<&'static str> {
    let base = ApiKeyConfig {
        name: "valid".into(),
        key_sha256: Some(crate::config::api_key_digest_spec(b"validation")),
        backends: vec!["*".into()],
        ..ApiKeyConfig::default()
    };
    let probes: [(&'static str, ApiKeyConfig); 4] = [
        (
            "name",
            ApiKeyConfig {
                name: body.name.clone(),
                ..base.clone()
            },
        ),
        (
            "backends",
            ApiKeyConfig {
                backends: body.backends.clone(),
                ..base.clone()
            },
        ),
        (
            "allowed_tools",
            ApiKeyConfig {
                allowed_tools: body.allowed_tools.clone(),
                ..base.clone()
            },
        ),
        (
            "denied_tools",
            ApiKeyConfig {
                denied_tools: body.denied_tools.clone(),
                ..base
            },
        ),
    ];
    probes
        .into_iter()
        .find(|(_, key)| !loader_accepts(key.clone()))
        .map(|(field, _)| field)
}

/// A requested expiry at or before now would never authenticate.
fn expired_by(expires_at: Option<DateTime<Utc>>) -> Result<(), Box<Response>> {
    let Some(at) = expires_at else { return Ok(()) };
    match crate::clock::utc_now() {
        Ok(now) if !crate::config::api_key_expired(Some(at), now) => Ok(()),
        Ok(_) => Err(Box::new(invalid_field("expires_at"))),
        Err(_) => Err(Box::new(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the clock cannot be read",
        ))),
    }
}

/// What the preconditions found: the file as read, for the write.
struct Checked {
    revision: FileRevision,
    config: Config,
    context: Arc<crate::config_reload::ReloadContext>,
}

/// The preconditions, in order: a config file, reload and a loadable file, a
/// free name, a current revision.
async fn preconditions(state: &AppState, body: &CreateBody) -> Result<Checked, Box<Response>> {
    let path = state.config_path.clone();
    let read = tokio::task::spawn_blocking(move || read_gateway("keys", path.as_deref())).await;
    if matches!(read, Ok(Ok(Gateway::None))) {
        return Err(Box::new(fixed(StatusCode::CONFLICT, "no_config_file")));
    }
    let (Ok(Ok(Gateway::File { revision, config })), Some(context)) =
        (read, state.meta_mcp.reload_context())
    else {
        return Err(Box::new(fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload is off or gateway.yaml could not be loaded",
        )));
    };
    if config.auth.api_keys.iter().any(|k| k.name == body.name) {
        return Err(Box::new(fixed(StatusCode::CONFLICT, "name_taken")));
    }
    if revision.as_str() != body.revision {
        return Err(Box::new(stale(&revision).into_response()));
    }
    Ok(Checked {
        revision,
        config: *config,
        context,
    })
}

/// The new key as the writer sees it: the body's fields and the digest spec.
/// It has no field for the secret, so nothing derived from it can carry one.
struct NewKeyEntry {
    name: String,
    key_sha256: String,
    backends: Vec<String>,
    allowed_tools: Option<Vec<String>>,
    denied_tools: Option<Vec<String>>,
    admin: Option<bool>,
    rate_limit: Option<u32>,
    expires_at: Option<DateTime<Utc>>,
}

impl NewKeyEntry {
    fn of(body: CreateBody, key_sha256: String) -> Self {
        Self {
            name: body.name,
            key_sha256,
            backends: body.backends,
            allowed_tools: body.allowed_tools,
            denied_tools: body.denied_tools,
            admin: body.admin,
            rate_limit: body.rate_limit,
            expires_at: body.expires_at,
        }
    }

    /// The entry as the loader will read it, for the candidate checks.
    fn as_key(&self) -> ApiKeyConfig {
        ApiKeyConfig {
            name: self.name.clone(),
            key_sha256: Some(self.key_sha256.clone()),
            backends: self.backends.clone(),
            allowed_tools: self.allowed_tools.clone(),
            denied_tools: self.denied_tools.clone(),
            admin: self.admin.unwrap_or(false),
            rate_limit: self.rate_limit.unwrap_or(0),
            expires_at: self.expires_at,
            ..ApiKeyConfig::default()
        }
    }

    /// One new list element at `at`: each given field set in place.
    fn changes(&self, at: usize) -> Vec<(FieldPath, Change)> {
        let path = |field: &str| {
            let keys = ["auth", "api_keys"].map(|k| Segment::Key(k.to_owned()));
            let mut segments = keys.to_vec();
            segments.extend([Segment::Index(at), Segment::Key(field.to_owned())]);
            FieldPath(segments)
        };
        let text = |value: &str| Change::Set(Scalar::Str(value.to_owned()));
        let mut out = vec![
            (path("name"), text(&self.name)),
            (path("key_sha256"), text(&self.key_sha256)),
            (path("backends"), Change::List(self.backends.clone())),
        ];
        for (field, list) in [
            ("allowed_tools", &self.allowed_tools),
            ("denied_tools", &self.denied_tools),
        ] {
            out.extend(list.iter().map(|l| (path(field), Change::List(l.clone()))));
        }
        out.extend(
            self.admin
                .map(|a| (path("admin"), Change::Set(Scalar::Bool(a)))),
        );
        out.extend(
            self.rate_limit
                .map(|r| (path("rate_limit"), Change::Set(Scalar::Int(i64::from(r))))),
        );
        let expiry = self
            .expires_at
            .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        out.extend(expiry.map(|at| (path("expires_at"), text(&at))));
        out
    }
}

/// Why the compute refused, for the route's own answer: the writer's `String`
/// channel is never parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Refusal {
    Expired,
    /// API keys already wait in the file as read; their names.
    Waiting(Vec<String>),
    NotWritten,
}

/// What the compute decided, filled under the lock and read after the writer:
/// its refusal, if any, and whether the file with this key is a first key
/// the writer will hold (to tell a held write's `Unconfirmed` apart).
#[derive(Default)]
struct Decided {
    refusal: Option<Refusal>,
    held: bool,
}

type Outcome = Arc<Mutex<Decided>>;

/// What the compute reads under the lock besides the file's bytes: the file
/// as the preconditions loaded it (the writer's revision check makes them
/// the same bytes) and the environment its references resolve in.
struct Judge {
    live: Arc<LiveConfig>,
    env: Arc<crate::config::LiveEnv>,
    file: Config,
    outcome: Outcome,
}

impl Judge {
    fn cell(&self) -> std::sync::MutexGuard<'_, Decided> {
        self.outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn refuse_with(&self, why: Refusal) -> String {
        let label = match &why {
            Refusal::Expired => "expired",
            Refusal::Waiting(_) => "keys_waiting",
            Refusal::NotWritten => "not_written",
        };
        self.cell().refusal = Some(why);
        label.to_owned()
    }

    /// The expiry against the clock as read now, under the lock.
    fn check_expiry(&self, expires_at: Option<DateTime<Utc>>) -> Result<(), String> {
        let Some(at) = expires_at else { return Ok(()) };
        match crate::clock::utc_now() {
            Ok(now) if !crate::config::api_key_expired(Some(at), now) => Ok(()),
            _ => Err(self.refuse_with(Refusal::Expired)),
        }
    }

    /// One wait at a time: a file in which API keys already wait takes no
    /// other key, even after a hand edit broke it. Otherwise the writer's own
    /// question on the file with this key decides whether it is held; the
    /// same answer is noted here for the route.
    fn check_waiting(&self, entry: &NewKeyEntry) -> Result<(), String> {
        let (generation, overlay) = (self.live.generation(), self.env.get());
        let running = self.live.running();
        let file = waiting_first_key(running, &generation, &self.file, &overlay);
        let waiting = waiting_names(&generation, &self.file);
        if let Some(waiting) = restart_pending_guard(&file, waiting) {
            return Err(self.refuse_with(Refusal::Waiting(waiting.names().to_vec())));
        }
        let mut candidate = self.file.clone();
        candidate.auth.api_keys.push(entry.as_key());
        self.cell().held = matches!(
            waiting_first_key(running, &generation, &candidate, &overlay),
            Waiting::Yes { keys, .. } if keys.contains(&entry.name)
        );
        Ok(())
    }
}

/// The writer's compute: appends the entry to `auth.api_keys` in place, after
/// the expiry, and any key already waiting in the file, are judged on the
/// bytes it was handed.
fn compute(
    entry: NewKeyEntry,
    judge: Judge,
) -> impl FnOnce(&[u8]) -> Result<Template, String> + Send {
    move |bytes| {
        let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
        judge.check_expiry(entry.expires_at)?;
        judge.check_waiting(&entry)?;
        let at = judge.file.auth.api_keys.len();
        edit_in_place(text, &entry.changes(at)).map_err(|_| judge.refuse_with(Refusal::NotWritten))
    }
}

fn audit_unavailable() -> Response {
    fixed(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable")
}

/// Writes `replace` under the key write's audit: its intent names the caller
/// and the key. No audit log is no write, whatever the auth posture.
async fn write_audited(
    state: &AppState,
    guard: &Guard,
    (name, context): (&str, Arc<crate::config_reload::ReloadContext>),
    replace: Replace,
) -> Result<ReplaceOutcome, ReplaceError> {
    let log = state
        .transparency_log
        .clone()
        // No log is refused here, as the audit's own refusal, so the
        // posture below never sees a missing log: its `NoAuditLog` can't
        // reach this route.
        .ok_or_else(|| ReplaceError::AuditRefused(NO_AUDIT_LOG.to_owned()))?;
    let auth = GatewayAuth::of(state.live_config.running().auth.enabled);
    let who = super::admin_audit::caller_who(state, guard.client.as_ref(), guard.identity.as_ref());
    let account = who.account.clone();
    let audit = AuditPosture::of(Some(log), auth).key_write(IntentKind::KeyCreate, who, name)?;
    replace_audited(
        context,
        replace,
        audit,
        crate::config_reload::history::Source::Ui { who: account },
        RELOAD_LOCK_WAIT,
    )
    .await
}

/// Whether the live generation holds `name` under `digest` (a spec): the
/// reload's own restart flag says nothing about a key list.
fn landed(state: &AppState, name: &str, digest: &str) -> bool {
    let Some(wanted) = crate::config::parse_api_key_digest(digest) else {
        return false;
    };
    let generation = state.live_config.generation();
    let keys = generation.auth().api_keys();
    keys.iter().any(|k| k.name == name && k.digest == wanted)
}

/// The 201: the name, the key once, the new revision; never cached.
fn created(name: &str, once: &str, revision: &FileRevision) -> Response {
    let mut response = (
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({"name": name, "secret": once, "revision": revision.as_str()})),
    )
        .into_response();
    let detail = serde_json::json!({"key": name, "action": "create"});
    if let Some(fields) = detail.as_object() {
        let fields = super::admin_audit::AuditDetail(fields.clone());
        response.extensions_mut().insert(fields);
    }
    response
}

/// The 201 of a key written now and put in force by the next start, the only
/// route answer that speaks of a restart (the writer's question checked that
/// a start from these bytes is not refused). Never cached; the admin record
/// says it is pending.
fn held(name: &str, once: &str, revision: &FileRevision) -> Response {
    let mut response = (
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "name": name,
            "secret": once,
            "revision": revision.as_str(),
            "pending_restart": true,
            "message": format!(
                "The key `{name}` is created; it takes effect at the next restart of the gateway."
            ),
        })),
    )
        .into_response();
    let detail = json!({"key": name, "action": "create", "pending_restart": true});
    if let Some(fields) = detail.as_object() {
        let fields = super::admin_audit::AuditDetail(fields.clone());
        response.extensions_mut().insert(fields);
    }
    response
}

/// A held create whose write could not be recorded: which gateway.yaml
/// stands is settled by the next holder of the config lock, so the answer
/// promises neither. No secret was handed out.
fn held_unconfirmed() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "state_uncertain",
            "recovery": "nobody received this key's value, so it cannot be used. Which \
                gateway.yaml is in place is not known yet: save any other setting first, which \
                settles it. If the key then shows in the list, revoke it, and only then restart. \
                Already restarted and the web UI no longer answers? Delete that key's entry \
                from gateway.yaml by hand, then start the gateway again.",
        })),
    )
        .into_response()
}

/// The hand steps when keyedit cannot edit in place.
fn not_written(state: &AppState) -> Response {
    let path = state
        .config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "not_written",
            "message": format!(
                "{path} cannot be edited in place; nothing was written. Run \
                 `mcp-gateway hash-key` on the new key, add an entry to auth.api_keys \
                 with the key_sha256 it prints, then reload."
            ),
        })),
    )
        .into_response()
}

/// The variant's name, for the log: never its payload.
fn variant_of(error: &ReplaceError) -> &'static str {
    match error {
        ReplaceError::Busy => "busy",
        ReplaceError::Gated(_) => "gated",
        ReplaceError::Stale { .. } => "stale",
        ReplaceError::Refused(_) => "refused",
        ReplaceError::AuditRefused(_) => "audit_refused",
        ReplaceError::NoAuditLog => "no_audit_log",
        ReplaceError::Unsupported(_) => "unsupported",
        ReplaceError::Stage(_) => "stage",
        ReplaceError::Write(_) => "write",
        ReplaceError::WriterRefused { .. } => "writer_refused",
        ReplaceError::ReloadRefused { .. } => "reload_refused",
        ReplaceError::RollbackFailed { .. } => "rollback_failed",
        ReplaceError::Unconfirmed { .. } => "unconfirmed",
        ReplaceError::Failed(_) => "failed",
        ReplaceError::Secrets(_) => "secrets",
        ReplaceError::NoConfigFile => "no_config_file",
        ReplaceError::ConfigRefused(_) => "config_refused",
    }
}

/// Every write that did not end in a live key, as fixed text. The compute's
/// own refusal wins; a writer refusal with none is the audit log's (the
/// compute and the loader check are the others).
fn refused_write(
    state: &AppState,
    refusal: Option<Refusal>,
    written: Result<ReplaceOutcome, ReplaceError>,
) -> Response {
    if let Err(error) = &written {
        tracing::warn!(
            variant = variant_of(error),
            "key create: the config write failed"
        );
    }
    match (refusal, written) {
        (Some(Refusal::Expired), _) => invalid_field("expires_at"),
        (Some(Refusal::Waiting(keys)), _) => super::errors::restart_pending(&keys),
        (Some(Refusal::NotWritten), _) => not_written(state),
        (None, Err(ReplaceError::Stale { current })) => stale(&current).into_response(),
        (None, Err(ReplaceError::Busy)) => fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the config is being written; retry",
        ),
        (None, Err(ReplaceError::Gated(refusal))) => gate_refusal(refusal),
        (None, Err(ReplaceError::ReloadRefused { .. })) => {
            fixed(StatusCode::CONFLICT, "reload_refused")
        }
        (None, Err(ReplaceError::AuditRefused(_) | ReplaceError::NoAuditLog)) => {
            audit_unavailable()
        }
        // The writer's own read check: nothing was written, so these are the
        // preconditions' answers, never the guard's text.
        (None, Err(ReplaceError::NoConfigFile)) => fixed(StatusCode::CONFLICT, "no_config_file"),
        (None, Err(ReplaceError::ConfigRefused(_))) => fixed(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload is off or gateway.yaml could not be loaded",
        ),
        (
            None,
            Err(
                ReplaceError::Refused(_)
                | ReplaceError::Unsupported(_)
                | ReplaceError::Stage(_)
                | ReplaceError::Write(_)
                | ReplaceError::WriterRefused { .. }
                | ReplaceError::Secrets(_),
            ),
        ) => fixed(StatusCode::INTERNAL_SERVER_ERROR, "the key was not created"),
        (None, _) => state_uncertain(),
    }
}

/// `POST /ui/api/keys`.
/// A CLI key must not mint an unbound successor that outlives its approver.
pub(super) async fn create_key(
    State(state): State<std::sync::Arc<AppState>>,
    guard: Guard,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    session: Option<Extension<SessionMintedBy>>,
    #[cfg(test)] known: Option<axum::Extension<KnownSecret>>,
    #[cfg(test)] (before_lock, inject): (
        Option<axum::Extension<BeforeLock>>,
        Option<axum::Extension<InjectWriter>>,
    ),
    body: Result<Json<CreateBody>, JsonRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if caller_is_cli_key(
        generation.auth(),
        guard
            .client
            .as_ref()
            .and_then(|client| client.quota_principal.as_ref()),
        session.as_ref().map(|Extension(SessionMintedBy(key))| key),
    ) {
        return super::guard::Refused::Forbidden.into_response();
    }
    let Ok(Json(mut body)) = body else {
        return invalid_body();
    };
    // gateway.yaml stores whole seconds: check the instant that will be
    // written, so a sub-second expiry is never stored already past.
    body.expires_at = body
        .expires_at
        .map(|at| chrono::SubsecRound::trunc_subsecs(at, 0));
    let checked = match preconditions(&state, &body).await {
        Ok(checked) => checked,
        Err(refused) => return *refused,
    };
    // A name the key's own routes could not address, or one holding a
    // control character: the one shared rule says so, before the loader is
    // asked about anything (the loader itself keeps accepting such a name).
    if let Some(message) = crate::config::name_refusal("API key name", &body.name) {
        return structured_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "name_not_addressable",
            message,
        )
        .into_response();
    }
    if let Some(field) = refused_field(&body) {
        return invalid_field(field);
    }
    if let Err(refused) = expired_by(body.expires_at) {
        return *refused;
    }
    let secret = crate::random_secret::random_secret("mcpgw_");
    #[cfg(test)]
    let secret = known.map_or(secret, |axum::Extension(k)| k.0);
    let digest = crate::config::api_key_digest_spec(secret.as_bytes());
    let name = body.name.clone();
    let entry = NewKeyEntry::of(body, digest.clone());
    let outcome = Outcome::default();
    let judge = Judge {
        live: Arc::clone(&state.live_config),
        env: Arc::clone(checked.context.live_env()),
        file: checked.config,
        outcome: Arc::clone(&outcome),
    };
    // Every create offers to hold: the writer's own question on the file
    // with the key decides, never this route.
    let replace = Replace {
        expected: Expected::Revision(checked.revision),
        compute: Box::new(compute(entry, judge)),
        replaced: Replaced::Discard,
        secrets: None,
        status_change: StatusChange::HoldForRestart,
    };
    #[cfg(test)]
    if let Some(axum::Extension(hook)) = &before_lock {
        (hook.0)();
    }
    #[cfg(test)]
    let written = match &inject {
        Some(axum::Extension(injected)) => (injected.0)(),
        None => write_audited(&state, &guard, (&name, checked.context), replace).await,
    };
    #[cfg(not(test))]
    let written = write_audited(&state, &guard, (&name, checked.context), replace).await;
    let Decided {
        refusal,
        held: holds,
    } = std::mem::take(
        &mut *outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    match written {
        Ok(ReplaceOutcome {
            revision: Some(revision),
            reload: ReplaceReload::Applied(_),
            ..
        }) if landed(&state, &name, &digest) => created(&name, &secret, &revision),
        // Written for the next start: the live table is the one from before,
        // so `landed` cannot apply.
        Ok(ReplaceOutcome {
            revision: Some(revision),
            reload: ReplaceReload::HeldForRestart { .. },
            ..
        }) => held(&name, &secret, &revision),
        Err(ReplaceError::Unconfirmed { .. }) if refusal.is_none() && holds => {
            tracing::warn!(
                variant = "unconfirmed",
                "key create: the held write could not be recorded"
            );
            held_unconfirmed()
        }
        other => refused_write(&state, refusal, other),
    }
}
