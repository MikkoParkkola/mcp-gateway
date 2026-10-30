// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct fixture's pieces for the MIK-8293 slot-cap rows: backends with
//! no rate limiter, and a propagating fixture (two backends that require
//! identity propagation to distinct audiences, with the audit sinks and HTTP
//! base URL a required propagation needs).

use std::sync::Arc;

use super::{Answer, Fx, MetaMcp, fixture};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::security::transparency_log::temp::TempLog;

/// A transparency log in `log`'s temp dir. The builder stores `log` on the
/// returned [`Fx`], so the log and its sidecars go when the fixture drops.
pub(super) fn transparency_log_in(log: &TempLog) -> Arc<crate::security::TransparencyLogger> {
    use crate::security::transparency_log::TransparencyLogConfig;
    let config = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log.path().to_string_lossy().to_string(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(crate::security::TransparencyLogger::open(config).expect("logger opens"))
}

/// A required propagation refuses to mint without a durable audit sink, so a
/// propagating fixture's route gets a log; the caller keeps it on the [`Fx`].
pub(super) fn propagating_route_log(
    state: &mut crate::gateway::router::AppState,
) -> Option<TempLog> {
    let log = super::PROPAGATING
        .with(std::cell::Cell::get)
        .then(TempLog::new)?;
    state.transparency_log = Some(transparency_log_in(&log));
    Some(log)
}

/// The fixture's backends with the per-backend rate limiter off: no row here
/// tests it (`probe_tests` does, on its own backend), and the slot-cap rows
/// (MIK-8293) send 65 calls in a burst.
pub(super) fn fixture_failsafe() -> FailsafeConfig {
    let mut failsafe = FailsafeConfig::default();
    failsafe.rate_limit.enabled = false;
    failsafe
}

/// [`fixture`] whose two backends require identity propagation to distinct
/// audiences; `arm` installs the strategy (MIK-8293 S3c).
pub(crate) async fn fixture_propagating(answer: Answer, arm: impl FnOnce(&mut MetaMcp)) -> Fx {
    super::PROPAGATING.with(|p| p.set(true));
    let log = TempLog::new();
    let logger = transparency_log_in(&log);
    let fx = fixture(answer, |meta| {
        // The meta layer checks for its own audit sink before a required mint.
        meta.enable_transparency_log(logger);
        arm(meta);
    })
    .await;
    let fx = Fx {
        _audit: Some(log),
        ..fx
    };
    super::PROPAGATING.with(|p| p.set(false));
    fx
}

/// [`fixture_firewalled_audited_built`] with a call budget of `calls` per window
/// on both firewalls (MIK-8362: a playbook's steps spend what a direct call spends).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_budget_built(
    answer: Answer,
    (audit, calls): (std::path::PathBuf, usize),
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    super::BUDGET.with(|b| b.set(calls));
    let fx = super::fixture_firewalled_audited_built(answer, audit, build).await;
    super::BUDGET.with(|b| b.set(0));
    fx
}

/// [`fixture_propagating`] with the production firewalls and a call budget of
/// `calls` per window, audit rows to `audit` (MIK-8362 STEPFW.3: a refusal at
/// the route mints nothing).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_propagating_budgeted(
    (audit, calls): (std::path::PathBuf, usize),
    arm: impl FnOnce(&mut MetaMcp),
) -> Fx {
    super::PROPAGATING.with(|p| p.set(true));
    let log = TempLog::new();
    let logger = transparency_log_in(&log);
    let fx = super::fixture_firewalled_budget_built(Answer::Ok, (audit, calls), |mut meta| {
        meta.enable_transparency_log(logger);
        arm(&mut meta);
        meta
    })
    .await;
    let fx = Fx {
        _audit: Some(log),
        ..fx
    };
    super::PROPAGATING.with(|p| p.set(false));
    fx
}

thread_local! {
    /// The `secrets:` rules every fixture backend carries; empty for none.
    static SECRETS: std::cell::RefCell<Vec<crate::secret_injection::CredentialRule>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// What the fixture backends talk to.
    static BACKENDS: std::cell::RefCell<Backends> = const { std::cell::RefCell::new(Backends::Scripted) };
}

/// What the two fixture backends talk to.
#[derive(Clone)]
pub(crate) enum Backends {
    /// The scripted in-process transport (every fixture but the echo rows).
    Scripted,
    /// A real HTTP MCP server at this URL: the transport parses the
    /// server's bytes, as the echo-redaction rows need (MIK-9035).
    #[cfg_attr(
        not(feature = "firewall"),
        expect(dead_code, reason = "built only by the firewall-gated echo rows")
    )]
    HttpServer(String),
}

/// What the fixture backends talk to now.
pub(super) fn backends() -> Backends {
    BACKENDS.with(|backends| backends.borrow().clone())
}

/// [`fixture_with_secrets`] whose two backends talk to the real HTTP MCP
/// server at `url`. Only a real server: an echo row must run over a
/// transport that parses and scrubs the backend's bytes, never a scripted
/// double that claims to redact (MIK-9035).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_with_secrets_over_http(
    rules: Vec<crate::secret_injection::CredentialRule>,
    url: String,
) -> Fx {
    BACKENDS.with(|held| *held.borrow_mut() = Backends::HttpServer(url));
    let fx = fixture_with_secrets(rules, None, None).await;
    BACKENDS.with(|held| *held.borrow_mut() = Backends::Scripted);
    fx
}

/// [`super::fixture`] whose two backends each carry `rules`, answering over
/// `transport` when one is given, and writing its firewall audit rows to
/// `audit` when one is given.
pub(crate) async fn fixture_with_secrets(
    rules: Vec<crate::secret_injection::CredentialRule>,
    transport: Option<Arc<dyn crate::transport::Transport>>,
    audit: Option<std::path::PathBuf>,
) -> Fx {
    SECRETS.with(|s| *s.borrow_mut() = rules);
    let fixture = Box::pin(async move {
        #[cfg(feature = "firewall")]
        if let Some(audit) = audit {
            return super::fixture_firewalled_audited(Answer::Ok, audit).await;
        }
        #[cfg(not(feature = "firewall"))]
        let _ = audit;
        super::fixture_built(Answer::Ok, |meta| meta).await
    });
    let fx = match transport {
        Some(transport) => super::with_transport(transport, fixture).await,
        None => fixture.await,
    };
    SECRETS.with(|s| s.borrow_mut().clear());
    fx
}

#[cfg(feature = "firewall")]
impl Fx {
    /// The directory the fixture's gateway writes its stores under.
    pub(crate) fn store_path(&self) -> &std::path::Path {
        let Self { _store: store, .. } = self;
        store.path()
    }
}

/// One fixture backend's config: pass-through or not, and, for a propagating
/// fixture, a required propagation to `aud-<name>` over an HTTP base URL.
pub(super) fn fixture_backend_config(name: &str, passthrough: bool) -> BackendConfig {
    BackendConfig {
        passthrough,
        secrets: SECRETS.with(|s| s.borrow().clone()),
        // A propagating backend validates an HTTP base URL before it
        // reaches the scripted transport.
        transport: if let Backends::HttpServer(http_url) = backends() {
            crate::config::TransportConfig::Http {
                http_url,
                streamable_http: Some(true),
                protocol_version: None,
            }
        } else if super::PROPAGATING.with(std::cell::Cell::get) {
            crate::config::TransportConfig::Http {
                http_url: format!("https://{name}.internal/mcp"),
                streamable_http: Some(true),
                protocol_version: None,
            }
        } else {
            BackendConfig::default().transport
        },
        identity_propagation: super::PROPAGATING.with(std::cell::Cell::get).then(|| {
            crate::identity_propagation::IdentityPropagationConfig {
                strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
                audience: format!("aud-{name}"),
                required: !super::OPTIONAL.with(std::cell::Cell::get),
                session_mode: crate::identity_propagation::SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }
        }),
        input_schema_enforcement: if super::SCHEMA_OFF.with(std::cell::Cell::get) {
            crate::config::InputSchemaEnforcement::Off
        } else {
            crate::config::InputSchemaEnforcement::default()
        },
        ..BackendConfig::default()
    }
}

/// A propagation strategy that counts every credential it mints. Mints are
/// never cached (`invoke/account_mint.rs`), so each propagated call mints once.
#[derive(Default)]
pub(crate) struct Minting(std::sync::atomic::AtomicUsize);

impl Minting {
    /// Credentials minted so far.
    pub(crate) fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Minting {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let binding = format!("{}@{}", identity.subject, backend.audience);
        Ok(crate::identity_propagation::PropagatedCredential {
            expiry_synthetic: false,
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: binding,
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// The hardened, signed (nonce required) fixture whose backends require
/// identity propagation, minting through a counting [`Minting`] strategy
/// (MIK-8353 slice 3a). `build` arms the signed `MetaMcp` further, e.g. with a
/// spend budget. Returns the fixture and the strategy, so a row reads mints.
pub(crate) async fn fixture_propagating_signed(
    answer: Answer,
    firewalled: bool,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> (Fx, Arc<Minting>) {
    let minting = Arc::new(Minting::default());
    let strategy = Arc::clone(&minting);
    super::HARDENED.with(|h| h.set(true));
    super::PROPAGATING.with(|p| p.set(true));
    let log = TempLog::new();
    let logger = transparency_log_in(&log);
    let fx = super::fixture_inner(answer, firewalled, |meta| {
        let mut meta = build(super::signing(meta, true));
        meta.enable_transparency_log(logger);
        meta.set_identity_propagation(strategy);
        meta
    })
    .await;
    let fx = Fx {
        _audit: Some(log),
        ..fx
    };
    super::PROPAGATING.with(|p| p.set(false));
    super::HARDENED.with(|h| h.set(false));
    (fx, minting)
}

/// A propagation strategy whose every mint fails after it was attempted, as a
/// token exchange that reached its issuer and errored (MIK-8379 H1); or, with
/// `bad_header`, succeeds with a header that does not parse, which the
/// resolver refuses the same way. Counts its attempts.
#[derive(Default)]
pub(crate) struct FailingMint {
    attempts: std::sync::atomic::AtomicUsize,
    bad_header: bool,
}

impl FailingMint {
    /// A mint that succeeds with an invalid header name.
    pub(crate) fn with_bad_header() -> Self {
        Self {
            attempts: std::sync::atomic::AtomicUsize::new(0),
            bad_header: true,
        }
    }

    /// Mints attempted so far.
    pub(crate) fn count(&self) -> usize {
        self.attempts.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for FailingMint {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.bad_header {
            return Ok(crate::identity_propagation::PropagatedCredential {
                expiry_synthetic: false,
                headers: vec![("bad header".to_string(), "minted".to_string())],
                expires_at: i64::MAX,
                cache_binding: format!("{}@{}", identity.subject, backend.audience),
                subject_key: identity.subject.clone(),
                audience: backend.audience.clone(),
                scopes: Vec::new(),
            });
        }
        Err(crate::identity_propagation::PropagationError::Refuse(
            "the issuer refused the exchange".to_string(),
        ))
    }
}

/// A named way for a [`FailingMint`] to fail.
pub(crate) type MintMode = (&'static str, fn() -> FailingMint);

/// Both failure modes the H1 rows run: a failed mint, and a mint whose header
/// does not parse.
pub(crate) const MINT_MODES: [MintMode; 2] = [
    ("failed mint", FailingMint::default),
    ("invalid header", FailingMint::with_bad_header),
];

/// The hardened, signed fixture whose backends declare OPTIONAL identity
/// propagation through a [`FailingMint`]: every propagated call attempts a
/// mint, fails, and falls back to the static credential (IDP.5). `build` arms
/// the signed `MetaMcp` further (a spend budget).
pub(crate) async fn fixture_optional_failing_mint(
    answer: Answer,
    mint: FailingMint,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> (Fx, Arc<FailingMint>) {
    let failing = Arc::new(mint);
    let strategy = Arc::clone(&failing);
    super::HARDENED.with(|h| h.set(true));
    super::PROPAGATING.with(|p| p.set(true));
    super::OPTIONAL.with(|o| o.set(true));
    let log = TempLog::new();
    let logger = transparency_log_in(&log);
    let fx = super::fixture_inner(answer, false, |meta| {
        let mut meta = build(super::signing(meta, true));
        meta.enable_transparency_log(logger);
        meta.set_identity_propagation(strategy);
        meta
    })
    .await;
    let fx = Fx {
        _audit: Some(log),
        ..fx
    };
    super::OPTIONAL.with(|o| o.set(false));
    super::PROPAGATING.with(|p| p.set(false));
    super::HARDENED.with(|h| h.set(false));
    (fx, failing)
}
