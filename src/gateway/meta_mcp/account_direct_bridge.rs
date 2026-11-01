// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The managed-account gateway, handed to the direct-route tests (#2190).
//!
//! Those tests live in `router`, where this fixture's `pub(super)` items are
//! out of reach. This is their one door, and it exposes only owned values and
//! counts, so none of the fixture's types leak out through a signature. The
//! gateway itself is [`gateway_in`], unchanged: production compilation,
//! production install, real custody.

use super::*;

/// The backend every direct-route case calls.
pub(crate) const BACKEND: &str = "work-mail";

/// The access token of the sole operator's seeded grant.
pub(crate) const OPERATOR_TOKEN: &str = ALICE_WORK_TOKEN;

/// The second managed backend [`DirectAccountGateway::with_second`] adds,
/// bound to the `personal-gmail` account (MIK-8406 two-account rows).
pub(crate) const PERSONAL_BACKEND: &str = "personal-mail";

/// The second backend as an external (signed-assertion) propagation target:
/// it has no mint-free account view (MIK-8392 `Unjudged`).
pub(crate) const EXTERNAL_BACKEND: &str = "partner";

/// The backend [`DirectAccountGateway::with_second`] adds beside `BACKEND`.
#[derive(Clone, Copy)]
pub(crate) enum Second {
    /// [`PERSONAL_BACKEND`], a managed account.
    PersonalAccount,
    /// [`EXTERNAL_BACKEND`], external propagation.
    External,
}

/// How `BACKEND` is configured.
pub(crate) enum Binding {
    /// `account: work-gmail`, a managed account, with empty custody.
    Unconnected,
    /// [`Self::Unconnected`] with a connected grant for the sole operator.
    Connected,
    /// [`Self::Unconnected`] with a connected grant for the verified OIDC
    /// subject named, for a gateway with more than one credential, where no
    /// sole operator exists (MIK-8387 S7a-acct: two scoped keys, one person).
    ConnectedFor(&'static str),
    /// A backend-level signed-assertion `identity_propagation` block: minted
    /// per caller, never by the sole-operator assertion.
    Propagation,
}

/// A compiled and installed gateway serving `BACKEND`.
pub(crate) struct DirectAccountGateway {
    meta: Option<MetaMcp>,
    pub(super) backends: Arc<BackendRegistry>,
    pub(super) dispatches: Arc<Dispatches>,
    /// Kept alive: its store directory lives as long as the gateway.
    custody: Custody,
    /// The Meta-MCP's audit log. It outlives `take_meta`'s hand-off: hold this
    /// gateway until the router state it fed is dropped.
    _log: crate::security::transparency_log::temp::TempLog,
}

impl DirectAccountGateway {
    /// Served over HTTP under `auth`. A seeded grant's per-user slot is
    /// seeded too, so a dispatch under it stays in process.
    pub(crate) fn new(auth: crate::config::AuthConfig, binding: &Binding) -> Self {
        Self::new_in(ServeMode::Http, auth, binding)
    }

    /// [`Self::new`] for a chosen transport; stdio catalogue tests (#2231).
    pub(crate) fn new_in(
        mode: ServeMode,
        auth: crate::config::AuthConfig,
        binding: &Binding,
    ) -> Self {
        Self::new_with(mode, auth, binding, None)
    }

    /// [`Self::new_in`], with `BACKEND`'s argument-key enforcement set when
    /// `enforcement` names one (MIK-8356 C10 runs the stdio twin at Off).
    pub(crate) fn new_with(
        mode: ServeMode,
        auth: crate::config::AuthConfig,
        binding: &Binding,
        enforcement: Option<crate::config::InputSchemaEnforcement>,
    ) -> Self {
        Self::new_configured(mode, auth, binding, move |config| {
            if let Some(mode) = enforcement {
                config.input_schema_enforcement = mode;
            }
        })
    }

    /// [`Self::new_in`], with `configure` applied to `BACKEND`'s config (the
    /// MIK-8356 X1 stdio row makes it a `passthrough` backend).
    pub(crate) fn new_configured(
        mode: ServeMode,
        auth: crate::config::AuthConfig,
        binding: &Binding,
        configure: impl Fn(&mut crate::config::BackendConfig),
    ) -> Self {
        let bind = match binding {
            Binding::Unconnected | Binding::Connected | Binding::ConnectedFor(_) => {
                Bind::Account(WORK)
            }
            Binding::Propagation => Bind::Propagation(external_cfg()),
        };
        Self::build((mode, auth), binding, &[(BACKEND, bind)], configure)
    }

    /// `BACKEND` (`account: work-gmail`) plus one `second` backend, over HTTP.
    /// Under [`Binding::Connected`] the sole operator holds a live grant on
    /// every managed account the gateway serves, each with its slot seeded.
    pub(crate) fn with_second(
        auth: crate::config::AuthConfig,
        binding: &Binding,
        second: Second,
    ) -> Self {
        Self::with_second_configured(auth, binding, second, |_| {})
    }

    /// [`Self::with_second`], with `configure` applied to both backends'
    /// config (a fill bound past the listing's deadline cap).
    pub(crate) fn with_second_configured(
        auth: crate::config::AuthConfig,
        binding: &Binding,
        second: Second,
        configure: impl Fn(&mut crate::config::BackendConfig),
    ) -> Self {
        let first = match binding {
            Binding::Unconnected | Binding::Connected | Binding::ConnectedFor(_) => {
                Bind::Account(WORK)
            }
            Binding::Propagation => Bind::Propagation(external_cfg()),
        };
        let other = match second {
            Second::PersonalAccount => (PERSONAL_BACKEND, Bind::Account(PERSONAL)),
            Second::External => (EXTERNAL_BACKEND, Bind::Propagation(external_cfg())),
        };
        Self::build(
            (ServeMode::Http, auth),
            binding,
            &[(BACKEND, first), other],
            configure,
        )
    }

    fn build(
        (mode, auth): (ServeMode, crate::config::AuthConfig),
        binding: &Binding,
        binds: &[(&str, Bind<'_>)],
        configure: impl Fn(&mut crate::config::BackendConfig),
    ) -> Self {
        let operator_grant = matches!(binding, Binding::Connected | Binding::ConnectedFor(_));
        let accounts: Vec<&str> = binds
            .iter()
            .filter_map(|(_, bind)| match bind {
                Bind::Account(id) => Some(*id),
                Bind::Propagation(_) => None,
            })
            .collect();
        let (seed, slots) = if operator_grant {
            accounts
                .iter()
                .map(|id| {
                    let key = match binding {
                        Binding::ConnectedFor(subject) => account_key(subject, id),
                        _ => operator_key_for(id),
                    };
                    let slot = expected_identity_key_for(&key, SEEDED_REVISION);
                    ((key, grant(operator_token(id), u64::MAX)), slot)
                })
                .unzip()
        } else {
            (Vec::new(), Vec::new())
        };
        let custody = custody_with(&seed);
        let descriptors: Vec<&str> = if accounts.is_empty() {
            vec![WORK]
        } else {
            accounts
        };
        let (log, meta, dispatches) = gateway_in_with(
            binds,
            &Descriptors::same(&descriptors),
            &custody.installed(),
            &slots,
            (mode, auth),
            configure,
        );
        Self {
            backends: Arc::clone(meta.backends.for_test()),
            meta: Some(meta),
            dispatches,
            custody,
            _log: log,
        }
    }

    /// The Meta-MCP to install in the router state. Once only.
    pub(crate) fn take_meta(&mut self) -> MetaMcp {
        self.meta.take().expect("the Meta-MCP is taken once")
    }

    /// The registry the Meta-MCP resolves against, which the direct route
    /// must look `BACKEND` up in too.
    pub(crate) fn backends(&self) -> Arc<BackendRegistry> {
        Arc::clone(&self.backends)
    }

    /// Revoke the sole operator's grant through live custody, with no
    /// reconnect (MIK-8392 rows).
    pub(crate) async fn revoke_operator_grant_for_test(&self) {
        self.custody
            .handle
            .invalidate(&operator_key())
            .await
            .expect("the seeded grant must revoke through real custody");
    }

    /// Revoke the sole operator's grant on ONE managed backend's account; any
    /// other account keeps its live grant.
    pub(crate) async fn revoke_operator_grant_on(&self, backend: &str) {
        let id = match backend {
            BACKEND => WORK,
            PERSONAL_BACKEND => PERSONAL,
            other => panic!("{other} is not a managed backend of this fixture"),
        };
        self.custody
            .handle
            .invalidate(&operator_key_for(id))
            .await
            .expect("the seeded grant must revoke through real custody");
    }

    /// Forced refreshes custody ran: one per `after_upstream_401`.
    pub(crate) fn refreshes(&self) -> usize {
        self.custody.refreshes()
    }

    /// Custody reads (`resolve`): one per mint-free view read or resolution
    /// (MIK-8392 O3, E5).
    pub(crate) fn resolves(&self) -> usize {
        self.custody.resolves()
    }

    /// Reconnect the operator's grant after [`Self::revoke_operator_grant`],
    /// as a completed connect journey publishes it (MIK-8392 L5).
    pub(crate) async fn reconnect_operator_grant_for_test(&self) {
        let current = grant(ALICE_WORK_TOKEN, u64::MAX);
        let expectation = ConsentExpectation::Revoked(GrantVersion {
            generation: current.generation.clone(),
            token_revision: current.token_revision,
            authorization_epoch: current.authorization_epoch,
            descriptor_revision: current.descriptor_revision.clone(),
        });
        let mut next = grant(ALICE_WORK_TOKEN, u64::MAX);
        next.generation = RECONNECT_GENERATION.to_string();
        self.custody
            .handle
            .commit_grant_if(&operator_key(), &expectation, &next)
            .await
            .expect("the reconnected grant must be published through live custody");
    }

    /// Re-attach the operator's per-user upstream after a real eviction
    /// dropped its slot, as a gateway reconnects it (MIK-8392 C6; reconnect
    /// from config itself is MIK-8417).
    pub(crate) fn rearm_operator_slot_for_test(&self) {
        self.rearm_operator_slot_at_for_test(&Self::operator_binding());
    }

    /// [`Self::rearm_operator_slot_for_test`] for the slot `binding` selects
    /// (a reconnected grant selects a new one).
    pub(crate) fn rearm_operator_slot_at_for_test(&self, binding: &str) {
        self.backends
            .get(BACKEND)
            .expect("the backend")
            .set_pooled_transport_for_test(
                &PoolKey::PerUser {
                    binding: binding.to_string(),
                },
                Arc::new(CapturingTransport {
                    dispatches: Arc::clone(&self.dispatches),
                    server: BACKEND.to_string(),
                }),
            );
    }

    /// Make every custody read fail as busy, or recover (MIK-8392 U1, C6).
    pub(crate) fn fail_custody_for_test(&self, failing: bool) {
        self.custody.fail_reads(failing);
    }

    /// Allow `allowed` further custody reads, then fail busy (G1a).
    pub(crate) fn fail_custody_after_for_test(&self, allowed: usize) {
        self.custody.fail_after(allowed);
    }

    /// Make only the mint's release step answer `Busy`: the account still
    /// reads live, so a cold view is claimed and its credential lookup fails.
    pub(crate) fn fail_release_for_test(&self) {
        self.custody.busy_at(super::BusyStep::Release);
    }

    /// Credential releases custody made: one per `prepare` (MIK-8356 F5: a
    /// refused call resolves nothing).
    pub(crate) fn releases(&self) -> usize {
        self.custody.releases()
    }

    /// Revoke the sole operator's seeded grant and reconnect it under a new
    /// generation, through live custody (MIK-8356: the old slot stays warm and
    /// indexed, but no longer belongs to the current grant).
    pub(crate) async fn rotate_operator_grant(&self) {
        revoke_and_reconnect(
            &self.custody,
            &operator_key(),
            &grant(ALICE_WORK_TOKEN, u64::MAX),
            ROTATED_TOKEN,
        )
        .await;
    }

    /// Revoke the sole operator's seeded grant through live custody, with no
    /// reconnect: the operator keeps its principal but has no current grant,
    /// so it has no view of the backend (MIK-8356 R3.7).
    pub(crate) async fn revoke_operator_grant(&self) {
        self.custody
            .handle
            .invalidate(&operator_key())
            .await
            .expect("the seeded grant must revoke through real custody");
    }

    /// The per-user slot the sole operator's seeded grant selects.
    pub(crate) fn operator_binding() -> String {
        expected_identity_key_for(&operator_key(), SEEDED_REVISION)
    }

    /// The verified identity [`Binding::ConnectedFor`]`(subject)`'s grant is
    /// held by, as a request extension would carry it.
    pub(crate) fn verified(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
        identity(subject)
    }

    /// The audit subject the sole operator is recorded under.
    pub(crate) fn operator_subject() -> String {
        crate::personal_accounts::identity::Principal::SoleOperator.stable_actor_id()
    }
}

/// The sole operator's key for [`WORK`], built the way custody builds it.
pub(super) fn operator_key() -> AccountKey {
    operator_key_for(WORK)
}

/// The sole operator's key for account `id`.
pub(super) fn operator_key_for(id: &str) -> AccountKey {
    crate::personal_accounts::identity::account_key(
        Some(crate::personal_accounts::identity::Principal::SoleOperator),
        &key_descriptor(id),
    )
    .expect("fixture principal and descriptor must bind")
}

/// The access token the sole operator's seeded grant on `id` carries.
fn operator_token(id: &str) -> &'static str {
    if id == PERSONAL {
        ALICE_PERSONAL_TOKEN
    } else {
        ALICE_WORK_TOKEN
    }
}

/// MIK-8392 T11, U2: a REST capability whose dispatch runs under alice's
/// account `WORK` (`auth.account`), served by a loopback capture endpoint,
/// for the router's stored-read rows. Real custody, the production installer.
pub(crate) struct CapabilityAccount {
    pub(super) custody: Custody,
    pub(super) port: u16,
    /// What the loopback capture peer received (#3892: a served call is
    /// proved by the peer seeing it, not by an outer "completed").
    captured: Arc<super::super::account_rest_fixture::Captured>,
    log: Arc<crate::security::TransparencyLogger>,
    kind: AccountKind,
    personal: bool,
    log_dir: tempfile::TempDir,
    /// Test-only (MIK-8428 Case A): see [`ReleaseBudget`].
    release_budget: Arc<Mutex<Option<usize>>>,
    /// MIK-8407: `PERSONAL` is installed too, for a capability re-bind.
    pub(super) second: bool,
}

/// What the capability's account reference names (MIK-8451).
#[derive(Clone, Copy, PartialEq, Eq)]
enum AccountKind {
    /// `WORK`, a managed descriptor: the vault mints per caller.
    Managed,
    /// `WORK`, an external descriptor (no vault, so its view is unjudged).
    External,
    /// `WORK`, a `shared` descriptor: the gateway's static credential, no
    /// per-caller binding.
    Shared,
    /// [`GHOST`], which no descriptor declares, registered with no registry
    /// to check it against.
    Undeclared,
}

/// An account id no fixture descriptor declares (MIK-8451).
pub(crate) const GHOST: &str = "ghost";

/// The capability server and tool [`CapabilityAccount`] serves.
pub(crate) const CAPABILITY_SERVER: &str = super::super::account_rest_fixture::CAPABILITIES;
pub(crate) const CAPABILITY_TOOL: &str = super::super::account_rest_fixture::TOOL;

impl CapabilityAccount {
    /// Alice's grant seeded; `external` makes `WORK` an external descriptor
    /// (no vault, so its view is unjudged).
    pub(crate) async fn start(external: bool) -> Self {
        Self::start_expiring(external, u64::MAX, &[]).await
    }

    /// As [`Self::start`] (managed), with the capture peer answering its
    /// first requests with `statuses` (MIK-8428 SETTLE.4: an error after the
    /// send).
    pub(crate) async fn start_answering(statuses: &[u16]) -> Self {
        Self::start_expiring(false, u64::MAX, statuses).await
    }

    /// Alice's grant seeded already expired, so every mint refreshes it with
    /// the scripted provider before the release (#3892 R7).
    pub(crate) async fn start_expired() -> Self {
        Self::start_expiring(false, 1, &[]).await
    }

    async fn start_expiring(external: bool, expires_at: u64, statuses: &[u16]) -> Self {
        let (port, captured) =
            super::super::account_rest_fixture::capture_endpoint_answering(statuses).await;
        let custody = custody_with(&[(
            account_key("alice", WORK),
            grant(ALICE_WORK_TOKEN, expires_at),
        )]);
        let dir = tempfile::tempdir().expect("a log directory");
        let log = crate::gateway::meta_mcp::grant_audit_fixture::logger(
            &dir,
            crate::security::audit::AuditFailurePolicy::BestEffort,
        );
        Self {
            custody,
            port,
            captured,
            log,
            kind: if external {
                AccountKind::External
            } else {
                AccountKind::Managed
            },
            personal: false,
            log_dir: dir,
            release_budget: Arc::new(Mutex::new(None)),
            second: false,
        }
    }

    /// As [`Self::start`] (managed), but the capability is Personal owned by
    /// alice, so identity grants decide it (the order twin that withdraws the
    /// grant as well as revoking the account).
    pub(crate) async fn start_personal() -> Self {
        let mut account = Self::start(false).await;
        account.personal = true;
        account
    }

    /// As [`Self::start`], with `WORK` a `shared` descriptor: it resolves
    /// to the static credential, with no per-caller binding (MIK-8406).
    pub(crate) async fn start_shared() -> Self {
        let mut account = Self::start(false).await;
        account.kind = AccountKind::Shared;
        account
    }

    /// As [`Self::start`], with the capability naming [`GHOST`], an account
    /// no descriptor declares. Its executor carries no registry, so
    /// registration has nothing to check the reference against
    /// (`execution_context.rs` returns `Ok` with no registry) and only the
    /// dispatch can refuse it (MIK-8451).
    pub(crate) async fn start_undeclared() -> Self {
        let mut account = Self::start(false).await;
        account.kind = AccountKind::Undeclared;
        account
    }

    /// The caller the grant belongs to.
    pub(crate) fn alice() -> VerifiedIdentity {
        identity("alice")
    }

    /// The identity grant that lets alice reach the personal capability.
    pub(crate) fn alice_grant() -> crate::identity_grants::IdentityGrant {
        serde_json::from_value(serde_json::json!({
            "grant_id": "g-alice",
            "subject": { "authority": INBOUND_ISSUER, "subject": "alice" },
            "agent": "any",
            "capability": super::super::account_rest_fixture::TOOL,
            "scope": "read",
            "owner": { "authority": INBOUND_ISSUER, "subject": "alice" },
            "provenance": "local-operator",
            "reason": "order-twin fixture grant"
        }))
        .expect("the fixture grant deserialises")
    }

    /// Install the account and the capability on `meta`.
    pub(crate) fn install(&self, mut meta: MetaMcp) -> MetaMcp {
        use super::super::account_rest_fixture::{
            capability, external, managed, rest_config, shared,
        };
        meta.enable_transparency_log(Arc::clone(&self.log));
        let descriptor = match self.kind {
            AccountKind::Shared => shared(WORK),
            AccountKind::External => external(WORK),
            AccountKind::Managed | AccountKind::Undeclared => managed(WORK),
        };
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        let custody: Arc<dyn AccountCustody> = Arc::new(ReleaseBudget {
            inner: self.custody.installed(),
            allowed: Arc::clone(&self.release_budget),
        });
        let mut descriptors = vec![(WORK, descriptor)];
        if self.second {
            descriptors.push((
                PERSONAL,
                super::super::account_rest_fixture::managed(PERSONAL),
            ));
        }
        install_account_strategies(
            &rest_config(&descriptors),
            Some(&custody),
            &key,
            &meta,
            ServeMode::Http,
        )
        .expect("the installer accepts the fixture");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("an HTTP client");
        let executor = crate::capability::CapabilityExecutor::new();
        let executor = if self.kind == AccountKind::Undeclared {
            executor
        } else {
            executor.with_account_strategies(meta.account_strategies())
        };
        let executor = Arc::new(
            executor
                .with_test_http_client(client)
                // The meta dispatch opens no loopback egress, and the capture
                // peer is loopback (#3892 healthy controls).
                .with_test_loopback_egress(),
        );
        if self.kind == AccountKind::Shared {
            // A shared account dispatches under the gateway's own static
            // OAuth token, so the fixture seeds one.
            let token =
                serde_json::from_value(serde_json::json!({"access_token": "shared-static"}))
                    .expect("a static token");
            executor.set_oauth_token("google", token);
        }
        let backend = Arc::new(crate::capability::CapabilityBackend::new(
            CAPABILITY_SERVER,
            executor,
        ));
        let definition = if self.personal {
            personal_capability(
                &format!("http://127.0.0.1:{}", self.port),
                "oauth:google",
                WORK,
            )
        } else {
            capability(
                &format!("http://127.0.0.1:{}", self.port),
                "oauth:google",
                Some(if self.kind == AccountKind::Undeclared {
                    GHOST
                } else {
                    WORK
                }),
            )
        };
        backend
            .register_capability(definition)
            .expect("the capability registers");
        meta.set_capabilities(backend);
        meta
    }

    /// Make every custody read fail as busy, or recover (seat finding 3).
    /// Either way the release budget is lifted.
    pub(crate) fn fail_custody_for_test(&self, failing: bool) {
        self.custody.fail_reads(failing);
        *self.release_budget.lock() = None;
    }

    /// Let `allowed` further custody releases pass, then answer every later
    /// one `Busy` (MIK-8428 Case A): see [`ReleaseBudget`].
    pub(crate) fn fail_releases_after_for_test(&self, allowed: usize) {
        *self.release_budget.lock() = Some(allowed);
    }

    /// Custody releases that passed the real lease check.
    pub(crate) fn releases(&self) -> usize {
        self.custody.releases()
    }

    /// Provider refreshes custody has made since this fixture started.
    pub(crate) fn refreshes(&self) -> usize {
        self.custody.refreshes()
    }

    /// Requests the capture peer has received.
    pub(crate) fn peer_requests(&self) -> usize {
        self.captured.count()
    }

    /// Custody lookups since this fixture started.
    pub(crate) fn resolves(&self) -> usize {
        self.custody.resolves()
    }

    /// Allow `allowed` further custody reads, then fail busy
    /// (#3892 R6 test seam: intake view fine, worker mint busy).
    pub(crate) fn fail_custody_after_for_test(&self, allowed: usize) {
        self.custody.fail_after(allowed);
    }

    /// Make only the mint's refresh step answer `Busy` (#3892 R8).
    pub(crate) fn fail_refresh_for_test(&self) {
        self.custody.busy_at(super::BusyStep::Refresh);
    }

    /// Make only the mint's release step answer `Busy` (#3892 R7).
    pub(crate) fn fail_release_for_test(&self) {
        self.custody.busy_at(super::BusyStep::Release);
    }

    /// The `idp_refuse` records in this fixture's transparency log.
    pub(crate) fn idp_refusals_for_test(&self) -> usize {
        self.idp_refusal_reasons_for_test().len()
    }

    /// The reasons of those records, in order (#3892 R1).
    pub(crate) fn idp_refusal_reasons_for_test(&self) -> Vec<String> {
        crate::gateway::meta_mcp::grant_audit_fixture::entries(&self.log_dir)
            .iter()
            .filter(|entry| entry["action"] == "idp_refuse")
            .map(|entry| entry["reason"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    /// Revoke alice's grant through live custody.
    pub(crate) async fn revoke(&self) {
        self.custody
            .handle
            .invalidate(&account_key("alice", WORK))
            .await
            .expect("the seeded grant revokes");
    }
}

/// The same account-bound REST capability as
/// [`account_rest_fixture::capability`](super::super::account_rest_fixture::capability),
/// but Personal owned by alice, so identity grants decide it.
fn personal_capability(
    base_url: &str,
    key: &str,
    account: &str,
) -> crate::capability::CapabilityDefinition {
    crate::capability::parse_capability(&format!(
        "name: {}\n\
         description: Read one folder through a personal account\n\
         metadata:\n\
         \x20 exposure: personal\n\
         \x20 read_only: true\n\
         \x20 identity_owner:\n\
         \x20   authority: {}\n\
         \x20   subject: alice\n\
         auth:\n\
         \x20 required: true\n\
         \x20 type: bearer\n\
         \x20 key: {key}\n\
         \x20 account: {account}\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /read\n\
         \x20     method: GET\n",
        super::super::account_rest_fixture::TOOL,
        INBOUND_ISSUER,
    ))
    .expect("fixture personal capability must parse")
}

/// Test-only (MIK-8428 Case A): lets `allowed` custody releases pass, then
/// answers every later release `Busy`. A capability call releases its lease
/// once at the mint and again at each of three rechecks before the send, so
/// `allowed = 1..=3` puts the `Busy` on one recheck, with nothing sent.
struct ReleaseBudget {
    inner: Arc<dyn AccountCustody>,
    allowed: Arc<Mutex<Option<usize>>>,
}

#[async_trait::async_trait]
impl AccountCustody for ReleaseBudget {
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError> {
        self.inner.resolve(account).await
    }

    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        self.inner.refresh_if_expired(account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        {
            let mut budget = self.allowed.lock();
            if let Some(left) = budget.as_mut() {
                if *left == 0 {
                    return Err(CustodyError::Busy);
                }
                *left -= 1;
            }
        }
        self.inner.release(lease).await
    }

    async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<crate::personal_accounts::RejectionOutcome, CustodyError> {
        self.inner.refresh_after_rejection(lease).await
    }
}

/// The error-rate cooldown refusal for `server`'s `tool`, as
/// `admit_enabled_capability` words it, without the `JSON-RPC error -32000: `
/// prefix the dispatch's rendering adds (the MIK-8439 rows).
pub(crate) fn cooldown_refusal(server: &str, tool: &str) -> String {
    format!(
        "Capability '{tool}' on server '{server}' is temporarily disabled due to a high error \
         rate. It will auto-recover after the cooldown period. Use \
         gateway_list_disabled_capabilities to see all disabled capabilities."
    )
}

#[path = "account_direct_bridge_traffic.rs"]
mod traffic;

#[cfg(test)]
#[path = "account_direct_bridge_fence_tests.rs"]
mod fence_tests;
