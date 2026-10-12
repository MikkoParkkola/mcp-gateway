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
    /// A backend-level signed-assertion `identity_propagation` block: minted
    /// per caller, never by the sole-operator assertion.
    Propagation,
}

/// A compiled and installed gateway serving `BACKEND`.
pub(crate) struct DirectAccountGateway {
    meta: Option<MetaMcp>,
    backends: Arc<BackendRegistry>,
    dispatches: Arc<Dispatches>,
    /// Kept alive: its store directory lives as long as the gateway.
    custody: Custody,
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
            Binding::Unconnected | Binding::Connected => Bind::Account(WORK),
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
        let first = match binding {
            Binding::Unconnected | Binding::Connected => Bind::Account(WORK),
            Binding::Propagation => Bind::Propagation(external_cfg()),
        };
        let other = match second {
            Second::PersonalAccount => (PERSONAL_BACKEND, Bind::Account(PERSONAL)),
            Second::External => (EXTERNAL_BACKEND, Bind::Propagation(external_cfg())),
        };
        Self::build((ServeMode::Http, auth), binding, &[(BACKEND, first), other], |_| {})
    }

    fn build(
        (mode, auth): (ServeMode, crate::config::AuthConfig),
        binding: &Binding,
        binds: &[(&str, Bind<'_>)],
        configure: impl Fn(&mut crate::config::BackendConfig),
    ) -> Self {
        let operator_grant = matches!(binding, Binding::Connected);
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
                    let key = operator_key_for(id);
                    let slot = expected_identity_key_for(&key, SEEDED_REVISION);
                    ((key, grant(operator_token(id), u64::MAX)), slot)
                })
                .unzip()
        } else {
            (Vec::new(), Vec::new())
        };
        let custody = custody_with(&seed);
        let descriptors: Vec<&str> = if accounts.is_empty() { vec![WORK] } else { accounts };
        let (meta, dispatches) = gateway_in_with(
            binds,
            &Descriptors::same(&descriptors),
            &custody.installed(),
            &slots,
            (mode, auth),
            configure,
        );
        Self {
            backends: Arc::clone(&meta.backends),
            meta: Some(meta),
            dispatches,
            custody,
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

    /// Requests that reached the fixture's capturing transport.
    pub(crate) fn dispatched(&self) -> usize {
        self.dispatches.count()
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

    /// The `tools/call` requests that reached the backend, each as its
    /// `Authorization` header and the identity key that selected its slot.
    pub(crate) fn tool_calls(&self) -> Vec<(Option<String>, Option<String>)> {
        self.dispatches
            .calls()
            .into_iter()
            .map(|call| (call.authorization(), call.identity_key))
            .collect()
    }

    /// Every request that reached the backend, as its method, `Authorization`
    /// header and slot identity key (#2231: listings, not only `tools/call`).
    pub(crate) fn requests(&self) -> Vec<(String, Option<String>, Option<String>)> {
        self.dispatches
            .all()
            .into_iter()
            .map(|call| (call.method.clone(), call.authorization(), call.identity_key))
            .collect()
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

    /// The `tools/call` requests sent to `backend`.
    pub(crate) fn tool_calls_to(&self, backend: &str) -> usize {
        self.dispatches
            .calls()
            .iter()
            .filter(|call| call.server == backend)
            .count()
    }

    /// Fail the next non-`tools/list` request with the HTTP `status` the
    /// transport would report, with every account left live (MIK-8406 P8i).
    pub(crate) fn fail_next(&self, status: u16) {
        self.dispatches.answer_with(&[status]);
    }

    /// Answer the next non-`tools/list` request with `result`.
    pub(crate) fn answer_next(&self, result: serde_json::Value) {
        self.dispatches.script(&[Answer::Result(result)]);
    }

    /// Answer the next requests, `tools/list` included, with these HTTP
    /// statuses (MIK-8356 C9: a cold slot's first list gets a 401).
    pub(crate) fn answer_lists_with(&self, statuses: &[u16]) {
        self.dispatches.script_lists();
        self.dispatches.answer_with(statuses);
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
                }),
            );
    }

    /// Make every custody read fail as busy, or recover (MIK-8392 U1, C6).
    pub(crate) fn fail_custody_for_test(&self, failing: bool) {
        self.custody.fail_reads(failing);
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
fn operator_key_for(id: &str) -> AccountKey {
    crate::personal_accounts::identity::account_key(
        Some(crate::personal_accounts::identity::Principal::SoleOperator),
        &key_descriptor(id),
    )
    .expect("fixture principal and descriptor must bind")
}

/// The access token the sole operator's seeded grant on `id` carries.
fn operator_token(id: &str) -> &'static str {
    if id == PERSONAL { ALICE_PERSONAL_TOKEN } else { ALICE_WORK_TOKEN }
}

/// MIK-8392 T11, U2: a REST capability whose dispatch runs under alice's
/// account `WORK` (`auth.account`), served by a loopback capture endpoint,
/// for the router's stored-read rows. Real custody, the production installer.
pub(crate) struct CapabilityAccount {
    custody: Custody,
    port: u16,
    log: Arc<crate::security::TransparencyLogger>,
    external: bool,
    _log_dir: tempfile::TempDir,
}

/// The capability server and tool [`CapabilityAccount`] serves.
pub(crate) const CAPABILITY_SERVER: &str = super::super::account_rest_fixture::CAPABILITIES;
pub(crate) const CAPABILITY_TOOL: &str = super::super::account_rest_fixture::TOOL;

impl CapabilityAccount {
    /// Alice's grant seeded; `external` makes `WORK` an external descriptor
    /// (no vault, so its view is unjudged).
    pub(crate) async fn start(external: bool) -> Self {
        let (port, _captured) = super::super::account_rest_fixture::capture_endpoint().await;
        let custody = custody_with(&[(
            account_key("alice", WORK),
            grant(ALICE_WORK_TOKEN, u64::MAX),
        )]);
        let dir = tempfile::tempdir().expect("a log directory");
        let log = crate::gateway::meta_mcp::grant_audit_fixture::logger(
            &dir,
            crate::security::audit::AuditFailurePolicy::BestEffort,
        );
        Self {
            custody,
            port,
            log,
            external,
            _log_dir: dir,
        }
    }

    /// The caller the grant belongs to.
    pub(crate) fn alice() -> VerifiedIdentity {
        identity("alice")
    }

    /// Install the account and the capability on `meta`.
    pub(crate) fn install(&self, mut meta: MetaMcp) -> MetaMcp {
        use super::super::account_rest_fixture::{capability, external, managed, rest_config};
        meta.enable_transparency_log(Arc::clone(&self.log));
        let descriptor = if self.external {
            external(WORK)
        } else {
            managed(WORK)
        };
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        install_account_strategies(
            &rest_config(&[(WORK, descriptor)]),
            Some(&self.custody.installed()),
            &key,
            &meta,
            ServeMode::Http,
        )
        .expect("the installer accepts the fixture");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("an HTTP client");
        let executor = Arc::new(
            crate::capability::CapabilityExecutor::new()
                .with_account_strategies(meta.account_strategies())
                .with_test_http_client(client),
        );
        let backend = Arc::new(crate::capability::CapabilityBackend::new(
            CAPABILITY_SERVER,
            executor,
        ));
        backend
            .register_capability(capability(
                &format!("http://127.0.0.1:{}", self.port),
                "oauth:google",
                Some(WORK),
            ))
            .expect("the capability registers");
        meta.set_capabilities(backend);
        meta
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
