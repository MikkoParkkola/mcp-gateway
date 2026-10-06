// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Configuration validation (split from `mod.rs`).

use super::{
    BackendConfig, Config, EnvOverlay, Error, Result, SecretRef, TransportConfig, account_bindings,
    features, flagged_tools, log_once, remote_transport_identity, verify_remote_server_provenance,
};

impl Config {
    /// Validate the configuration for common misconfigurations.
    ///
    /// Checks performed:
    /// - No backend names are empty or contain invalid characters (`/`, `\`, `:`)
    /// - No duplicate backend names (guaranteed by `HashMap`, but checked for
    ///   completeness in case the config is reconstructed from another source)
    /// - Server port is within the valid range (1–65535; 0 means OS-assigned)
    /// - Backend URLs (for HTTP transports) are syntactically valid
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] describing the first violation found.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_env(&EnvOverlay::none())
    }

    /// As [`Config::validate`], resolving `env:` references through `overlay`.
    ///
    /// A separate entry point rather than a field on `Config`: validation runs against
    /// the environment the load produced, which is not part of the config it validates.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] describing the first violation found.
    pub fn validate_with_env(&self, overlay: &EnvOverlay) -> Result<()> {
        // Port 0 is valid (OS-assigned ephemeral port); u16 caps the top.
        log_once::warn_port_zero(self.server.port, &log_once::PORT_ZERO_WARNED);
        // First, so no other reader touches a plaintext key (E4).
        self.auth.validate_api_key_material(overlay)?;
        // The router caps every body at this (C8), so 0 would refuse all of them.
        if self.server.max_body_size == 0 {
            return Err(Error::ConfigValidation(
                "server.max_body_size is 0, which refuses every request body; \
                 set a positive byte count (default 10485760)"
                    .into(),
            ));
        }
        self.validate_backend_names()?;
        self.validate_backend_urls()?;
        self.validate_remote_backend_provenance()?;
        self.validate_required_env_references(overlay)?;
        self.runtime.validate()?;
        self.idempotency.validate()?;
        self.validate_backend_runtime_profiles()?;
        self.validate_stop_when_idle_ownership()?;
        self.validate_max_frame_bytes()?;
        self.webhooks.validate()?;
        self.control_plane.role_mapping.validate()?;
        self.validate_identity_propagation()?;
        flagged_tools::validate_flagged_tool_pins(&self.backends)?;
        self.validate_agent_key_material(overlay)?;
        self.auth.validate_api_key_names()?;
        self.auth.validate_distinct_principals(overlay)?;
        self.security.validate_sections(self.auth.enabled)?;
        self.security.message_signing.resolve_with_env(overlay)?;
        features::validate_backend_chains(self)?;
        self.validate_identity_sources()?;
        self.error_budget.validate()?;
        self.tasks.validate()?;
        self.events.validate()?;
        self.capabilities.egress_proxy_url()?;
        // Descriptor structure first, and separately: a `personal_managed`
        // descriptor under `enabled: false` must refuse, and the arm below
        // deliberately accepts `NotEnabled` from `resolve` so that an
        // explicitly disabled store-only block stays an ordinary
        // configuration. Checking structure here also means a malformed
        // descriptor never causes an account secret to be read.
        crate::personal_accounts::config::validate_descriptors(self.accounts.as_ref())
            .map_err(|error| Error::ConfigValidation(error.to_string()))?;
        // Structural half of the approved "no reuse with gateway authentication
        // secrets" rule: one variable wired into both an adapter and a gateway
        // credential is one secret whatever it holds, so this is decided from
        // the text and reads nothing, disabled store included.
        let gateway_credentials = self.gateway_credentials();
        crate::personal_accounts::config::validate_adapter_gateway_reference_separation(
            self.accounts.as_ref(),
            &gateway_credentials,
        )
        .map_err(|error| Error::ConfigValidation(error.to_string()))?;
        // Consumer side of the same contract: every `backends[*].account`
        // reference resolves to a declared descriptor key, and a managed
        // consumer carries no second answer to "how is this backend
        // authenticated". Compiling here means an unresolved or contradictory
        // reference is a load refusal rather than a dispatch-time discovery.
        account_bindings::validate(self)?;
        match crate::personal_accounts::config::resolve(self.accounts.as_ref(), overlay) {
            Ok(_) | Err(crate::personal_accounts::config::AccountsConfigError::NotEnabled) => {}
            Err(error) => return Err(Error::ConfigValidation(error.to_string())),
        }
        // Material half of the same rule, and only where material is resolved:
        // two differently NAMED variables holding one value, or a literal
        // gateway credential, are invisible to the reference check above.
        crate::personal_accounts::config::validate_adapter_gateway_material_separation(
            self.accounts.as_ref(),
            overlay,
            &gateway_credentials,
        )
        .map_err(|error| Error::ConfigValidation(error.to_string()))?;
        Ok(())
    }

    /// The gateway authentication credentials AS CONFIGURED, for the adapter
    /// separation checks.
    ///
    /// Borrowed spec text, never a resolved value: the `auto` bearer mints a
    /// fresh random token on every `resolve_bearer_token` call, so a resolved
    /// value would compare against a token nobody holds. Handing over the
    /// configured text lets the checks resolve through the overlay themselves
    /// and skip `auto` deliberately.
    pub(crate) fn gateway_credentials(
        &self,
    ) -> Vec<crate::personal_accounts::config::GatewayCredential<'_>> {
        use crate::personal_accounts::config::GatewayCredential;

        let mut credentials: Vec<GatewayCredential<'_>> = Vec::new();
        if let Some(token) = self.auth.bearer_token.as_deref() {
            credentials.push(GatewayCredential::BearerToken(token));
        }
        for (index, api_key) in self.auth.api_keys.iter().enumerate() {
            if let Some(spec) = api_key.key_sha256.as_deref() {
                credentials.push(GatewayCredential::ApiKeyDigest {
                    index,
                    name: api_key.name.as_str(),
                    spec,
                });
            }
        }
        credentials
    }

    /// Refuse to start when an enabled agent's key material cannot reject
    /// anybody (MIK-7258).
    ///
    /// `DecodingKey::from_secret(b"")` is a perfectly valid key, so an agent
    /// whose HS256 secret is empty verifies a token ANY caller can sign. The
    /// config reads as having agent authentication on while that agent
    /// authenticates the world. Nothing rejected it: the 32-byte figure existed
    /// only as advice in `gateway::oauth::jwt`'s module docs.
    ///
    /// Checked on the RESOLVED value, not the literal. An `env:` reference to a
    /// variable that exists and is empty passes every other check — existence
    /// is what `validate_required_env_references` asks, and it is not the
    /// question here.
    ///
    /// Every enabled agent, not merely one of them: a caller forges the WEAKEST
    /// agent's token and gets that agent's scopes, so one sound definition
    /// beside a forgeable one protects nothing.
    pub(super) fn validate_agent_key_material(&self, overlay: &EnvOverlay) -> Result<()> {
        /// Shortest HS256 secret accepted, in bytes. A shorter shared secret is
        /// brute-forceable rather than merely inadvisable, and this is the
        /// length this project's own guidance already asks for.
        const MIN_HS256_SECRET_BYTES: usize = 32;

        if !self.agent_auth.enabled {
            return Ok(());
        }
        for agent in &self.agent_auth.agents {
            let has_rsa = agent
                .rs256_public_key
                .as_deref()
                .is_some_and(|k| !k.trim().is_empty());
            let has_hs256 = agent.hs256_secret.is_some();
            // The algorithm comes from the TOKEN HEADER, so with both keys
            // configured the caller picks which one verifies its token and the
            // agent is only as strong as the weaker key. `AgentDefinition`
            // already documents "exactly one"; refusing is what enforces it.
            if has_rsa && has_hs256 {
                return Err(Error::ConfigValidation(format!(
                    "agent_auth.agents['{}'] sets both hs256_secret and \
                     rs256_public_key. The algorithm is read from the token, so \
                     a caller chooses which key verifies it and the agent is \
                     only as strong as the weaker one. Configure exactly one.",
                    agent.client_id
                )));
            }
            // Audience must be checked BEFORE the RSA early exit below, or an
            // audience-less RS256 agent would load and the startup refusal
            // would cover only HS256. Without a configured audience the
            // verifier cannot tell a token minted for this gateway from one
            // minted for any other relying party that shares the signing key.
            if agent
                .audience
                .as_deref()
                .is_none_or(|a| a.trim().is_empty())
            {
                return Err(Error::ConfigValidation(format!(
                    "agent_auth.agents['{}'] sets no audience. The signing key \
                     may be shared with other relying parties, so without an \
                     expected `aud` this agent accepts tokens minted for them. \
                     Set audience to the identifier this gateway is known by.",
                    agent.client_id
                )));
            }
            if has_rsa {
                continue;
            }
            let Some(raw) = agent.hs256_secret.as_deref() else {
                return Err(Error::ConfigValidation(format!(
                    "agent_auth.agents['{}'] has neither hs256_secret nor \
                     rs256_public_key, so it can verify nothing",
                    agent.client_id
                )));
            };
            let resolved = SecretRef::parse(raw).resolve(
                &format!("agent_auth.agents['{}'].hs256_secret", agent.client_id),
                overlay,
            )?;
            if resolved.len() < MIN_HS256_SECRET_BYTES {
                return Err(Error::ConfigValidation(format!(
                    "agent_auth.agents['{}'].hs256_secret resolves to {} bytes; \
                     at least {MIN_HS256_SECRET_BYTES} are required. A short or \
                     empty shared secret can be guessed or signed by anyone, so \
                     that agent would authenticate every caller.",
                    agent.client_id,
                    resolved.len()
                )));
            }
        }
        Ok(())
    }

    /// Validate per-backend identity-propagation config (MIK-6704 / ADR-007),
    /// failing closed at load so a misconfigured propagation backend never
    /// starts. Both `Stateless` and `PerUser` session modes are supported: the
    /// per-user transport pool (MIK-6735) gives each caller its own session, so
    /// `PerUser` no longer needs to be rejected here.
    pub(super) fn validate_identity_propagation(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            let Some(idp) = backend.identity_propagation.as_ref() else {
                continue;
            };
            idp.validate().map_err(|e| {
                Error::ConfigValidation(format!("backend '{name}' identity_propagation: {e}"))
            })?;
            // Only HTTP transports can carry the per-request credential header;
            // stdio/websocket would silently drop it (their transport ignores
            // extra headers), so a propagation-configured non-HTTP backend must
            // fail closed at load rather than dispatch without the credential
            // (MIK-6734 review).
            if !matches!(backend.transport, TransportConfig::Http { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' identity_propagation requires an http transport; \
                     stdio/websocket cannot carry the credential header (IDP.2)"
                )));
            }
            // `SessionMode::PerUser` is supported by the per-user transport pool
            // (MIK-6735, IDP.7). A backend running the gateway's own OAuth client
            // authenticates its session as the gateway during initialize(), so a
            // per-user credential would ride a channel that no longer represents
            // the end user. Refuse the pairing at load (F3).
            if backend.oauth.as_ref().is_some_and(|o| o.enabled) {
                return Err(Error::ConfigValidation(format!(
                    "backend '{name}' cannot combine identity_propagation with its own enabled \
                     oauth client: the backend oauth authorizes and persists a gateway-held token \
                     during initialize(), authenticating the transport session as the gateway \
                     before the per-request credential override — silently defeating per-user \
                     propagation. Set oauth.enabled=false on this backend or remove \
                     identity_propagation (F3)."
                )));
            }
        }
        self.validate_single_minting_strategy_kind()?;
        Ok(())
    }

    /// Refuse a config that asks for more than one *minting* strategy kind
    /// across backends (MIK-6729).
    ///
    /// The runtime installs exactly one `Arc<dyn IdentityPropagation>` for the
    /// whole gateway (`Gateway::config_installs_minting_strategy` +
    /// `set_identity_propagation`); it is not yet a per-backend resolver
    /// (tracked on MIK-6746). `SignedAssertion` and `TokenExchange` are both
    /// minting strategies — a config that mixes them would only ever get the
    /// first-installed strategy applied to every backend's `propagate()` call,
    /// silently minting the WRONG credential shape for the other backend's
    /// declared strategy. Fail closed at load instead (IDP.2): `Passthrough`
    /// mints nothing and is excluded from this check (see the `Gateway`
    /// install-site comment for the documented Passthrough + minting mix).
    pub(super) fn validate_single_minting_strategy_kind(&self) -> Result<()> {
        use crate::identity_propagation::PropagationStrategyKind as Kind;

        let mut kinds: Vec<Kind> = Vec::new();
        for c in self
            .backends
            .values()
            .filter_map(|b| b.identity_propagation.as_ref())
        {
            if matches!(c.strategy, Kind::SignedAssertion | Kind::TokenExchange)
                && !kinds.contains(&c.strategy)
            {
                kinds.push(c.strategy);
            }
        }

        if kinds.len() > 1 {
            return Err(Error::ConfigValidation(format!(
                "identity_propagation: backends request {} distinct minting strategies \
                 ({kinds:?}) but the gateway installs only one minting strategy process-wide; \
                 use a single minting strategy across all backends, or route the others through \
                 passthrough (MIK-6746 tracks a per-backend resolver)",
                kinds.len()
            )));
        }
        Ok(())
    }

    pub(super) fn validate_backend_names(&self) -> Result<()> {
        const INVALID_CHARS: &[char] = &['/', '\\', ':'];
        for name in self.backends.keys() {
            if name.is_empty() {
                return Err(Error::ConfigValidation(
                    "Backend name must not be empty".to_string(),
                ));
            }
            if let Some(bad) = INVALID_CHARS.iter().find(|&&c| name.contains(c)) {
                return Err(Error::ConfigValidation(format!(
                    "Backend name '{name}' contains invalid character '{bad}'"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn validate_remote_backend_provenance(&self) -> Result<()> {
        let policy = &self.security.remote_server_signing;

        for (name, backend) in &self.backends {
            if !backend.enabled {
                continue;
            }
            let Some((transport, url)) = remote_transport_identity(&backend.transport) else {
                continue;
            };

            let metadata = policy.backends.get(name);
            if policy.require_for_remote_backends || metadata.is_some() {
                let metadata = metadata.ok_or_else(|| {
                    Error::ConfigValidation(format!(
                        "remote backend '{name}' requires signed provenance metadata"
                    ))
                })?;
                verify_remote_server_provenance(name, transport, url, metadata, policy)?;
            }
        }

        Ok(())
    }

    pub(super) fn validate_backend_urls(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            match &backend.transport {
                TransportConfig::Http { http_url, .. } => {
                    if http_url.is_empty() {
                        return Err(Error::ConfigValidation(format!(
                            "Backend '{name}' has an empty http_url"
                        )));
                    }
                    let url = url::Url::parse(http_url).map_err(|e| {
                        Error::ConfigValidation(format!(
                            // The URL is not echoed: a malformed one still carries its
                            // userinfo and query, and a validation error is printed on
                            // startup and in support threads (MIK-7221).
                            "Backend '{name}' has an invalid http_url: {e}"
                        ))
                    })?;
                    Self::reject_cleartext_credentials(name, backend, &url)?;
                }
                #[cfg(feature = "a2a")]
                TransportConfig::A2a { a2a_url, .. } => {
                    if a2a_url.is_empty() {
                        return Err(Error::ConfigValidation(format!(
                            "Backend '{name}' has an empty a2a_url"
                        )));
                    }
                    let url = url::Url::parse(a2a_url).map_err(|e| {
                        Error::ConfigValidation(format!(
                            // Twin of the http_url line above. Fixing one spelling of a
                            // leak and not the other is how the first fix stops mattering.
                            "Backend '{name}' has an invalid a2a_url: {e}"
                        ))
                    })?;
                    Self::reject_cleartext_credentials(name, backend, &url)?;
                }
                TransportConfig::WebSocket {
                    ws_url,
                    protocol_version,
                } => Self::validate_ws_backend(name, backend, ws_url, protocol_version.as_deref())?,
                TransportConfig::Stdio { .. } => {}
            }
        }
        Ok(())
    }

    /// Refuse a backend that would put a credential on a cleartext wire.
    ///
    /// A credential sent over `http://` to a host off this machine is readable
    /// by everything on the path and replayable forever, so config load treats
    /// the combination as a mistake unless the operator has said otherwise in
    /// `allow_cleartext_credentials`.
    ///
    /// Runs only for an enabled backend: a disabled one opens no connection, so
    /// it leaks nothing. The skip covers this predicate alone — an empty or
    /// malformed URL still fails above, whatever `enabled` says.
    pub(super) fn reject_cleartext_credentials(
        name: &str,
        backend: &BackendConfig,
        url: &url::Url,
    ) -> Result<()> {
        if !backend.enabled
            || backend.allow_cleartext_credentials
            || !matches!(url.scheme(), "http" | "ws")
        {
            return Ok(());
        }
        // Loopback never leaves the machine. Decided by the classifier the
        // Origin gate already uses, so the two cannot drift; `host_str` hands it
        // a bare host, brackets and all for an IPv6 literal.
        let host = url.host_str().unwrap_or_default();
        if crate::gateway::is_loopback_host(host) {
            return Ok(());
        }
        // Five ways a credential reaches this backend. Any static header counts:
        // a known-name list would miss `X-Custom-Token` and every other spelling
        // an operator picks. A query counts because it is operator-supplied
        // material on the wire and its sensitivity is not decidable here.
        let credential_bearing = backend.oauth.is_some()
            || backend.identity_propagation.is_some()
            || !backend.secrets.is_empty()
            || !backend.headers.is_empty()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some();
        if !credential_bearing {
            return Ok(());
        }
        // The message names the backend and nothing else. It is printed on
        // startup and pasted into support threads, and the URL it would
        // otherwise echo is exactly the credential-bearing one (MIK-7221).
        Err(Error::ConfigValidation(format!(
            "Backend '{name}' would send credentials in cleartext to a host off this \
             machine. Use TLS, or set allow_cleartext_credentials on this backend to \
             accept that the credentials are readable and replayable in transit."
        )))
    }

    pub(super) fn validate_required_env_references(&self, overlay: &EnvOverlay) -> Result<()> {
        let errors = self.required_reference_errors(overlay);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Self::unresolved_error(&errors, overlay))
        }
    }

    pub(super) fn validate_backend_runtime_profiles(&self) -> Result<()> {
        for (name, backend) in &self.backends {
            let Some(profile_name) = backend.runtime_profile.as_deref() else {
                continue;
            };
            if profile_name.is_empty() {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile must not be empty"
                )));
            }
            if !matches!(backend.transport, TransportConfig::Stdio { .. }) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile is currently supported only for stdio backends"
                )));
            }
            if !self.runtime.profiles.contains_key(profile_name) {
                return Err(Error::ConfigValidation(format!(
                    "backends.{name}.runtime_profile references unknown runtime profile '{profile_name}'"
                )));
            }
        }

        Ok(())
    }
}
