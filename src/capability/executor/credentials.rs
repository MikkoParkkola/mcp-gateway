// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Credential resolution for capability execution
//!
//! All credential sources: `env:VAR`, `keychain:name`, `oauth:provider`,
//! `file:/path:field`, `{env.VAR}`, `BARE_UPPER_NAME`.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::capability::CapabilityExecutionContext;
use crate::identity_propagation::AccountCredential;
use crate::oauth::TokenInfo;
use crate::personal_accounts::config::DescriptorMode;
use crate::{Error, Result};

use super::CapabilityExecutor;

impl CapabilityExecutor {
    /// Fetch credential from secure storage.
    /// Resolve a capability's `auth.account` reference into outbound headers.
    ///
    /// `Ok(None)` means there is nothing to resolve — no reference, or an
    /// explicit `shared` descriptor whose existing static behaviour must be
    /// preserved byte for byte. Everything else is either headers minted for
    /// the verified caller by the shared strategy, or a refusal.
    ///
    /// # Errors
    ///
    /// Every refusal from [`crate::identity_propagation::AccountStrategyRegistry::resolve`],
    /// plus the no-catalogue case. None of them falls through to a legacy
    /// lookup.
    pub(super) async fn resolve_account_headers(
        &self,
        auth: &super::super::AuthConfig,
        context: &CapabilityExecutionContext,
    ) -> Result<Option<Vec<(String, String)>>> {
        let Some(account) = auth.account.as_deref() else {
            return Ok(None);
        };
        let registry = self.require_account_catalogue(auth, account)?;
        // The dispatch already resolved this account before its first cache
        // lookup. Recheck it against the SAME registry here — the last point
        // before the credential goes on the wire — and then present the headers
        // it minted verbatim. Re-minting instead would mean the value that
        // selected the cache entry and the value on the wire were two different
        // credentials, which is exactly the drift the MCP route's
        // resolve-once-reuse-verbatim rule exists to prevent.
        if let Some(prepared) = context.account_credential.as_deref() {
            Self::assert_prepared_matches(prepared, auth, account)?;
            registry
                .revalidate(prepared, context.verified_identity.as_deref())
                .await?;
            return Ok(Some(prepared.headers().to_vec()));
        }
        match registry
            .resolve(account, &auth.key, context.verified_identity.as_deref())
            .await?
        {
            AccountCredential::Legacy => Ok(None),
            AccountCredential::Prepared(prepared) => Ok(Some(prepared.headers().to_vec())),
        }
    }

    /// Resolve the capability's PRIMARY `auth.account` reference and publish
    /// its binding onto the context, BEFORE the caller consults any cache.
    ///
    /// Returns the context to execute under. Unchanged for a capability with no
    /// account reference and for an explicit `shared` descriptor — both keep
    /// the existing cache key and the existing static credential path.
    ///
    /// When the invoke path already resolved a credential for this dispatch it
    /// is RECHECKED against the registry rather than re-minted, so one dispatch
    /// consumes exactly one credential; when nothing was carried (a standalone
    /// executor, or any caller that did not prepare one) the account is
    /// resolved here instead. There is no third case, and in particular no case
    /// in which a cache is consulted for an account that was never resolved.
    ///
    /// # Errors
    ///
    /// Every refusal from
    /// [`crate::identity_propagation::AccountStrategyRegistry::resolve`] and
    /// [`crate::identity_propagation::AccountStrategyRegistry::revalidate`],
    /// plus the no-catalogue case and a carried credential that does not belong
    /// to this capability's reference. None of them falls back to a legacy
    /// lookup and none of them degrades into a cache miss.
    pub(super) async fn prepare_account_context(
        &self,
        capability: &super::super::CapabilityDefinition,
        mut context: CapabilityExecutionContext,
    ) -> Result<CapabilityExecutionContext> {
        let auth = &capability.auth;
        let Some(account) = auth.account.as_deref() else {
            return Ok(context);
        };
        let registry = self.require_account_catalogue(auth, account)?;

        if let Some(prepared) = context.account_credential.clone() {
            Self::assert_prepared_matches(&prepared, auth, account)?;
            registry
                .revalidate(&prepared, context.verified_identity.as_deref())
                .await?;
            context.cache_binding = Some(prepared.cache_binding().to_owned());
            return Ok(context);
        }

        match registry
            .resolve(account, &auth.key, context.verified_identity.as_deref())
            .await?
        {
            // A `shared` descriptor is not an account credential at all: the
            // deployment already serves it statically, and its cache namespace
            // must stay exactly what it was.
            AccountCredential::Legacy => Ok(context),
            AccountCredential::Prepared(prepared) => {
                // The strategy's own opaque binding — the five-field account
                // digest widened with the grant generation, authorization
                // epoch, token revision and descriptor revision. Copied, never
                // re-hashed: a re-authorized, rotated or revoked account
                // publishes a different binding and therefore a different key.
                context.cache_binding = Some(prepared.cache_binding().to_owned());
                context.account_credential = Some(prepared);
                Ok(context)
            }
        }
    }

    /// The account catalogue, or the no-catalogue refusal.
    ///
    /// A standalone executor has no catalogue, and a capability naming an
    /// account must fail CLOSED there rather than resolving the gateway-held
    /// `oauth:<provider>` token.
    fn require_account_catalogue(
        &self,
        auth: &super::super::AuthConfig,
        account: &str,
    ) -> Result<&crate::identity_propagation::AccountStrategyRegistry> {
        self.account_strategies().ok_or_else(|| {
            Error::Config(format!(
                "capability auth references account '{account}' but this executor has no \
                 account catalogue; refusing rather than falling back to the gateway-held \
                 credential for '{}'.",
                auth.key
            ))
        })
    }

    /// A carried credential must be the one THIS capability's reference asks
    /// for. A credential prepared for another descriptor or another auth key
    /// belongs to another capability's account boundary and is refused rather
    /// than reused.
    fn assert_prepared_matches(
        prepared: &crate::identity_propagation::PreparedAccountCredential,
        auth: &super::super::AuthConfig,
        account: &str,
    ) -> Result<()> {
        if prepared.descriptor_id == account && prepared.auth_key == auth.key {
            return Ok(());
        }
        Err(Error::Config(format!(
            "capability auth references account '{account}' but the credential resolved for \
             this dispatch was minted for a different account reference; refusing rather than \
             presenting one capability's account credential for another."
        )))
    }

    /// Whether `account` is an explicit `shared` descriptor, whose credential
    /// is the existing gateway-held one.
    ///
    /// Answers from the DECLARED catalogue and never mints: asking this question
    /// must not consume a custody lease.
    fn account_is_shared(&self, account: &str) -> bool {
        self.account_strategies().is_some_and(|registry| {
            registry
                .declared(account)
                .is_some_and(|declared| declared.mode == DescriptorMode::Shared)
        })
    }

    /// Fetch credential from secure storage.
    pub(super) async fn fetch_credential(
        &self,
        auth: &super::super::AuthConfig,
        _context: &CapabilityExecutionContext,
    ) -> Result<String> {
        let key = &auth.key;

        // A managed or external account's credential is a per-caller HEADER
        // minted by the shared resolver, not an opaque secret this function can
        // return: the provider's own `token_type` and any additional header
        // would be lost, and the caller of this function may be about to put
        // the value in a URL query parameter. `inject_auth` is the one place
        // that may resolve one. Everything else refuses BEFORE any legacy
        // lookup — falling through would resolve the gateway-held
        // `oauth:<provider>` token from the shared TokenStorage and present one
        // person's login as another's. An explicit `shared` descriptor is not
        // an account credential at all and continues below, unchanged.
        if let Some(account) = auth.account.as_deref()
            && !self.account_is_shared(account)
        {
            return Err(Error::Config(format!(
                "capability auth references account '{account}', whose credential is a \
                 per-caller header minted by the shared identity resolver; it cannot be \
                 injected as a query parameter or rewritten with a prefix. Refusing rather \
                 than falling back to the gateway-held credential for '{key}'."
            )));
        }

        if let Some(var_name) = key.strip_prefix("env:") {
            self.env.get().resolve(var_name).ok_or_else(|| {
                Error::Config(format!(
                    "Environment variable '{}' not set (required for {})",
                    var_name, auth.description
                ))
            })
        } else if let Some(keychain_key) = key.strip_prefix("keychain:") {
            self.fetch_from_keychain(keychain_key).await
        } else if let Some(provider) = key.strip_prefix("oauth:") {
            self.fetch_oauth_token(provider, auth.token_endpoint.as_deref())
                .await
        } else if let Some(file_spec) = key.strip_prefix("file:") {
            self.fetch_from_file(file_spec)
        } else if key.starts_with("{env.") && key.ends_with('}') {
            let var_name = &key[5..key.len() - 1];
            self.env
                .get()
                .resolve(var_name)
                .ok_or_else(|| Error::Config(format!("Environment variable '{var_name}' not set")))
        } else if key.is_empty() {
            Err(Error::Config("No credential key configured".to_string()))
        } else if Self::looks_like_env_var_name(key) {
            self.env.get().resolve(key).ok_or_else(|| {
                Error::Config(format!(
                    "Environment variable '{key}' not set. Set it with: export {key}=your_key"
                ))
            })
        } else {
            Err(Error::Config(format!(
                "Unknown credential format: {}. Use env:, keychain:, oauth:, file:, or set environment variable",
                key.chars().take(20).collect::<String>()
            )))
        }
    }

    /// Returns `true` if the string is `UPPER_SNAKE_CASE` (bare env-var form).
    pub(super) fn looks_like_env_var_name(s: &str) -> bool {
        !s.is_empty()
            && s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Fetch a JSON field from a file.  Format: `file:/path.json:nested.field`
    #[allow(clippy::unused_self)]
    pub(super) fn fetch_from_file(&self, spec: &str) -> Result<String> {
        let (path, field) = spec.rsplit_once(':').ok_or_else(|| {
            Error::Config(format!(
                "Invalid file credential format. Expected: file:/path/to/file.json:field_name (got 'file:{}')",
                spec.chars().take(50).collect::<String>()
            ))
        })?;

        if field.is_empty() {
            return Err(Error::Config(
                "Empty field name in file credential. Expected: file:/path/to/file.json:field_name"
                    .to_string(),
            ));
        }

        let expanded_path = expand_home_dir(path)?;
        let content = std::fs::read_to_string(&expanded_path).map_err(|e| {
            Error::Config(format!(
                "Failed to read credential file '{}': {}",
                expanded_path.display(),
                e
            ))
        })?;
        let json: Value = serde_json::from_str(&content).map_err(|e| {
            Error::Config(format!(
                "Failed to parse credential file '{}' as JSON: {}",
                expanded_path.display(),
                e
            ))
        })?;

        extract_json_field(&json, field, &expanded_path)
    }

    /// Fetch an OAuth token, refreshing automatically when possible.
    ///
    /// Resolution order:
    /// 1. In-memory cache (valid token)
    /// 2. Disk storage (valid token)
    /// 3. Refresh-token grant (expired + `refresh_token` + `token_endpoint`)
    /// 4. Error
    pub(super) async fn fetch_oauth_token(
        &self,
        provider: &str,
        token_endpoint: Option<&str>,
    ) -> Result<String> {
        // 1. In-memory cache
        {
            let tokens = self.oauth_tokens.read();
            if let Some(token) = tokens.get(provider)
                && !token.is_expired()
            {
                return Ok(token.access_token.clone());
            }
        }

        // 2. Disk storage
        if let Some(ref storage) = self.token_storage
            && let Some(token) = storage.load(provider, provider)
        {
            if !token.is_expired() {
                let tokens = self.oauth_tokens.read();
                tokens.insert(provider.to_string(), token.clone());
                return Ok(token.access_token);
            }

            // 3. Refresh grant
            if let (Some(ref_tok), Some(endpoint)) = (&token.refresh_token, token_endpoint) {
                match self
                    .perform_token_refresh(
                        provider,
                        ref_tok,
                        endpoint,
                        storage,
                        token.client_id.as_deref(),
                    )
                    .await
                {
                    Ok(new_token) => return Ok(new_token),
                    Err(e) => {
                        warn!(
                            provider = %provider,
                            error = %e,
                            "Token refresh failed; manual re-authentication required"
                        );
                    }
                }
            } else if token.refresh_token.is_some() && token_endpoint.is_none() {
                warn!(
                    provider = %provider,
                    "OAuth token expired with refresh_token present, but no \
                     token_endpoint configured in auth.token_endpoint."
                );
            }

            return Err(Error::Config(format!(
                "OAuth token for '{provider}' is expired. Re-authenticate using the gateway OAuth flow or refresh the token."
            )));
        }

        Err(Error::Config(format!(
            "OAuth token for '{provider}' not found. \
            To authorize, use the gateway's OAuth flow: \
            1. Configure an OAuth-enabled backend named '{provider}' in gateway config \
            2. Make a request to trigger authorization \
            3. Complete browser-based authorization \
            Or manually set the token via set_oauth_token()"
        )))
    }

    /// Perform the OAuth refresh-token grant and persist the refreshed token.
    ///
    /// `client_id` is forwarded when present (required by Google and other providers).
    /// `client_secret` is looked up from the macOS Keychain under the key
    /// `"{provider}-client-secret"` and included when found.
    async fn perform_token_refresh(
        &self,
        provider: &str,
        refresh_token: &str,
        token_endpoint: &str,
        storage: &crate::oauth::TokenStorage,
        client_id: Option<&str>,
    ) -> Result<String> {
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token);

        if let Some(id) = client_id {
            params.insert("client_id", id);
        }

        let keychain_key = format!("{provider}-client-secret");
        let client_secret_owned: Option<String> =
            self.fetch_from_keychain(&keychain_key).await.ok();
        if let Some(ref secret) = client_secret_owned {
            params.insert("client_secret", secret.as_str());
        }

        let response = self
            .client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "OAuth refresh request to '{token_endpoint}' failed: {e}"
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(Error::Config(format!(
                "OAuth refresh for '{provider}' failed: HTTP {status}"
            )));
        }

        let resp: RefreshTokenResponse = response.json().await.map_err(|e| {
            Error::Config(format!(
                "Failed to parse OAuth refresh response for '{provider}': {e}"
            ))
        })?;

        let expires_at = resp.expires_in.map(|secs| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + secs
        });

        let new_token = TokenInfo {
            access_token: resp.access_token,
            token_type: resp.token_type.unwrap_or_else(|| "Bearer".to_string()),
            refresh_token: resp
                .refresh_token
                .or_else(|| Some(refresh_token.to_string())),
            expires_at,
            scope: resp.scope,
            token_endpoint: Some(token_endpoint.to_string()),
            client_id: client_id.map(str::to_owned),
            client_secret: client_secret_owned,
        };

        if let Err(e) = storage.save(provider, provider, &new_token) {
            warn!(
                provider = %provider,
                error = %e,
                "Failed to persist refreshed OAuth token"
            );
        }

        {
            let tokens = self.oauth_tokens.read();
            tokens.insert(provider.to_string(), new_token.clone());
        }

        info!(provider = %provider, "OAuth token refreshed successfully");
        Ok(new_token.access_token)
    }

    #[cfg(target_os = "macos")]
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub(super) async fn fetch_from_keychain(&self, key: &str) -> Result<String> {
        use std::process::Command;
        let output = Command::new("security")
            .args(["find-generic-password", "-s", key, "-w"])
            .output()
            .map_err(|e| Error::Config(format!("Failed to access keychain: {e}")))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Error::Config(format!(
                "Keychain entry '{key}' not found. Add it with: security add-generic-password -s '{key}' -a 'mcp-gateway' -w 'YOUR_SECRET'"
            )))
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(unknown_lints, clippy::unused_async_trait_impl)]
    pub(super) async fn fetch_from_keychain(&self, _key: &str) -> Result<String> {
        Err(Error::Config(
            "Keychain access only supported on macOS. Use env: instead.".to_string(),
        ))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    token_type: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

// Manual `Debug` that redacts the OAuth tokens (CWE-532, mirrors PR #323). A
// derived `Debug` would print `access_token` / `refresh_token` verbatim into
// any trace or error context.
impl std::fmt::Debug for RefreshTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("RefreshTokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("refresh_token", &redact_opt(&self.refresh_token))
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

fn expand_home_dir(path: &str) -> Result<std::path::PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(home) => Ok(home.join(rest)),
            None => Err(Error::Config(
                "Cannot expand ~ in file credential path: HOME not set".to_string(),
            )),
        }
    } else {
        Ok(std::path::PathBuf::from(path))
    }
}

fn extract_json_field(json: &Value, field: &str, path: &std::path::Path) -> Result<String> {
    let mut current = json;
    for segment in field.split('.') {
        current = current.get(segment).ok_or_else(|| {
            Error::Config(format!(
                "Field '{}' not found in credential file '{}'",
                field,
                path.display()
            ))
        })?;
    }
    match current {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(Error::Config(format!(
            "Field '{}' in '{}' must be a string or number, got {}",
            field,
            path.display(),
            match current {
                Value::Bool(_) => "boolean",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
                Value::Null => "null",
                _ => "unknown",
            }
        ))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use dashmap::DashMap;
    use parking_lot::RwLock;
    use tempfile::tempdir;

    use crate::capability::response_cache::ResponseCache;
    use crate::oauth::{TokenInfo, TokenStorage};
    use crate::secrets::SecretResolver;

    use super::super::CapabilityExecutor;

    fn executor_with_storage(storage: Arc<TokenStorage>) -> CapabilityExecutor {
        CapabilityExecutor {
            client: reqwest::Client::new(),
            cache: ResponseCache::new(),
            token_storage: Some(storage),
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("test"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
        }
    }

    fn executor_no_storage() -> CapabilityExecutor {
        CapabilityExecutor {
            client: reqwest::Client::new(),
            cache: ResponseCache::new(),
            token_storage: None,
            oauth_tokens: RwLock::new(DashMap::new()),
            secret_resolver: Arc::new(SecretResolver::new()),
            health: crate::failsafe::HealthTracker::new("test"),
            env: Arc::new(crate::config::LiveEnv::default()),
            policy_epoch: None,
            account_strategies: None,
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn valid_tok(name: &str) -> TokenInfo {
        TokenInfo {
            expires_at: Some(now_secs() + 3600),
            ..TokenInfo::from_response(name.to_string(), None, None, None, None)
        }
    }

    fn expired_tok(name: &str) -> TokenInfo {
        TokenInfo {
            expires_at: Some(0),
            ..TokenInfo::from_response(name.to_string(), None, None, None, None)
        }
    }

    #[tokio::test]
    async fn returns_valid_cached_token() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let ex = executor_with_storage(s);
        ex.set_oauth_token("p", valid_tok("cached"));
        assert_eq!(ex.fetch_oauth_token("p", None).await.unwrap(), "cached");
    }

    #[tokio::test]
    async fn loads_valid_token_from_disk() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        s.save("p2", "p2", &valid_tok("disk")).unwrap();
        let ex = executor_with_storage(s);
        assert_eq!(ex.fetch_oauth_token("p2", None).await.unwrap(), "disk");
    }

    #[tokio::test]
    async fn disk_token_cached_after_load() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        s.save("p3", "p3", &valid_tok("fresh")).unwrap();
        let ex = executor_with_storage(s);
        ex.fetch_oauth_token("p3", None).await.unwrap();
        assert!(ex.oauth_tokens.read().contains_key("p3"));
    }

    #[tokio::test]
    async fn expired_no_refresh_returns_error() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        s.save("p4", "p4", &expired_tok("old")).unwrap();
        let ex = executor_with_storage(s);
        let err = ex.fetch_oauth_token("p4", None).await.unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn expired_with_refresh_no_endpoint_returns_error() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let mut tok = expired_tok("stale");
        tok.refresh_token = Some("rt".to_string());
        s.save("p5", "p5", &tok).unwrap();
        let ex = executor_with_storage(s);
        let err = ex.fetch_oauth_token("p5", None).await.unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn missing_token_returns_not_found() {
        let ex = executor_no_storage();
        let err = ex.fetch_oauth_token("unk", None).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found"), "{msg}");
        assert!(msg.contains("unk"), "{msg}");
    }

    #[tokio::test]
    async fn expired_memory_falls_through_to_valid_disk() {
        let dir = tempdir().unwrap();
        let s = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        s.save("p6", "p6", &valid_tok("disk_fresh")).unwrap();
        let ex = executor_with_storage(s);
        ex.set_oauth_token("p6", expired_tok("mem_stale"));
        assert_eq!(
            ex.fetch_oauth_token("p6", None).await.unwrap(),
            "disk_fresh"
        );
    }

    #[test]
    fn env_var_name_detection() {
        assert!(CapabilityExecutor::looks_like_env_var_name("API_KEY"));
        assert!(CapabilityExecutor::looks_like_env_var_name("KEY123"));
        assert!(!CapabilityExecutor::looks_like_env_var_name("api_key"));
        assert!(!CapabilityExecutor::looks_like_env_var_name(""));
    }

    #[test]
    fn file_no_colon_is_error() {
        let ex = CapabilityExecutor::new();
        let err = ex.fetch_from_file("/path/to/file.json").unwrap_err();
        assert!(
            err.to_string().contains("Invalid file credential format"),
            "{err}"
        );
    }

    #[test]
    fn file_empty_field_is_error() {
        let ex = CapabilityExecutor::new();
        let err = ex.fetch_from_file("/path/to/file.json:").unwrap_err();
        assert!(err.to_string().contains("Empty field name"), "{err}");
    }
}

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // RefreshTokenResponse::Debug must never surface the OAuth tokens.
    #[test]
    fn refresh_token_response_debug_redacts_tokens() {
        let r = RefreshTokenResponse {
            access_token: SENTINEL.to_string(),
            token_type: Some("Bearer".to_string()),
            refresh_token: Some(format!("{SENTINEL}-refresh")),
            expires_in: Some(3600),
            scope: Some("read".to_string()),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(SENTINEL), "leaked token: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("Bearer"),
            "token_type should stay visible: {dbg}"
        );
    }
}
