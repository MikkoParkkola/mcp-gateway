// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the gateway lends the watch source, and the catalogue and call
//! shapes they exchange.

use serde_json::Value;

use super::super::records::ApiKeyRef;

/// Whose credential a capability call needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialUse {
    /// None: one poller serves every principal.
    Free,
    /// A gateway-held key (env, keychain, file): a poller per principal.
    Keyed,
    /// A per-user account credential: not watchable (needs the caller's
    /// verified identity, which a stored subscription does not hold).
    Account,
}

/// One REST capability as the watch source sees it.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub capability: String,
    /// The backend the capability is served under (visibility scope).
    pub backend: String,
    /// Classified read-only as data (MIK-7216.IDEM.1); anything else is
    /// side-effecting and never watchable.
    pub read_only: bool,
    // ci-allow-secret-debug: an enum naming whose credential a call needs; it holds no secret.
    pub credential: CredentialUse,
    pub input_schema: Value,
}

/// The subscriber a poll runs as.
#[derive(Debug, Clone)]
pub(crate) struct Holder {
    pub principal: String,
    // ci-allow-secret-debug: a key's name and digest-derived principal, never the secret.
    pub api_key: ApiKeyRef,
}

/// Which budget a poll is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charge {
    /// The holder's own (a credentialed poller).
    Holder,
    /// The gateway's global budget (a shared poller).
    Global,
}

/// A poll that produced no answer: refused by a control or failed upstream.
#[derive(Debug)]
pub(crate) struct PollFailed;

/// One read of the capability catalogue (MIK-8037).
#[derive(Debug, Clone, Default)]
pub(crate) struct Catalogue {
    /// Every REST capability in it, read-only or not.
    pub targets: Vec<Target>,
    /// Every capability name in it, REST-served or not, and every name read
    /// yet absent (refused, or unloaded): a capability not here was not
    /// read, which is not the same as reclassified.
    pub present: std::collections::HashSet<String>,
    /// Every capability directory loaded, after the startup scan completed.
    pub complete: bool,
    /// The catalogue generation it was read at.
    pub generation: u64,
}

/// What the gateway lends the source: the capability catalogue, the live
/// grant check and the enforced poll.
#[async_trait::async_trait]
pub(crate) trait WatchHost: Send + Sync {
    /// The catalogue now, read once: its contents, completeness and
    /// generation agree (MIK-8037).
    fn catalogue(&self) -> Catalogue;
    /// Every REST capability now, read-only or not.
    fn targets(&self) -> Vec<Target> {
        self.catalogue().targets
    }
    /// The catalogue generation now: it moves at every catalogue write, so a
    /// denial is trusted only when it has not moved since the read the
    /// decision started from (MIK-8037).
    fn catalogue_generation(&self) -> u64;
    /// Whether `holder` may invoke `target` at the caller's reading `now` (MIK-8202).
    fn may_invoke(
        &self,
        holder: &Holder,
        target: &Target,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool;
    /// Call `target` as `holder` with every control a `tools/call` gets, and
    /// return the firewall-approved application value, before per-call
    /// metadata is attached.
    async fn poll(
        &self,
        holder: &Holder,
        target: &Target,
        arguments: &Value,
        charge: Charge,
    ) -> Result<Value, PollFailed>;
}
