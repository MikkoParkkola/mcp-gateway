// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/lease`: the one request that hands
//! the gateway a subscriber's own passthrough token for their listener.

use serde_json::{Value, json};

use super::types::RpcError;
use super::{EventsHub, lease, observation, upstream};

impl EventsHub {
    /// `events/lease` on `POST /mcp/{backend}`: hold the
    /// caller's own passthrough token, in memory only, for the listener of
    /// their live subscription `params.subscription` on this backend. Answered
    /// by the gateway, never forwarded. Ownership and the observation come from
    /// the events owner principal, the same function `events/subscribe` keys
    /// its rows by (D4).
    ///
    /// # Errors
    /// `-32012` for no principal, a handle that is not the caller's live row
    /// on this backend, or a backend that is not passthrough; `-32602` for a
    /// missing handle or token; `-32014` for a token the lease refuses.
    pub(crate) async fn lease(
        &self,
        principal: Option<&str>,
        backend: &str,
        params: Option<&Value>,
        authorization: Option<zeroize::Zeroizing<String>>,
    ) -> Result<Value, RpcError> {
        let principal = principal.ok_or_else(RpcError::forbidden)?;
        let handle = params
            .and_then(|p| p.get("subscription"))
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid("subscription"))?;
        let now = crate::clock::utc_now().map_err(|_| RpcError::clock_unreadable())?;
        // The caller's own live row, found by its handle: another principal's
        // handle, or a row on another backend, is refused alike (E3).
        let row = self
            .store
            .subscriptions()
            .into_iter()
            .filter(|s| s.principal == principal && s.live(now))
            .find(|s| self.handle(&s.id).is_ok_and(|h| h == handle))
            .filter(|s| upstream::parse_name(&s.name).is_some_and(|(b, _)| b == backend))
            .ok_or_else(RpcError::forbidden)?;
        let services = self.runtime.services.get().ok_or_else(RpcError::internal)?;
        let config = services.live.get();
        let binding = observation::binding(&config, backend).ok_or_else(RpcError::forbidden)?;
        if binding.basis.strategy
            != crate::identity_propagation::PropagationStrategyKind::Passthrough
        {
            return Err(RpcError::forbidden());
        }
        let obs = observation::observe_row(&config, backend, &row)
            .ok()
            .flatten()
            .ok_or_else(RpcError::forbidden)?;
        let authorization = authorization.ok_or_else(|| RpcError::invalid("authorization"))?;
        let until = row
            .effective_expiry()
            .and_then(|at| u64::try_from(at.timestamp()).ok())
            .unwrap_or(u64::MAX);
        let key = lease::LeaseKey {
            backend: backend.to_owned(),
            obs,
        };
        self.leases
            .install(key, authorization, until, lease::MIN_LEASE_REMAINING_SECS)
            .await
            .map_err(RpcError::lease_refused)?;
        // The parked listener starts now, under the new lease (E7).
        if let Some(source) = self.source(super::types::SourceKind::BackendNotification) {
            source.backend_changed(backend);
        }
        Ok(json!({ "subscription": handle, "state": "active" }))
    }
}

#[cfg(test)]
#[path = "lease_rpc_tests.rs"]
mod tests;
