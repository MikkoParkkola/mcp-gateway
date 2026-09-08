// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup installation of per-backend account strategies.
//!
//! THE ONE INSTALL. Production startup and any test that drives a real startup
//! call this same function; there is no second place that decides what a bound
//! backend dispatches with. It runs before the gateway serves, against the
//! configuration `config::account_bindings` already compiled and refused on, so
//! a strategy is either installed for every bound backend or startup fails.
//!
//! REFUSES BEFORE SERVING. A `personal_managed` binding with no custody handle
//! is a startup failure, not a backend that quietly falls back to the shared
//! credential it is not allowed to have: the whole point of the binding is that
//! this backend speaks as one person, and a gateway that cannot do that must
//! not answer at all.

use std::sync::Arc;

use crate::config::Config;
use crate::config::account_bindings::{BoundAccountBackend, compile};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::identity_propagation::PropagationStrategyKind;
use crate::personal_accounts::{AccountCustody, VaultStrategy};
use crate::{Error, Result};

/// Install one strategy per bound backend, or refuse to start.
///
/// # Errors
///
/// [`Error::Config`] when a managed binding has no custody to serve it, or when
/// an external descriptor names a strategy this build cannot mint.
pub(crate) fn install_account_strategies(
    config: &Config,
    custody: Option<&Arc<dyn AccountCustody>>,
    gateway_key_pair: &Arc<GatewayKeyPair>,
    meta_mcp: &MetaMcp,
) -> Result<()> {
    for (name, bound) in compile(config)? {
        // A disabled backend was never registered, so installing a strategy
        // for it would bind custody to something that cannot be dispatched to.
        if !config.backends.get(&name).is_some_and(|b| b.enabled) {
            continue;
        }
        install_one(&bound, custody, gateway_key_pair, meta_mcp)?;
    }
    Ok(())
}

fn install_one(
    bound: &BoundAccountBackend,
    custody: Option<&Arc<dyn AccountCustody>>,
    gateway_key_pair: &Arc<GatewayKeyPair>,
    meta_mcp: &MetaMcp,
) -> Result<()> {
    let backend = bound.backend.as_str();
    let Some(propagation) = bound.propagation.as_ref() else {
        // A `shared` descriptor names an account this deployment already serves
        // statically. Nothing is installed, and nothing changes.
        return Ok(());
    };

    match propagation.strategy {
        PropagationStrategyKind::Vault => {
            let custody = custody.ok_or_else(|| {
                Error::Config(format!(
                    "backend '{backend}' is bound to personal_managed account '{}' but no \
                     account custody was started; the gateway refuses to serve a managed \
                     account as though it were a shared one. Configure the accounts block \
                     (enabled, store and authority directories, keys) for this deployment.",
                    bound.descriptor_id
                ))
            })?;
            let descriptor = bound.account.clone().ok_or_else(|| {
                Error::Config(format!(
                    "backend '{backend}' compiled to vault custody without an account \
                     descriptor; refusing to dispatch without one"
                ))
            })?;
            // The production custody, erased only so the strategy can hold it:
            // the same handle, the same service, the same store the gateway
            // claimed its locks with at startup.
            let erased: Arc<dyn AccountCustody> = Arc::clone(custody);
            meta_mcp.set_backend_identity_propagation(
                backend,
                Arc::new(VaultStrategy::new(erased, descriptor)),
            );
            tracing::info!(
                backend,
                account = %bound.descriptor_id,
                "Managed personal account bound to backend (vault custody)"
            );
        }
        PropagationStrategyKind::SignedAssertion => {
            let strategy = Arc::new(crate::identity_propagation::SignedAssertionStrategy::new(
                Arc::clone(gateway_key_pair),
                ASSERTION_TTL_SECS,
            ));
            meta_mcp.set_backend_identity_propagation(backend, strategy);
            tracing::info!(
                backend,
                account = %bound.descriptor_id,
                "External account descriptor bound to backend (signed-assertion strategy)"
            );
        }
        PropagationStrategyKind::TokenExchange => {
            let strategy = Arc::new(crate::identity_propagation::TokenExchangeStrategy::new(
                Arc::clone(gateway_key_pair),
                ASSERTION_TTL_SECS,
            ));
            meta_mcp.set_backend_identity_propagation(backend, strategy);
            tracing::info!(
                backend,
                account = %bound.descriptor_id,
                "External account descriptor bound to backend (RFC 8693 token-exchange strategy)"
            );
        }
        // Refused at config load (`external_strategy` accepts only the two
        // minting strategies), so this is unreachable from a validated config.
        // It refuses rather than installing nothing, because installing
        // nothing for a `required` binding would be discovered at dispatch.
        PropagationStrategyKind::Passthrough => {
            return Err(Error::Config(format!(
                "backend '{backend}' is bound to account '{}', whose strategy mints no \
                 credential; an account binding must produce the account holder's own \
                 credential",
                bound.descriptor_id
            )));
        }
    }
    Ok(())
}

/// Subject-assertion lifetime for an external descriptor's strategy, matching
/// the process-wide install site: 5 minutes, clamped further by the strategy.
const ASSERTION_TTL_SECS: i64 = 300;
