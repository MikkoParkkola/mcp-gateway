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
use crate::config::account_bindings::{CompiledDescriptor, compile, compile_descriptors};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::GatewayKeyPair;
use crate::identity_propagation::{
    AccountStrategyRegistry, IdentityPropagation, InstalledAccount, PropagationStrategyKind,
};
use crate::personal_accounts::{AccountCustody, VaultStrategy};
use crate::{Error, Result};

/// Declare every configured descriptor into the shared registry.
///
/// Separate from installation because DECLARATION is what the capability
/// registration boundary checks against, and it must run before capabilities
/// are loaded — earlier than installation, which needs custody and the gateway
/// key pair. Idempotent, so startup and a later install may both call it.
pub(crate) fn declare_account_descriptors(config: &Config, registry: &AccountStrategyRegistry) {
    let Some(descriptors) = config
        .accounts
        .as_ref()
        .and_then(|accounts| accounts.descriptors.as_ref())
    else {
        return;
    };
    for (id, descriptor) in descriptors {
        registry.declare(id, &descriptor.provider, descriptor.mode);
    }
}

/// Install one strategy per configured descriptor, then bind it to every
/// backend that names it — or refuse to start.
///
/// TWO CONSUMERS, ONE STRATEGY. A descriptor's strategy is built ONCE, into the
/// shared registry a REST capability resolves against, and the SAME `Arc` is
/// handed to the per-backend map. Neither consumer can drift onto its own
/// instance, and there is no second store or second lookup pipeline.
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
    let registry = meta_mcp.account_strategies();
    declare_account_descriptors(config, &registry);

    // THE DEPLOYMENT'S MODE, decided ONCE here and handed to every managed
    // strategy. A gateway that authenticates, was explicitly declared
    // single-user, holds no second API key, has no identity provider and runs
    // no identity adapter serves its stored OAuth grants under one fixed
    // principal — otherwise a solo install has no principal at all and its
    // per-user credential store is unreachable (MIK-6744.STORE.1, open item O3).
    //
    // THE ADAPTER TERM IS NOT IN THE PREDICATE, deliberately.
    // `grants_single_user_principal` is an `AuthConfig` method and
    // `accounts.adapters` is not auth configuration, so the predicate cannot
    // see it. It matters for the same reason the OIDC term does: an adapter
    // (`gateway::openwebui_adapter`) is the product's OTHER `VerifiedIdentity`
    // producer, configured independently of any OIDC issuer, and a deployment
    // running one serves real per-user principals. Worse, a caller holding the
    // adapter's own credential but omitting the assertion header authenticates
    // and carries no identity — exactly the shape that would otherwise fall
    // through to the sole-operator principal.
    //
    // An ASSERTION, not a proof: two humans sharing this machine's credential
    // share the stored grants, because nothing here can tell them apart. That
    // is already true of `auth.single_user` for request authorisation; this
    // extends its reach to stored OAuth grants.
    let has_identity_adapter = config
        .accounts
        .as_ref()
        .is_some_and(|accounts| !accounts.adapters.is_empty());
    let sole_operator = config
        .auth
        .grants_single_user_principal(!config.key_server.oidc.is_empty())
        && !has_identity_adapter;
    if sole_operator {
        tracing::info!(
            "auth.single_user is asserted: managed accounts are served under one fixed \
             sole-operator principal, to callers this gateway authenticates. Anyone holding \
             this gateway's credential holds its stored OAuth grants."
        );
    }

    for compiled in compile_descriptors(config)? {
        install_descriptor(
            &compiled,
            custody,
            gateway_key_pair,
            &registry,
            sole_operator,
        );
    }

    for (name, bound) in compile(config)? {
        // A disabled backend was never registered, so installing a strategy
        // for it would bind custody to something that cannot be dispatched to.
        if !config.backends.get(&name).is_some_and(|b| b.enabled) {
            continue;
        }
        let backend = name.as_str();
        let Some(propagation) = bound.propagation.as_ref() else {
            // A `shared` descriptor names an account this deployment already
            // serves statically. Nothing is installed, and nothing changes.
            continue;
        };
        let Some(installed) = registry.installed(&bound.descriptor_id) else {
            return Err(match propagation.strategy {
                PropagationStrategyKind::Vault => Error::Config(format!(
                    "backend '{backend}' is bound to personal_managed account '{}' but no \
                     account custody was started; the gateway refuses to serve a managed \
                     account as though it were a shared one. Configure the accounts block \
                     (enabled, store and authority directories, keys) for this deployment.",
                    bound.descriptor_id
                )),
                // Refused at config load (`external_strategy` accepts only the
                // two minting strategies), so this is unreachable from a
                // validated config. It refuses rather than installing nothing,
                // because installing nothing for a `required` binding would be
                // discovered at dispatch.
                _ => Error::Config(format!(
                    "backend '{backend}' is bound to account '{}', whose strategy mints no \
                     credential; an account binding must produce the account holder's own \
                     credential",
                    bound.descriptor_id
                )),
            });
        };
        meta_mcp.set_backend_identity_propagation(backend, Arc::clone(&installed.strategy));
        tracing::info!(
            backend,
            account = %bound.descriptor_id,
            strategy = ?propagation.strategy,
            "Account descriptor bound to backend"
        );
    }
    Ok(())
}

/// Build and register the strategy for ONE descriptor.
///
/// Skips rather than refuses when it cannot build one: a `shared` descriptor
/// installs nothing by design, and a managed descriptor may be declared by a
/// deployment that never started custody. Skipping is safe ONLY because every
/// consumer fails closed on a missing installation — the backend loop above
/// refuses at startup for a bound MCP backend, and
/// `AccountStrategyRegistry::resolve` refuses at dispatch for a capability.
fn install_descriptor(
    compiled: &CompiledDescriptor,
    custody: Option<&Arc<dyn AccountCustody>>,
    gateway_key_pair: &Arc<GatewayKeyPair>,
    registry: &AccountStrategyRegistry,
    sole_operator: bool,
) {
    let id = compiled.descriptor_id.as_str();
    let Some(propagation) = compiled.propagation.as_ref() else {
        return;
    };
    // The managed strategy, retained TYPED beside the trait object below when
    // this descriptor is `personal_managed`. It is the same `Arc`: the registry
    // needs the concrete type to re-release a lease through durable custody
    // (which `IdentityPropagation` cannot express), and the MCP backend map
    // needs the trait object. One instance, so one key, one resolver and one
    // store serve both consumers.
    let mut managed: Option<Arc<VaultStrategy>> = None;
    let strategy: Arc<dyn IdentityPropagation> = match propagation.strategy {
        PropagationStrategyKind::Vault => {
            let (Some(custody), Some(descriptor)) = (custody, compiled.account.clone()) else {
                tracing::warn!(
                    account = id,
                    "personal_managed account declared with no started custody; no strategy is \
                     installed and every consumer of this account refuses"
                );
                return;
            };
            // The production custody, erased only so the strategy can hold it:
            // the same handle, the same service, the same store the gateway
            // claimed its locks with at startup.
            let erased: Arc<dyn AccountCustody> = Arc::clone(custody);
            let vault = Arc::new(VaultStrategy::new(erased, descriptor, sole_operator));
            managed = Some(Arc::clone(&vault));
            vault
        }
        PropagationStrategyKind::SignedAssertion => {
            Arc::new(crate::identity_propagation::SignedAssertionStrategy::new(
                Arc::clone(gateway_key_pair),
                ASSERTION_TTL_SECS,
            ))
        }
        PropagationStrategyKind::TokenExchange => {
            Arc::new(crate::identity_propagation::TokenExchangeStrategy::new(
                Arc::clone(gateway_key_pair),
                ASSERTION_TTL_SECS,
            ))
        }
        // Mints no credential. Left uninstalled so the bound-backend loop
        // above turns it into the startup refusal it has always been.
        PropagationStrategyKind::Passthrough => return,
    };
    registry.install(
        InstalledAccount {
            descriptor_id: id.to_string(),
            provider: compiled.provider.clone(),
            audience: propagation.audience.clone(),
            required: propagation.required,
            token_exchange_endpoint: propagation.token_exchange_endpoint.clone(),
            token_exchange_scope: propagation.token_exchange_scope.clone(),
            strategy,
            managed,
        },
        compiled.mode,
    );
    tracing::info!(
        account = id,
        strategy = ?propagation.strategy,
        "Account descriptor strategy installed"
    );
}

/// Subject-assertion lifetime for an external descriptor's strategy, matching
/// the process-wide install site: 5 minutes, clamped further by the strategy.
const ASSERTION_TTL_SECS: i64 = 300;
