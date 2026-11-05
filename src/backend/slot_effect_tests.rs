// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The slot a dispatch stores is the one the backend resolves for it, and a
//! replay reads exactly that slot: a lookup, never a create, never resolved
//! again.

use std::sync::Arc;
use std::time::Duration;

use super::{Backend, PoolKey};
use crate::config::BackendConfig;
use crate::security::decision_record::Effect;

/// A backend named `name`, propagating identity per user when `per_user`.
fn backend(per_user: bool) -> Arc<Backend> {
    let identity_propagation =
        per_user.then(|| crate::identity_propagation::IdentityPropagationConfig {
            strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            audience: "mem".to_string(),
            required: true,
            session_mode: crate::identity_propagation::SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        });
    Arc::new(Backend::new(
        "mem",
        BackendConfig {
            identity_propagation,
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn read(hint: bool) -> crate::protocol::Tool {
    serde_json::from_value(serde_json::json!({
        "name": "read", "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": hint},
    }))
    .expect("a tool")
}

/// A binding on a backend that propagates no identity runs on the shared
/// slot, so that is the slot stored; on a per-user backend, the binding's own.
#[test]
fn the_stored_slot_is_the_one_the_backend_resolves() {
    assert_eq!(backend(false).slot_key_for(Some("b-1")), PoolKey::Shared);
    assert_eq!(backend(false).slot_key_for(None), PoolKey::Shared);
    assert_eq!(
        backend(true).slot_key_for(Some("b-1")),
        PoolKey::PerUser {
            binding: "b-1".to_owned()
        }
    );
    assert_eq!(backend(true).slot_key_for(None), PoolKey::Shared);
}

/// The exact lookup: a warm slot reads its own declaration, never another
/// slot's; a slot the backend does not hold reads none and is not created.
#[test]
fn the_exact_lookup_reads_only_the_slot_named() {
    let per_user = backend(true);
    per_user.declare_slot_effects_for_test(None, vec![read(true)]);
    per_user.declare_slot_effects_for_test(Some("b-1"), vec![read(false)]);
    let b1 = PoolKey::PerUser {
        binding: "b-1".to_owned(),
    };
    let absent = PoolKey::PerUser {
        binding: "b-2".to_owned(),
    };
    assert_eq!(
        per_user.declared_effect_at(&b1, "read"),
        Some(Effect::MayWrite)
    );
    assert_eq!(
        per_user.declared_effect_at(&PoolKey::Shared, "read"),
        Some(Effect::ReadOnly)
    );
    assert_eq!(per_user.declared_effect_at(&absent, "read"), None);
    // A slot the backend holds but whose list never landed (evicted and
    // re-armed, say) reads none, though the shared slot is warm.
    let cold = PoolKey::PerUser {
        binding: "b-3".to_owned(),
    };
    per_user.pooled_entry(&cold).expect("admitted");
    assert_eq!(per_user.declared_effect_at(&cold, "read"), None);
    assert!(
        per_user.pooled_transport_for_test(&absent).is_none()
            && !per_user.pool.contains_key(&absent),
        "the lookup created the slot it read"
    );
    // A per-user key on a backend that holds no per-user slots reads none,
    // though resolving its binding again would read the shared slot.
    let shared_only = backend(false);
    shared_only.declare_slot_effects_for_test(None, vec![read(true)]);
    assert_eq!(shared_only.declared_effect_at(&b1, "read"), None);
    assert_eq!(
        shared_only.declared_effect_for(Some("b-1"), "read"),
        Some(Effect::ReadOnly)
    );
}
