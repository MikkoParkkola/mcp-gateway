// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The slot a settled answer stores for a replay's declared effect
//! (MIK-9216.EFFECT.1): it survives the store's JSON form in every state, and
//! an execution that ran under two distinct slots stores none.

use serde_json::json;

use super::stored::{SlotNote, StoredChain, StoredDelivery};
use crate::backend::PoolKey;

fn per_user(binding: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: binding.to_owned(),
    }
}

fn settled_after(slots: &[PoolKey]) -> Option<PoolKey> {
    let mut note = SlotNote::default();
    for slot in slots {
        note.note(slot.clone());
    }
    note.settled()
}

/// GUARD (killed by mutant 6, Shared serialised as null): `None`,
/// `Some(Shared)` and `Some(PerUser)` each come back unchanged, and `Shared`
/// is a value, never null.
#[test]
fn the_stored_slot_survives_a_json_round_trip() {
    for slot in [None, Some(PoolKey::Shared), Some(per_user("b-1"))] {
        let stored = StoredDelivery {
            response: json!({"jsonrpc": "2.0", "result": {}}),
            chain: StoredChain::default(),
            audit: None,
            read: None,
            writes: crate::gateway::gateway_writes::WriteRecord::default(),
            dispatched: None,
            era: None,
            bindings: Vec::new(),
            effect_slot: slot.clone(),
        };
        let value = serde_json::to_value(&stored).expect("serialises");
        if slot == Some(PoolKey::Shared) {
            assert!(!value["effect_slot"].is_null(), "{value}");
        }
        let back: StoredDelivery = serde_json::from_value(value.clone()).expect("reads back");
        assert_eq!(back.effect_slot, slot, "{value}");
    }
}

#[test]
fn a_lease_noting_two_slots_stores_none() {
    let (a, b) = (per_user("a"), per_user("b"));
    assert_eq!(settled_after(&[]), None, "nothing noted");
    assert_eq!(
        settled_after(std::slice::from_ref(&a)),
        Some(a.clone()),
        "one slot"
    );
    assert_eq!(
        settled_after(&[a.clone(), a.clone()]),
        Some(a.clone()),
        "the same slot twice"
    );
    assert_eq!(
        settled_after(&[PoolKey::Shared, PoolKey::Shared]),
        Some(PoolKey::Shared),
        "the shared slot twice"
    );
    assert_eq!(settled_after(&[a.clone(), b.clone()]), None, "two slots");
    assert_eq!(
        settled_after(&[a.clone(), b, a]),
        None,
        "a conflict is sticky"
    );
}
