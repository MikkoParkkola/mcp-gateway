// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The declared effect reads capabilities as the caller sees them, as cache
//! admission does: a provider hidden from the caller is an unregistered name,
//! so its definition never labels the call.

use std::sync::Arc;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::hiding::{CallerHiding, with_caller};
use crate::security::decision_record::{Effect, EffectSource};

/// Hides the capability provider `caps`.
struct HidesCaps;

impl CallerHiding for HidesCaps {
    fn hides(&self, server: &str) -> bool {
        server == "caps"
    }
}

fn gateway() -> MetaMcp {
    let definition = crate::capability::parse_capability(
        "name: lookup\n\
         description: Look one thing up\n\
         metadata:\n\
         \x20 exposure: public\n\
         \x20 read_only: true\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://127.0.0.1:9\n\
         \x20     path: /lookup\n\
         \x20     method: GET\n",
    )
    .expect("the capability parses");
    let executor = Arc::new(crate::capability::CapabilityExecutor::new());
    let caps = Arc::new(crate::capability::CapabilityBackend::new("caps", executor));
    caps.register_capability(definition).expect("registers");
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_capabilities(caps);
    meta
}

#[tokio::test]
async fn a_hidden_capability_provider_lends_no_effect() {
    let meta = gateway();
    // Premise: visible, the definition labels the call.
    assert_eq!(
        meta.declared_effect(("caps", "lookup"), None, None),
        Some((Effect::ReadOnly, EffectSource::CapabilityDefinition))
    );
    let hidden = with_caller(Arc::new(HidesCaps), async {
        meta.declared_effect(("caps", "lookup"), None, None)
    })
    .await;
    assert_eq!(hidden, None);
}
