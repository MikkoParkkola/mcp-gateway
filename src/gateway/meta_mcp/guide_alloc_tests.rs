// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.8a: the initialize guide reads a capability's name, category
//! and chain hints, so building it must not copy the rest of the definition.
//! Measured on base, initialize spent about 8% of gateway CPU cloning every
//! `CapabilityDefinition` (input schemas, providers) to build it.

use std::sync::Arc;

use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::alloc_meter::measure;

const LARGE: usize = 256 * 1024;
const SMALL: usize = 256;

/// A capability whose input schema carries a description of `size` bytes.
fn meta_with_schema(size: usize) -> super::MetaMcp {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  category: search
schema:
  input:
    type: object
    properties:
      q:
        type: string
        description: {pad}
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /probe
",
        pad = "x".repeat(size)
    );
    let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
    backend
        .register_capability(crate::capability::parse_capability(&yaml).expect("capability"))
        .expect("registered");
    let meta = super::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_capabilities(Arc::new(backend));
    meta
}

fn guide(meta: &super::MetaMcp) -> (String, u64) {
    let scope = super::InvokeScope::unscoped(crate::gateway::router::CallerStanding::Admin);
    let (instructions, measured) = measure(|| meta.build_instructions(scope, None));
    assert!(
        instructions.contains("caps/probe"),
        "the guide names the capability: {instructions}"
    );
    (instructions, measured.bytes)
}

fn guide_bytes(meta: &super::MetaMcp) -> u64 {
    guide(meta).1
}

#[test]
fn the_initialize_guide_does_not_copy_capability_schemas() {
    let (small, large) = (meta_with_schema(SMALL), meta_with_schema(LARGE));
    guide_bytes(&small);
    guide_bytes(&large);
    // The guide never shows a schema: both texts are the same.
    assert_eq!(guide(&small).0, guide(&large).0);
    let grown = guide_bytes(&large).saturating_sub(guide_bytes(&small));
    assert!(
        grown < (LARGE / 4) as u64,
        "building the initialize guide allocated {grown} B more for a capability whose \
         schema is {LARGE} B than for one of {SMALL} B: the definition was copied \
         (MIK-8014 PERF.8a)"
    );
}
