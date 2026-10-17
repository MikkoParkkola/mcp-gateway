// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Integration tests' view of the crate's YAML adapter (MIK-8425 MIG.1a).
//!
//! This compiles `src/yaml.rs` itself rather than a second copy, so tests
//! and the gateway always share one implementation and one backend. That
//! only works while `src/yaml.rs` names nothing under `crate::`; compiling
//! this helper is what proves it.
#![allow(dead_code)]

#[path = "../../src/yaml.rs"]
mod adapter;

pub(crate) use adapter::*;
