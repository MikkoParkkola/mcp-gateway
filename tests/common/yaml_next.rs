// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The parity suite's view of the YAML adapter (MIK-8425 MIG.2): the same
//! surface as `tests/common/yaml.rs`, served by `yaml::next`, the
//! replacement backend. A report written against `crate::yaml` reads
//! through the new backend when compiled here.
#![allow(dead_code)]

#[path = "../../src/yaml/mod.rs"]
mod adapter;

pub(crate) use adapter::next::*;
