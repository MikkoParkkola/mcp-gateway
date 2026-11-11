// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared, test-only UI access matrix representation. Phase 1 pins the API;
//! loading and rendering deliberately panic until the red tests are confirmed.

use std::collections::BTreeMap;
use std::path::Path;

/// Attributes retained from `#@` header lines, false when absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::gateway) struct Attributes {
    pub(in crate::gateway) scoped: bool,
    pub(in crate::gateway) store_writes: bool,
    pub(in crate::gateway) store_reads: bool,
}

/// One route's fragment; rows contain path, method, shape, caller, answer.
/// Answers are expanded literals, including status, never `@name` references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct Fragment {
    pub(in crate::gateway) slug: String,
    /// The route path, independent of the directory used to load this file.
    pub(in crate::gateway) path: String,
    pub(in crate::gateway) attributes: Attributes,
    pub(in crate::gateway) rows: Vec<[String; 5]>,
}

/// A digest-only name: the same body can occur under different statuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct NamedBody {
    pub(in crate::gateway) digest: String,
    pub(in crate::gateway) meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway) struct Loaded {
    /// Files ordered by slug, with row order retained within each file.
    pub(in crate::gateway) files: Vec<Fragment>,
    /// Names retained for rendering expanded answers back to references.
    pub(in crate::gateway) bodies: BTreeMap<String, NamedBody>,
}

/// Read all checked-in fragments under `env!("CARGO_MANIFEST_DIR")`.
/// Feature filtering belongs to consumers, so this includes cost rows.
pub(in crate::gateway) fn rows() -> Loaded {
    panic!("not built")
}

/// Load an explicit fragment directory and its adjacent body definitions.
/// Errors use file basenames and physical, one-based line numbers so their
/// text is independent of the checkout or synthetic temporary directory.
pub(in crate::gateway) fn load_from(_dir: &Path, _bodies_file: &Path) -> Result<Loaded, String> {
    panic!("not built")
}

impl Loaded {
    /// Render TSV file contents, preserving attributes and replacing any
    /// digest equal to a named body with `@name`, regardless of status.
    pub(in crate::gateway) fn render_block(&self, _file: &Fragment) -> String {
        panic!("not built")
    }
}
