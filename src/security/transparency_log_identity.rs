// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit log's stable identity: one `log_id`, minted once, carried by
//! every segment open record, so a record kept elsewhere can name the log it
//! was meant for. Records hold the id only: no paths, values or secrets.

use std::fmt;

/// Names a log that has no segment open record to carry its id (a log
/// written before the id existed), and records the mint of one.
pub(crate) const EV_IDENTIFIED: &str = "audit_log_identified";

/// An audit log's identity. Opaque: compare, display, never parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogId(String);

impl LogId {
    /// A fresh random id.
    pub(super) fn mint() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }

    /// The id as written to a record.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
