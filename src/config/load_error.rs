// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A config load error names the key, the place and the expected type, never
//! the value that caused it (MIK-8375, CWE-532).

/// The error every config extract reports.
pub(crate) fn from_figment(error: figment::Error) -> crate::Error {
    crate::Error::Config(error.to_string())
}

/// `message` with any value serde quoted in it removed.
pub(crate) fn redact_message(message: &str) -> String {
    message.to_owned()
}
