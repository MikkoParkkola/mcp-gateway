// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — reading a 3.x credential file, and refusing loudly.
//!
//! Design §5.3c.1 (a missing source must not read as "nothing to migrate"),
//! §10.2 (a malformed record must leak nothing to logs) and §10.5 (the source
//! directory is a trust boundary).
//!
//! WHY THIS DOES NOT CALL `TokenStorage::load`. Design §7.1 step 1 originally
//! said to, on the grounds that reusing the existing reader adds no parser. Two
//! requirements make that wrong here, and both were already written down
//! elsewhere in the same design:
//!
//! 1. `load` returns `None` for a file that is ABSENT and for one that is
//!    PRESENT BUT UNPARSEABLE (`oauth/storage.rs:194-224`). Migration must tell
//!    those apart: the first is the silent-zero failure §5.3c.1 exists to
//!    refuse, and the second is a different refusal with a different fix.
//! 2. `load` logs the raw `serde_json` error (`oauth/storage.rs:215`), whose
//!    `Display` can embed the offending input — so a token landing in a
//!    wrong-typed field reaches an operator's log at `warn`. §10.2 requires
//!    migration not to rely on those diagnostics, and names a position-only
//!    wrapper as one of the two sanctioned fixes. This is that wrapper.
//!
//! The 3.x FORMAT is still not reimplemented: this deserializes the same
//! `TokenInfo` the existing reader does, so a schema change moves both together.

use std::path::Path;

use crate::oauth::TokenInfo;

/// Why a declared backend's 3.x source cannot be read.
///
/// Carries the path in the missing case and NOTHING ELSE anywhere: a path under
/// the credential directory is what the user needs to act on, and no variant
/// carries a token, a scope, or a fragment of file content. `Position` is the
/// whole of what a parse failure reports (§10.2).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::personal_accounts) enum SourceRefusal {
    /// Declared, but the resolved file is not there.
    ///
    /// THE LOUD REFUSAL. A resolved filename that does not exist otherwise
    /// reads as "nothing to migrate", which reaches the user as every backend
    /// asking to re-authorise — indistinguishable from the migration never
    /// running. Deriving the backend name from the binding (§5.3c) removes the
    /// typo path into this; it does not remove a rename, a moved `$HOME`, or a
    /// file the user deleted. So the path is named, and so is the override.
    #[error(
        "no 3.x credential file at {path}; if this backend was renamed since 3.x, \
         pass its former name as `--legacy-backend-name NAME`"
    )]
    Missing { path: String },
    /// The resolved path is not a regular file, or is a symbolic link.
    ///
    /// §10.5: the filename is predictable from values anyone who can read the
    /// config can read, and `fs::read_to_string` follows symlinks with no
    /// ownership or mode check. A party who can write into the source directory
    /// could otherwise plant that exact path and have migration seal THEIR
    /// token into the declared principal's account.
    #[cfg_attr(
        not(windows),
        error(
            "the 3.x credential path at {path} is not a regular file owned privately by this user"
        )
    )]
    #[cfg_attr(
        windows,
        error(
            "the 3.x credential path at {path} is not a regular file owned privately by this user{detail}"
        )
    )]
    NotPrivate {
        path: String,
        /// Windows: which rule failed and the commands that repair it.
        #[cfg(windows)]
        detail: String,
    },
    /// The file parsed as neither a 3.x nor a 4.0.0 `TokenInfo`.
    ///
    /// Reports the position and nothing else. `serde_json`'s own `Display`
    /// embeds offending input in several error shapes, which is the leak §10.2
    /// records at `oauth/storage.rs:215`.
    #[error("the 3.x credential file at {path} is not valid JSON at line {line} column {column}")]
    Unparseable {
        path: String,
        line: usize,
        column: usize,
    },
}

/// Read one 3.x credential file, or refuse with a reason the user can act on.
///
/// The order is deliberate: existence before privacy before parsing, so the
/// most actionable refusal wins and no content is read from a path that failed
/// its trust check.
pub(in crate::personal_accounts) fn read_legacy_source(
    path: &Path,
) -> Result<TokenInfo, SourceRefusal> {
    let shown = path.display().to_string();
    // `symlink_metadata` does NOT follow the link, which is the whole point:
    // `metadata` would report the TARGET's type and mode and call a planted
    // symlink a private regular file. This check is cheap and it decides
    // whether to open at all.
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Err(SourceRefusal::Missing { path: shown });
    };
    if !meta.is_file() || !privately_owned(&meta) {
        return Err(not_private(shown, ""));
    }
    // OPEN ONCE, THEN VALIDATE AND READ THE SAME HANDLE. Checking a path and
    // then reopening it leaves a window in which the two are different files:
    // the path can be replaced between the two calls, so the checks would
    // describe one file and the bytes come from another. That matters only if
    // the private-directory precondition is already violated, which is exactly
    // when a defence has to hold. The re-check below is against the OPEN
    // handle's own metadata, which no rename can change.
    // Windows opens without following a reparse point, so a link swapped in
    // after the check above is refused by the handle's own type below.
    #[cfg(windows)]
    let mut file =
        crate::private_fs::open_file_read(path).map_err(|_| not_private(shown.clone(), ""))?;
    #[cfg(not(windows))]
    let mut file = std::fs::File::open(path).map_err(|_| not_private(shown.clone(), ""))?;
    let opened = file
        .metadata()
        .map_err(|_| not_private(shown.clone(), ""))?;
    if !opened.is_file() || !privately_owned(&opened) {
        return Err(not_private(shown, ""));
    }
    // Windows has no mode to read: the open handle's DACL is judged instead,
    // and the refusal says which rule failed and how to repair it.
    #[cfg(windows)]
    {
        let found = crate::private_fs::privacy_refusals(&file);
        if !found.is_empty() {
            let detail = windows_remediation(&shown, &found);
            return Err(not_private(shown, &detail));
        }
    }
    let mut bytes = String::new();
    std::io::Read::read_to_string(&mut file, &mut bytes)
        .map_err(|_| not_private(shown.clone(), ""))?;
    serde_json::from_str(&bytes).map_err(|error| SourceRefusal::Unparseable {
        path: shown,
        // Position only. The error's `Display` is never rendered.
        line: error.line(),
        column: error.column(),
    })
}

/// Mode exactly 0600, which within §10.5's threat model also establishes
/// ownership.
///
/// The mode check alone is enough, and that is worth stating rather than
/// reaching for a uid: a file at 0600 is readable ONLY by its owner, so a
/// successful read of one means the reading process owns it. A 0600 file owned
/// by someone else fails the read and refuses as `NotPrivate` — which is the
/// same answer, reached one step later. §10.5 defends against a party who can
/// WRITE into the source directory, and no `getuid` changes that answer.
///
/// Exactly 0600, not "no group or other write": any group or other access at
/// all on a credential file means it is not the file `TokenStorage::save`
/// wrote (`oauth/storage.rs:237-244`), whatever else is true of it.
#[cfg(unix)]
fn privately_owned(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o777 == 0o600
}

/// No mode on Windows: the DACL of the opened handle is judged in
/// `read_legacy_source` instead, so the metadata alone decides nothing here.
#[cfg(not(unix))]
fn privately_owned(_meta: &std::fs::Metadata) -> bool {
    true
}

fn not_private(path: String, detail: &str) -> SourceRefusal {
    #[cfg(windows)]
    {
        SourceRefusal::NotPrivate {
            path,
            detail: detail.to_owned(),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = detail;
        SourceRefusal::NotPrivate { path }
    }
}

/// Which rules failed, and the PowerShell lines that repair them, one per
/// line. Paths are PowerShell single-quoted literals (no expansion), with every
/// single-quote character PowerShell recognises doubled, so no path can end
/// the literal. The gateway account is named by its SID, which stays right in
/// an elevated prompt run as another account. The DACL is replaced in ONE
/// write with a protected DACL holding only the gateway account's grant, so no
/// intermediate state exposes the file; ownership, when foreign, is taken
/// first (that line needs an administrator prompt).
#[cfg(windows)]
fn windows_remediation(path: &str, found: &[crate::private_fs::PrivacyRefusal]) -> String {
    use crate::private_fs::PrivacyRefusal as P;
    use std::fmt::Write as _;
    let Some(me) = crate::private_fs::user_sid_string() else {
        return format!(" ({found:?})");
    };
    let literal: String = path
        .chars()
        .flat_map(|c| {
            let quote = matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}');
            std::iter::once(c).chain(quote.then_some(c))
        })
        .collect();
    let foreign_owner = found.iter().any(|r| matches!(r, P::ForeignOwner(_)));
    // Allowlist first: a line an administrator runs elevated is printed only
    // for a path made of characters that can never end or escape a literal.
    // The quote doubling above is the second layer, not the gate.
    if !runnable_path(path) {
        let mut out = format!(
            " ({found:?}). The path holds characters outside letters, digits, space and \
             \\ : . _ - ( ), so no command is printed for it. To repair it"
        );
        if foreign_owner {
            let _ = write!(
                out,
                ", as an administrator, make the account with SID {me} its owner, then"
            );
        }
        let _ = write!(
            out,
            " open its Security settings, disable inheritance and remove every entry, \
             and grant Full control to the account with SID {me} alone."
        );
        return out;
    }
    let mut out = format!(" ({found:?}). To repair it, run these lines in Windows PowerShell");
    if foreign_owner {
        out.push_str(" as an administrator, because the file has another owner");
    }
    out.push_str(":\n");
    if foreign_owner {
        let _ = writeln!(out, "icacls '{literal}' /setowner '*{me}'");
    }
    let _ = writeln!(
        out,
        "$acl = New-Object System.Security.AccessControl.FileSecurity; \
         $acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;{me})'); \
         (Get-Item -LiteralPath '{literal}').SetAccessControl($acl)"
    );
    out
}

/// The characters a printed, runnable repair line may carry in its path.
#[cfg(windows)]
fn runnable_path(path: &str) -> bool {
    path.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, ' ' | '\\' | ':' | '.' | '_' | '-' | '(' | ')')
    })
}

#[cfg(test)]
#[path = "migration_source_tests.rs"]
mod migration_source_tests;
