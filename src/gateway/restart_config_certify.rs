// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The read-only check task of a config checkpoint: it proves, under both
//! locks, that the file the next boot will read is settled and valid. It
//! never writes a byte and never recovers a journal.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::Certification;
#[cfg(test)]
use super::seams;
use crate::config::Config;
use crate::config::secret_ref::SecretRef;
use crate::config_persistence::journal::v2::abandoned_path;
use crate::config_persistence::lock::journal_pending;
use crate::gateway::restart_floor::FloorFault;
use crate::hashing::sha256_hex;
use crate::identity_grants::journal::resolved;

/// Everything the read-only check task needs; built on the calling thread.
pub(super) struct CheckInput {
    pub(super) attempt: u64,
    /// The configured path as the source names it (Booted(p) -> p; Defaults -> the candidate the search found).
    pub(super) configured: PathBuf,
    /// The config lock's resolved target (`Locked::target`), compared again at step 8.
    pub(super) locked_target: PathBuf,
    /// Whether any registered owed-reload flag was set (`gate.any_owed()`), read when the task starts (step 7).
    pub(super) owed: Arc<dyn Fn() -> bool + Send + Sync>,
    /// The keychain reader captured on the calling thread: under cfg(test) the thread's test reader, if any
    /// (`config::keychain::current_test_keychain()`), which the task installs around the evaluation; in release
    /// the OS reader is per process.
    #[cfg(test)]
    pub(super) test_keychain: Option<Arc<dyn crate::config::keychain::KeychainRead>>,
    #[cfg(test)]
    pub(super) check_hook: Option<seams::CheckHook>,
    #[cfg(test)]
    pub(super) meta_hook: Option<seams::MetaHook>,
}

/// A refusal; the reason is logged, never returned, and names no secret.
fn refuse(why: &str) -> FloorFault {
    tracing::warn!(reason = why, "config checkpoint refused");
    FloorFault::SaveFailed
}

#[cfg(test)]
fn at(input: &CheckInput, step: seams::CheckStep) {
    if let Some(hook) = &input.check_hook {
        hook(input.attempt, step);
    }
}

/// Whether the sidecar exists; any error other than `NotFound` is an error, so the caller fails closed.
fn sidecar_exists(input: &CheckInput) -> io::Result<bool> {
    let sidecar = abandoned_path(&input.locked_target);
    #[cfg(test)]
    if let Some(hook) = &input.meta_hook {
        return hook(&sidecar);
    }
    match std::fs::symlink_metadata(&sidecar) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Step 3: no unsettled write beside the target.
fn settled_write(input: &CheckInput) -> Result<(), FloorFault> {
    if journal_pending(&input.locked_target) {
        return Err(refuse("a replace journal is pending"));
    }
    match sidecar_exists(input) {
        Ok(false) => Ok(()),
        Ok(true) => Err(refuse("an abandoned journal is present")),
        Err(_) => Err(refuse("the abandoned sidecar cannot be examined")),
    }
}

/// Steps 4 and 8: the configured path still resolves to the locked target.
fn still_named(input: &CheckInput) -> Result<(), FloorFault> {
    if resolved(&input.configured) == input.locked_target {
        Ok(())
    } else {
        Err(refuse(
            "the configured path no longer names the locked file",
        ))
    }
}

/// The trusted read of the target; a missing, refused or failed read is a refusal.
fn read_target(target: &Path) -> Result<String, FloorFault> {
    match crate::config::read_config_text(target) {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Err(refuse("the config file is missing")),
        Err(_) => Err(refuse("the config file cannot be read")),
    }
}

/// Whether a secret slot still holds a `keychain:` reference after evaluation.
fn is_unresolved(slot: &str) -> bool {
    matches!(SecretRef::parse(slot), SecretRef::Keychain(_))
}

/// Resolution leaves a keychain read that timed out or failed verbatim, so any
/// slot the loader substitutes that still reads as a reference was not
/// resolved. The metrics token is excluded: its spelling stays by design.
fn has_unresolved_keychain(mut config: Config) -> bool {
    config.secret_slots_mut().any(|slot| is_unresolved(slot))
}

/// Step 6: the startup-equivalent evaluation, then the unresolved-reference check.
fn validate(input: &CheckInput, target: &Path, text: &str) -> Result<(), FloorFault> {
    let evaluate = || Config::load_evaluated_text(target, text);
    #[cfg(test)]
    let evaluated = match input.test_keychain.clone() {
        Some(reader) => crate::config::keychain::with_test_keychain(reader, evaluate),
        None => evaluate(),
    };
    #[cfg(not(test))]
    let evaluated = {
        let _ = input;
        evaluate()
    };
    let evaluated = evaluated.map_err(|_| refuse("the config file is invalid"))?;
    if has_unresolved_keychain(evaluated.config) {
        return Err(refuse("a keychain reference did not resolve"));
    }
    Ok(())
}

/// Step 8: nothing moved and no byte changed while the file was validated.
fn recheck(input: &CheckInput, sha256: &str) -> Result<(), FloorFault> {
    still_named(input)?;
    let again = read_target(&input.locked_target)?;
    if sha256_hex(again.as_bytes()) == sha256 {
        Ok(())
    } else {
        Err(refuse("the config file changed during validation"))
    }
}

/// Steps 3-9 of the checkpoint, synchronous (runs on the attempt's `spawn_blocking`). Calls
/// the check hook at `Start`, `BeforeRead`, `AfterRead` and `AfterValidation` under `cfg(test)`;
/// never writes a byte, never recovers.
///
/// # Errors
///
/// [`FloorFault::SaveFailed`] for an unsettled write, a moved target, a missing, refused
/// or failed read, an invalid file, an unresolved keychain reference, an owed reload, or a
/// change during validation.
pub(super) fn check(input: &CheckInput) -> Result<Certification, FloorFault> {
    #[cfg(test)]
    at(input, seams::CheckStep::Start);
    settled_write(input)?;
    #[cfg(test)]
    at(input, seams::CheckStep::BeforeRead);
    still_named(input)?;
    let text = read_target(&input.locked_target)?;
    #[cfg(test)]
    at(input, seams::CheckStep::AfterRead);
    validate(input, &input.locked_target, &text)?;
    #[cfg(test)]
    at(input, seams::CheckStep::AfterValidation);
    if (input.owed)() {
        return Err(refuse("a reload is owed"));
    }
    let sha256 = sha256_hex(text.as_bytes());
    recheck(input, &sha256)?;
    Ok(Certification {
        sha256,
        revision: input.attempt,
    })
}

/// The Defaults search: the first candidate that exists (`symlink_metadata` Ok) in order.
pub(super) fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|p| std::fs::symlink_metadata(p).is_ok())
        .cloned()
}

/// The four startup fallback paths in order, from startup's own search list.
pub(crate) fn production_candidates() -> Vec<PathBuf> {
    Config::fallback_candidates()
}
