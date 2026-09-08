// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable store operations: commit, compare-and-swap refresh, revoke, fence.
//!
//! A child of `storage` so it reads that module's private helpers — the sealing,
//! associated-data and directory-sync primitives — without widening any
//! visibility. `storage.rs` keeps the readers; the writers live here because
//! together they would pass the file-size cap.
//!
//! Ordering rule, from which everything else follows: **nothing is acknowledged
//! before its durable sequence completes**. The in-memory authority is replaced
//! only after the manifest is on disk, and if anything fails *after* the
//! manifest rename the in-memory copy is discarded rather than served — see
//! `write_manifest`.

#[cfg(unix)]
use super::{
    AUTHORITY_FILE, AUTHORITY_SCHEMA, accepted_basename, authority_aad, seal_bytes, seal_token,
    sync_directory, token_aad,
};
#[cfg(unix)]
use crate::personal_accounts::{
    AccountError, AccountKey, Authority, AuthorityEntry, FenceOutcome, GrantRecord, GrantState,
    GrantVersion, RefreshOutcome, StoreConfig,
};
#[cfg(unix)]
use ring::rand::{SecureRandom as _, SystemRandom};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::path::Path;

// Bounded regressions for runtime review r1. A child of this module because two
// of them must hand the delete paths a pointer a sealed manifest would never
// carry, which only a module inside the store can construct. Every frozen test
// file stays byte-identical.
#[cfg(all(test, unix))]
#[path = "repair_tests.rs"]
mod repair_tests;

/// One named persistence boundary. The fault control is `cfg(test)`-only, so
/// the call sites are too; in a release build this expands to nothing and the
/// nine names cost nothing. A macro rather than a function because the enum it
/// selects does not exist outside test builds, and duplicating that enum here
/// would create two lists that can silently disagree.
#[cfg(unix)]
macro_rules! boundary {
    ($name:ident) => {
        #[cfg(test)]
        crate::personal_accounts::faults::reached(
            crate::personal_accounts::faults::Boundary::$name,
        )?;
    };
}

/// A private scratch name inside the same directory, so the rename is atomic.
#[cfg(unix)]
fn scratch_name(name: &str) -> Result<String, AccountError> {
    Ok(format!(".{name}.{}.tmp", random_hex()?))
}

#[cfg(unix)]
fn random_hex() -> Result<String, AccountError> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AccountError::StorageUnavailable)?;
    Ok(hex::encode(bytes))
}

#[cfg(unix)]
fn open_private(path: &Path) -> Result<fs::File, AccountError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccountError::StorageUnavailable)
}

/// Write one immutable candidate record: create, write, sync, rename, sync the
/// parent. No debris is left behind on any failure.
#[cfg(unix)]
fn persist_record(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), AccountError> {
    let tmp = dir.join(scratch_name(name)?);
    let staged = (|| -> Result<(), AccountError> {
        let mut file = open_private(&tmp)?;
        boundary!(RecordWrite);
        file.write_all(bytes)
            .map_err(|_| AccountError::StorageUnavailable)?;
        boundary!(RecordSync);
        file.sync_all()
            .map_err(|_| AccountError::StorageUnavailable)?;
        drop(file);
        boundary!(RecordRename);
        fs::rename(&tmp, dir.join(name)).map_err(|_| AccountError::StorageUnavailable)?;
        boundary!(RecordParentSync);
        sync_directory(dir)
    })();
    if staged.is_err() {
        // The failure may have come AFTER the rename — the parent sync is the
        // last step — in which case the temporary is already gone and the
        // debris is the candidate itself. Nothing names it: the manifest has
        // not moved, and this basename carries a freshly drawn 128-bit suffix,
        // so it can be no other record.
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(dir.join(name));
    }
    staged
}

/// A record file the manifest no longer names, removed under the SAME rule the
/// read path applies to the same field.
///
/// `accepted_basename` refuses anything that is not `<digest>-<128-bit hex>`,
/// and `storage::connected_record` calls it before a pointer selects a file to
/// open. A delete needs it more, not less: `Path::join` DISCARDS the store
/// directory when given an absolute name, and a `..` segment walks out of it,
/// so an unvalidated pointer chooses any file the gateway user can unlink.
///
/// Failing to remove is not failing to commit — the manifest is already
/// authoritative and the file is merely unreferenced — so nothing is reported.
#[cfg(unix)]
fn remove_unreferenced(config: &StoreConfig, digest: &str, basename: &str) {
    if accepted_basename(basename, digest).is_ok() {
        let _ = fs::remove_file(config.store_dir.join(basename));
    }
}

/// Why a manifest commit did not complete. The variants exist to answer two
/// questions the caller cannot otherwise ask: may my candidate be swept, and is
/// this refusal permanent?
#[cfg(unix)]
enum ManifestRefusal {
    /// The sealed manifest exceeds `max_authority_bytes`. Permanent, and no IO
    /// was attempted, so the category is the CALLER's to choose: only an
    /// operation that adds an entry has a capacity story to tell.
    TooLarge,
    /// Refused before the rename: nothing durable moved, so a candidate written
    /// for this commit was never referenced and may be removed.
    Staged(AccountError),
    /// Refused after the rename: the durable authority is already the new one
    /// and it names the candidate, so removing it would destroy a committed
    /// credential.
    Renamed(AccountError),
}

/// Seal the next authority and check it against the byte cap. No IO at all.
///
/// Separate from the write so a permanent cap refusal happens BEFORE a
/// candidate record exists. An orphan swept afterwards is a worse answer than
/// an orphan never created, and the cap cannot be reached by writing less.
#[cfg(unix)]
fn seal_authority(config: &StoreConfig, next: &Authority) -> Result<String, ManifestRefusal> {
    let key_id = &config.current_key_id;
    let key = config
        .keys
        .get(key_id)
        .ok_or(ManifestRefusal::Staged(AccountError::InvalidConfiguration))?;
    let plaintext = serde_json::to_vec(next)
        .map_err(|_| ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let aad = authority_aad(key_id, &config.instance_id).map_err(ManifestRefusal::Staged)?;
    let envelope = seal_bytes(AUTHORITY_SCHEMA, key_id, key, &aad, plaintext)
        .map_err(ManifestRefusal::Staged)?;
    let encoded = serde_json::to_string(&envelope)
        .map_err(|_| ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    if encoded.len() > config.max_authority_bytes {
        return Err(ManifestRefusal::TooLarge);
    }
    Ok(encoded)
}

/// Write the sealed manifest and publish it in memory. This is the only step
/// that acknowledges anything.
///
/// After the rename the durable authority is the new one. If the parent sync
/// then fails, memory still holds the prior state and can no longer be
/// reconciled without re-reading the disk, so it is POISONED instead: every
/// later operation, `lookup` included, refuses until a restart re-reads the
/// authority. Serving the prior state would keep handing out a credential a
/// durable revoke has already retired, and the next write would rebuild from a
/// stale revision and silently undo a durable change.
#[cfg(unix)]
fn write_manifest(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    encoded: &str,
    next: Authority,
) -> Result<(), ManifestRefusal> {
    let dir = &config.authority_dir;
    let tmp = dir.join(scratch_name(AUTHORITY_FILE).map_err(ManifestRefusal::Staged)?);
    let staged = (|| -> Result<(), AccountError> {
        let mut file = open_private(&tmp)?;
        boundary!(ManifestWrite);
        file.write_all(encoded.as_bytes())
            .map_err(|_| AccountError::StorageUnavailable)?;
        boundary!(ManifestSync);
        file.sync_all()
            .map_err(|_| AccountError::StorageUnavailable)?;
        drop(file);
        boundary!(ManifestRename);
        fs::rename(&tmp, dir.join(AUTHORITY_FILE)).map_err(|_| AccountError::StorageUnavailable)
    })();
    if let Err(error) = staged {
        // Nothing durable moved, so the live authority is still exactly right.
        let _ = fs::remove_file(&tmp);
        return Err(ManifestRefusal::Staged(error));
    }
    #[cfg(test)]
    if let Err(error) = crate::personal_accounts::faults::reached(
        crate::personal_accounts::faults::Boundary::ParentSync,
    ) {
        *slot = None;
        return Err(ManifestRefusal::Renamed(error));
    }
    if let Err(error) = sync_directory(dir) {
        *slot = None;
        return Err(ManifestRefusal::Renamed(error));
    }
    *slot = Some(next);
    Ok(())
}

/// Seal a record, make it the accepted candidate, and publish the manifest that
/// names it. Shared by first consent, re-consent and refresh — they differ only
/// in what they check beforehand.
#[cfg(unix)]
fn stage_publication(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    digest: &str,
    account: &AccountKey,
    record: &GrantRecord,
) -> Result<(), ManifestRefusal> {
    let authority = slot
        .as_ref()
        .ok_or(ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let key_id = &config.current_key_id;
    let key = config
        .keys
        .get(key_id)
        .ok_or(ManifestRefusal::Staged(AccountError::InvalidConfiguration))?;
    // Binds schema, key id, instance, store epoch and the five account fields;
    // sealing also validates the record's own sizes and version formats.
    let aad = token_aad(key_id, &config.instance_id, &authority.store_epoch, account)
        .map_err(ManifestRefusal::Staged)?;
    let envelope = seal_token(key_id, key, &aad, record).map_err(ManifestRefusal::Staged)?;
    let bytes = serde_json::to_string(&envelope)
        .map_err(|_| ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let basename = format!(
        "{digest}-{}.json",
        random_hex().map_err(ManifestRefusal::Staged)?
    );
    let previous = authority
        .entries
        .get(digest)
        .and_then(|entry| entry.record_basename.clone());
    let mut next = authority.clone();
    next.commit_revision = next
        .commit_revision
        .checked_add(1)
        .ok_or(ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let legacy_migration = next
        .entries
        .get(digest)
        .and_then(|entry| entry.legacy_migration.clone());
    next.entries.insert(
        digest.to_owned(),
        AuthorityEntry {
            generation: record.generation.clone(),
            token_revision: record.token_revision,
            authorization_epoch: record.authorization_epoch,
            descriptor_revision: record.descriptor_revision.clone(),
            record_basename: Some(basename.clone()),
            record_sha256: Some(hex::encode(Sha256::digest(bytes.as_bytes()))),
            state: GrantState::Connected,
            legacy_migration,
        },
    );

    // Sealed and bound-checked BEFORE the candidate exists, so a manifest that
    // can never fit refuses without leaving a record file behind.
    let encoded = seal_authority(config, &next)?;
    persist_record(&config.store_dir, &basename, bytes.as_bytes())
        .map_err(ManifestRefusal::Staged)?;
    // Everything from here to the manifest rename shares one fate: the candidate
    // is on disk and nothing names it yet. Closing over the whole window rather
    // than each step is what stops a later boundary being added outside the
    // sweep — which is exactly how `CommitCheckpoint` escaped the first attempt.
    let committed = (|| -> Result<(), ManifestRefusal> {
        // Spelled out rather than `boundary!`, for the same reason `ParentSync`
        // is: this site needs the refusal category, which the macro cannot give.
        #[cfg(test)]
        crate::personal_accounts::faults::reached(
            crate::personal_accounts::faults::Boundary::CommitCheckpoint,
        )
        .map_err(ManifestRefusal::Staged)?;
        write_manifest(config, slot, &encoded, next)
    })();
    if let Err(refusal) = committed {
        // Only a failure AFTER the rename leaves the candidate durably named,
        // and that one must survive: removing it would destroy a committed
        // credential the manifest already points at.
        if !matches!(refusal, ManifestRefusal::Renamed(_)) {
            remove_unreferenced(config, digest, &basename);
        }
        return Err(refusal);
    }

    // Only now, and never before: the superseded candidate is unreferenced.
    if let Some(old) = previous.filter(|old| *old != basename) {
        remove_unreferenced(config, digest, &old);
    }
    Ok(())
}

/// Publish as every caller but `commit_grant` sees it. Only that one operation
/// adds an entry, so only it may translate a manifest that no longer fits into
/// a capacity answer; everyone else gets the storage category. Keeping the two
/// apart is what stops revoke and the reconnect fence reporting a capacity
/// problem they cannot have.
#[cfg(unix)]
fn publish(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    digest: &str,
    account: &AccountKey,
    record: &GrantRecord,
) -> Result<(), AccountError> {
    stage_publication(config, slot, digest, account, record).map_err(refusal_as_fault)
}

/// Replace only the manifest, keeping the four version fields the entry already
/// committed. Used by the two state changes that write no new record.
///
/// Returns a record name ONLY when this transition cleared the pointer to it.
/// The reconnect fence deliberately leaves `record_basename` intact — the
/// manifest still names that file and the credential is still live — so a
/// return value meaning "the entry used to point here" would be an invitation
/// to delete a referenced record. What comes back means *unreferenced now*.
#[cfg(unix)]
fn restate(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    digest: &str,
    state: GrantState,
) -> Result<Option<String>, ManifestRefusal> {
    let authority = slot
        .as_ref()
        .ok_or(ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let mut next = authority.clone();
    next.commit_revision = next
        .commit_revision
        .checked_add(1)
        .ok_or(ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let entry = next
        .entries
        .get_mut(digest)
        .ok_or(ManifestRefusal::Staged(AccountError::StorageUnavailable))?;
    let retired = entry
        .record_basename
        .clone()
        .filter(|_| matches!(state, GrantState::Revoked));
    if matches!(state, GrantState::Revoked) {
        // A tombstone needs no ciphertext pointer; its version is what it
        // discloses, and that is retained.
        entry.record_basename = None;
        entry.record_sha256 = None;
    }
    entry.state = state;
    let encoded = seal_authority(config, &next)?;
    write_manifest(config, slot, &encoded, next)?;
    Ok(retired)
}

#[cfg(unix)]
pub(in crate::personal_accounts) fn commit_grant(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    account: &AccountKey,
    record: &GrantRecord,
) -> Result<(), AccountError> {
    let digest = account.digest()?;
    let authority = slot.as_ref().ok_or(AccountError::StorageUnavailable)?;
    // An account that already holds a slot adds none, so re-consent into a full
    // store is allowed. Tombstones count, because they are retained entries.
    let adds_entry = !authority.entries.contains_key(&digest);
    if adds_entry && authority.entries.len() >= config.max_entries {
        return Err(AccountError::CapacityExhausted);
    }
    // The only operation that CAN add an entry — but this call only does when
    // the digest is new, and the same condition governs both answers. Admitting
    // an entry into a manifest that no longer fits is capacity. Overwriting a
    // slot the account already holds is not: the caller is asking for no room,
    // so freeing some would not help it, and `CapacityExhausted` would send it
    // to evict grants over what is a store fault.
    stage_publication(config, slot, &digest, account, record).map_err(|refusal| match refusal {
        ManifestRefusal::TooLarge if adds_entry => AccountError::CapacityExhausted,
        other => refusal_as_fault(other),
    })
}

#[cfg(unix)]
pub(in crate::personal_accounts) fn refresh_tokens(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    account: &AccountKey,
    expected: &GrantVersion,
    record: &GrantRecord,
) -> Result<RefreshOutcome, AccountError> {
    let digest = account.digest()?;
    // The proposal is checked against the caller's OWN expectation first,
    // because that contradiction is a caller defect however the race turned
    // out, and it needs no entry to detect. A refresh replaces tokens: it may
    // not move the grant to a different generation or descriptor, may not
    // reuse or lower a token revision that has already been committed, and may
    // not walk an authorization epoch backwards. Reporting this as `Rejected`
    // would tell the caller it lost a race worth retrying, and it never is.
    if record.generation != expected.generation
        || record.descriptor_revision != expected.descriptor_revision
        || record.token_revision <= expected.token_revision
        || record.authorization_epoch < expected.authorization_epoch
    {
        return Err(AccountError::InvalidGrantVersion);
    }
    let authority = slot.as_ref().ok_or(AccountError::StorageUnavailable)?;
    let Some(entry) = authority.entries.get(&digest) else {
        return Ok(RefreshOutcome::Rejected);
    };
    // The whole version, not just the generation: two callers that snapshot the
    // same grant are separated only by the token revision, and the loser of
    // that race must not roll an already-rotated token back.
    let holds = matches!(entry.state, GrantState::Connected)
        && entry.generation == expected.generation
        && entry.token_revision == expected.token_revision
        && entry.authorization_epoch == expected.authorization_epoch
        && entry.descriptor_revision == expected.descriptor_revision;
    if !holds {
        // Nothing is written, so a lost race costs no IO at all.
        return Ok(RefreshOutcome::Rejected);
    }
    // A refresh occupies a slot that already exists, so it never adds capacity
    // pressure and a manifest that no longer fits is a storage fault here.
    publish(config, slot, &digest, account, record)?;
    Ok(RefreshOutcome::Committed)
}

/// The category for every operation that adds no entry: an authority that no
/// longer fits is not a capacity answer they can honestly give.
#[cfg(unix)]
fn refusal_as_fault(refusal: ManifestRefusal) -> AccountError {
    match refusal {
        ManifestRefusal::TooLarge => AccountError::StorageUnavailable,
        ManifestRefusal::Staged(error) | ManifestRefusal::Renamed(error) => error,
    }
}

#[cfg(unix)]
pub(in crate::personal_accounts) fn revoke(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    account: &AccountKey,
) -> Result<(), AccountError> {
    let digest = account.digest()?;
    let authority = slot.as_ref().ok_or(AccountError::StorageUnavailable)?;
    match authority.entries.get(&digest) {
        // Nothing was ever committed, so there is nothing to retire.
        None => return Ok(()),
        // Already tombstoned: idempotent, and no IO.
        Some(entry) if matches!(entry.state, GrantState::Revoked) => return Ok(()),
        Some(_) => {}
    }
    let retired = restate(config, slot, &digest, GrantState::Revoked).map_err(refusal_as_fault)?;
    // Token bytes go only after the authority says they are unreferenced.
    if let Some(basename) = retired {
        remove_unreferenced(config, &digest, &basename);
    }
    Ok(())
}

#[cfg(unix)]
pub(in crate::personal_accounts) fn mark_reconnect_required(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    account: &AccountKey,
    descriptor_revision: &str,
) -> Result<(), AccountError> {
    let digest = account.digest()?;
    let authority = slot.as_ref().ok_or(AccountError::StorageUnavailable)?;
    match authority.entries.get(&digest) {
        None => return Ok(()),
        // Nothing moved, so nothing is fenced. Without this a blanket fence
        // would be indistinguishable from a correct one.
        Some(entry) if entry.descriptor_revision == descriptor_revision => return Ok(()),
        // A tombstone is already terminal; it is not re-fenced.
        Some(entry) if matches!(entry.state, GrantState::Revoked) => return Ok(()),
        Some(_) => {}
    }
    // The fence keeps the record pointer, so `restate` returns nothing to
    // remove — the credential stays on disk and stays named by the manifest.
    restate(config, slot, &digest, GrantState::ReconnectRequired).map_err(refusal_as_fault)?;
    Ok(())
}

/// Fence the exact grant a refresh provider rejected, and only that one.
///
/// The sibling above answers a DESCRIPTOR move, and deliberately does nothing
/// when the descriptor is unchanged — a provider rejecting a token moves no
/// descriptor, so that guard can never fence it. This is the other reason to
/// fence, and it is a compare-and-swap: the whole expected version must still
/// be the live one, exactly as `refresh_tokens` requires before it writes.
///
/// Superseded is an ordinary refusal that writes nothing. A grant re-authorized
/// while the provider was answering is a DIFFERENT grant, and tombstoning it
/// would disconnect a user who has just finished consenting.
///
/// The four version fields are untouched: `restate` replaces the state and
/// nothing else, so a fenced entry discloses the same version it committed.
#[cfg(unix)]
pub(in crate::personal_accounts) fn fence_expected_version(
    config: &StoreConfig,
    slot: &mut Option<Authority>,
    account: &AccountKey,
    expected: &GrantVersion,
) -> Result<FenceOutcome, AccountError> {
    let digest = account.digest()?;
    let authority = slot.as_ref().ok_or(AccountError::StorageUnavailable)?;
    let Some(entry) = authority.entries.get(&digest) else {
        return Ok(FenceOutcome::Superseded);
    };
    let holds = matches!(entry.state, GrantState::Connected)
        && entry.generation == expected.generation
        && entry.token_revision == expected.token_revision
        && entry.authorization_epoch == expected.authorization_epoch
        && entry.descriptor_revision == expected.descriptor_revision;
    if !holds {
        // Nothing is written, so losing this race costs no IO at all.
        return Ok(FenceOutcome::Superseded);
    }
    // Keeps the record pointer, like the descriptor fence: the credential stays
    // named by the manifest, so `restate` reports nothing to remove.
    restate(config, slot, &digest, GrantState::ReconnectRequired).map_err(refusal_as_fault)?;
    Ok(FenceOutcome::Fenced)
}

#[cfg(not(unix))]
use crate::personal_accounts::{
    AccountError, AccountKey, Authority, FenceOutcome, GrantRecord, GrantVersion, RefreshOutcome,
    StoreConfig,
};

#[cfg(not(unix))]
pub(in crate::personal_accounts) fn fence_expected_version(
    _config: &StoreConfig,
    _slot: &mut Option<Authority>,
    _account: &AccountKey,
    _expected: &GrantVersion,
) -> Result<FenceOutcome, AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(in crate::personal_accounts) fn commit_grant(
    _config: &StoreConfig,
    _slot: &mut Option<Authority>,
    _account: &AccountKey,
    _record: &GrantRecord,
) -> Result<(), AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(in crate::personal_accounts) fn refresh_tokens(
    _config: &StoreConfig,
    _slot: &mut Option<Authority>,
    _account: &AccountKey,
    _expected: &GrantVersion,
    _record: &GrantRecord,
) -> Result<RefreshOutcome, AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(in crate::personal_accounts) fn revoke(
    _config: &StoreConfig,
    _slot: &mut Option<Authority>,
    _account: &AccountKey,
) -> Result<(), AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(in crate::personal_accounts) fn mark_reconnect_required(
    _config: &StoreConfig,
    _slot: &mut Option<Authority>,
    _account: &AccountKey,
    _descriptor_revision: &str,
) -> Result<(), AccountError> {
    Err(AccountError::InvalidConfiguration)
}
