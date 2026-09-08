// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Authenticated envelopes and durable authority custody.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};

use super::{
    AccountError, AccountKey, AccountLookup, Authority, GrantRecord, PersonalAccountStore,
    StoreConfig,
};
#[cfg(unix)]
use super::{AuthorityEntry, GrantState, GrantVersion};
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::path::{Component, Path};

// The durable writers. A child module so it reads these private helpers
// without widening any visibility; together the two would pass the file cap.
#[path = "commit.rs"]
pub(super) mod commit;

const TOKEN_SCHEMA: &str = "personal_accounts.v1";
const TOKEN_DOMAIN: &[u8] = b"mcp-gateway/account-token-aad/v1";
const RECORD_BYTES: usize = 262_144;
#[cfg(unix)]
const AUTHORITY_SCHEMA: &str = "personal_accounts.authority.v1";
#[cfg(unix)]
const AUTHORITY_FILE: &str = "authority.json";
#[cfg(unix)]
const LOCK_FILE: &str = ".personal-accounts.lock";

/// Versioned ciphertext envelope; no credential appears in outer JSON fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenEnvelope {
    pub(super) schema_version: String,
    pub(super) key_id: String,
    pub(super) nonce: String,
    pub(super) ciphertext: String,
}

pub(super) fn encode_fields(domain: &[u8], fields: &[&str]) -> Result<Vec<u8>, AccountError> {
    let mut encoded = domain.to_vec();
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| AccountError::InvalidAccountKey)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    Ok(encoded)
}

/// Encode the exact record-domain, store-instance, epoch and account binding.
pub(super) fn token_aad(
    key_id: &str,
    instance_id: &str,
    store_epoch: &str,
    account: &AccountKey,
) -> Result<Vec<u8>, AccountError> {
    if key_id.is_empty() || instance_id.is_empty() || store_epoch.is_empty() {
        return Err(AccountError::InvalidConfiguration);
    }
    let fields = account.fields()?;
    encode_fields(
        TOKEN_DOMAIN,
        &[
            TOKEN_SCHEMA,
            key_id,
            instance_id,
            store_epoch,
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
        ],
    )
}

/// Encrypt with a fresh nonce under the supplied, fully bound associated data.
pub(super) fn seal_token(
    key_id: &str,
    key: &[u8],
    aad: &[u8],
    record: &GrantRecord,
) -> Result<TokenEnvelope, AccountError> {
    check_token_header(key_id, aad)?;
    validate_record(record)?;
    let plaintext = serde_json::to_vec(record).map_err(|_| AccountError::NotAuthentic)?;
    if plaintext.len() > RECORD_BYTES {
        return Err(AccountError::NotAuthentic);
    }
    seal_bytes(TOKEN_SCHEMA, key_id, key, aad, plaintext)
}

/// Authenticate the full envelope and associated data before returning a record.
pub(super) fn open_token(
    key: &[u8],
    aad: &[u8],
    envelope: &TokenEnvelope,
) -> Result<GrantRecord, AccountError> {
    check_token_header(&envelope.key_id, aad)?;
    let plaintext = open_bytes(TOKEN_SCHEMA, key, aad, envelope, RECORD_BYTES)?;
    let record = serde_json::from_slice(&plaintext).map_err(|_| AccountError::NotAuthentic)?;
    validate_record(&record)?;
    Ok(record)
}

fn check_token_header(key_id: &str, aad: &[u8]) -> Result<(), AccountError> {
    let prefix = encode_fields(TOKEN_DOMAIN, &[TOKEN_SCHEMA, key_id])?;
    // The caller builds the remaining context with token_aad. Outer metadata
    // must agree with that bound header even when the supplied key is identical.
    if key_id.is_empty() || !aad.starts_with(&prefix) || aad.len() == prefix.len() {
        return Err(AccountError::NotAuthentic);
    }
    Ok(())
}

fn validate_record(record: &GrantRecord) -> Result<(), AccountError> {
    let valid_token = |token: &str| !token.is_empty() && token.len() <= 65_536;
    if !valid_token(&record.access_token)
        || record
            .refresh_token
            .as_deref()
            .is_some_and(|token| !valid_token(token))
        || !lower_hex(&record.generation, 32)
        || !lower_hex(&record.descriptor_revision, 64)
        || record.token_revision == 0
        || record.authorization_epoch == 0
        || record.scopes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(AccountError::NotAuthentic);
    }
    // Expired tokens remain valid custody data: the service needs their refresh
    // token. Expiry determines dispatch/refresh, never whether storage exists.
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn seal_bytes(
    schema: &str,
    key_id: &str,
    key: &[u8],
    aad: &[u8],
    mut plaintext: Vec<u8>,
) -> Result<TokenEnvelope, AccountError> {
    let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| AccountError::InvalidConfiguration)?;
    let key = LessSafeKey::new(key);
    let mut nonce = [0_u8; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| AccountError::StorageUnavailable)?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut plaintext,
    )
    .map_err(|_| AccountError::StorageUnavailable)?;
    Ok(TokenEnvelope {
        schema_version: schema.into(),
        key_id: key_id.into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(plaintext),
    })
}

fn open_bytes(
    schema: &str,
    key: &[u8],
    aad: &[u8],
    envelope: &TokenEnvelope,
    plaintext_limit: usize,
) -> Result<Vec<u8>, AccountError> {
    let ciphertext_limit = plaintext_limit
        .checked_add(16)
        .ok_or(AccountError::InvalidConfiguration)?;
    let encoded_limit = ciphertext_limit
        .checked_add(2)
        .and_then(|size| (size / 3).checked_mul(4))
        .ok_or(AccountError::InvalidConfiguration)?;
    if envelope.schema_version != schema
        || envelope.key_id.is_empty()
        || envelope.nonce.len() != 16
        || envelope.ciphertext.len() > encoded_limit
    {
        return Err(AccountError::NotAuthentic);
    }
    let nonce: [u8; 12] = STANDARD
        .decode(&envelope.nonce)
        .map_err(|_| AccountError::NotAuthentic)?
        .try_into()
        .map_err(|_| AccountError::NotAuthentic)?;
    let mut ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| AccountError::NotAuthentic)?;
    if ciphertext.len() < 16 || ciphertext.len() > ciphertext_limit {
        return Err(AccountError::NotAuthentic);
    }
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| AccountError::NotAuthentic)?,
    );
    let opened = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| AccountError::NotAuthentic)?;
    Ok(opened.to_vec())
}

#[cfg(unix)]
fn validate_config(config: &StoreConfig) -> Result<(), AccountError> {
    if config.instance_id.is_empty()
        || config.current_key_id.is_empty()
        || !config.keys.contains_key(&config.current_key_id)
        || config
            .keys
            .iter()
            .any(|(id, key)| id.is_empty() || key.len() != 32)
        || config.max_entries == 0
        || config.max_authority_bytes == 0
        || config
            .max_authority_bytes
            .checked_add(16)
            .and_then(|size| size.checked_mul(4))
            .is_none()
        || config.store_dir.starts_with(&config.authority_dir)
        || config.authority_dir.starts_with(&config.store_dir)
    {
        return Err(AccountError::InvalidConfiguration);
    }
    validate_path(&config.store_dir)?;
    validate_path(&config.authority_dir)
}

#[cfg(unix)]
fn validate_path(path: &Path) -> Result<(), AccountError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(AccountError::InvalidConfiguration);
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err(AccountError::InvalidConfiguration),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AccountError::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<(), AccountError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::symlink_metadata(path).map_err(|_| AccountError::StorageUnavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AccountError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(unix)]
fn create_directory(path: &Path) -> Result<(), AccountError> {
    use std::os::unix::fs::DirBuilderExt as _;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => return Ok(()),
        Ok(_) => return Err(AccountError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(AccountError::StorageUnavailable),
    }
    let parent = path.parent().ok_or(AccountError::InvalidConfiguration)?;
    create_directory(parent)?;
    let result = fs::DirBuilder::new().mode(0o700).create(path);
    if let Err(error) = result {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(AccountError::StorageUnavailable);
        }
    }
    private_directory(path)?;
    sync_directory(parent)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), AccountError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| AccountError::StorageUnavailable)
}

#[cfg(unix)]
fn claim_store(
    config: &StoreConfig,
) -> Result<
    (
        crate::fs_lock::ExclusiveFileLock,
        crate::fs_lock::ExclusiveFileLock,
    ),
    AccountError,
> {
    let record_lock =
        crate::fs_lock::ExclusiveFileLock::try_acquire(&config.store_dir.join(LOCK_FILE))
            .map_err(|_| AccountError::StorageUnavailable)?;
    let authority_lock =
        crate::fs_lock::ExclusiveFileLock::try_acquire(&config.authority_dir.join(LOCK_FILE))
            .map_err(|_| AccountError::StorageUnavailable)?;
    Ok((record_lock, authority_lock))
}

#[cfg(unix)]
fn empty_authority(config: &StoreConfig) -> Result<Authority, AccountError> {
    let mut epoch = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut epoch)
        .map_err(|_| AccountError::StorageUnavailable)?;
    Ok(Authority {
        instance_id: config.instance_id.clone(),
        store_epoch: hex::encode(epoch),
        commit_revision: 0,
        entries: std::collections::BTreeMap::new(),
    })
}

#[cfg(unix)]
fn authority_aad(key_id: &str, instance_id: &str) -> Result<Vec<u8>, AccountError> {
    encode_fields(
        b"mcp-gateway/account-authority-aad/v1",
        &[AUTHORITY_SCHEMA, key_id, instance_id],
    )
}

#[cfg(unix)]
fn require_empty(path: &Path) -> Result<(), AccountError> {
    for entry in fs::read_dir(path).map_err(|_| AccountError::StorageUnavailable)? {
        let entry = entry.map_err(|_| AccountError::StorageUnavailable)?;
        if entry.file_name() != LOCK_FILE {
            return Err(AccountError::StorageUnavailable);
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn initialize(config: StoreConfig) -> Result<PersonalAccountStore, AccountError> {
    validate_config(&config)?;
    create_directory(&config.store_dir)?;
    create_directory(&config.authority_dir)?;
    private_directory(&config.store_dir)?;
    private_directory(&config.authority_dir)?;
    let (record_lock, authority_lock) = claim_store(&config)?;
    require_empty(&config.store_dir)?;
    require_empty(&config.authority_dir)?;
    let authority = empty_authority(&config)?;
    let plaintext = serde_json::to_vec(&authority).map_err(|_| AccountError::StorageUnavailable)?;
    let aad = authority_aad(&config.current_key_id, &config.instance_id)?;
    let envelope = seal_bytes(
        AUTHORITY_SCHEMA,
        &config.current_key_id,
        &config.keys[&config.current_key_id],
        &aad,
        plaintext,
    )?;
    let encoded = serde_json::to_string(&envelope).map_err(|_| AccountError::StorageUnavailable)?;
    if encoded.len() > config.max_authority_bytes {
        return Err(AccountError::StorageUnavailable);
    }
    crate::config_persistence::write_config_text(
        &config.authority_dir.join(AUTHORITY_FILE),
        &encoded,
    )
    .map_err(|_| AccountError::StorageUnavailable)?;
    sync_directory(&config.authority_dir)?;
    Ok(PersonalAccountStore {
        config,
        authority: parking_lot::Mutex::new(Some(authority)),
        _record_lock: record_lock,
        _authority_lock: authority_lock,
    })
}

#[cfg(unix)]
pub(super) fn open(config: StoreConfig) -> Result<PersonalAccountStore, AccountError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    validate_config(&config)?;
    private_directory(&config.store_dir)?;
    private_directory(&config.authority_dir)?;
    // Acquire both lifetime locks before inspecting authority. Open never creates
    // an epoch or substitutes empty authority for missing or invalid state.
    let (record_lock, authority_lock) = claim_store(&config)?;
    // A FIFO must reach the regular-file check instead of blocking inside open.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(config.authority_dir.join(AUTHORITY_FILE))
        .map_err(|_| AccountError::StorageUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| AccountError::StorageUnavailable)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len()
            > u64::try_from(config.max_authority_bytes)
                .map_err(|_| AccountError::InvalidConfiguration)?
    {
        return Err(AccountError::StorageUnavailable);
    }
    let mut encoded = Vec::new();
    file.take(
        u64::try_from(config.max_authority_bytes)
            .map_err(|_| AccountError::InvalidConfiguration)?
            + 1,
    )
    .read_to_end(&mut encoded)
    .map_err(|_| AccountError::StorageUnavailable)?;
    if encoded.len() > config.max_authority_bytes {
        return Err(AccountError::StorageUnavailable);
    }
    let envelope: TokenEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| AccountError::NotAuthentic)?;
    let key = config
        .keys
        .get(&envelope.key_id)
        .ok_or(AccountError::NotAuthentic)?;
    let aad = authority_aad(&envelope.key_id, &config.instance_id)?;
    let plaintext = open_bytes(
        AUTHORITY_SCHEMA,
        key,
        &aad,
        &envelope,
        config.max_authority_bytes,
    )?;
    let authority: Authority =
        serde_json::from_slice(&plaintext).map_err(|_| AccountError::NotAuthentic)?;
    if authority.instance_id != config.instance_id
        || !lower_hex(&authority.store_epoch, 32)
        || authority.entries.len() > config.max_entries
    {
        return Err(AccountError::NotAuthentic);
    }
    Ok(PersonalAccountStore {
        config,
        authority: parking_lot::Mutex::new(Some(authority)),
        _record_lock: record_lock,
        _authority_lock: authority_lock,
    })
}

/// The authenticated manifest entry's own version, validated before any use.
/// Its four fields are what a tombstone discloses, so they are checked whether
/// or not a ciphertext pointer survives.
#[cfg(unix)]
fn entry_version(entry: &AuthorityEntry) -> Result<GrantVersion, AccountError> {
    if !lower_hex(&entry.generation, 32)
        || !lower_hex(&entry.descriptor_revision, 64)
        || entry.token_revision == 0
        || entry.authorization_epoch == 0
    {
        return Err(AccountError::NotAuthentic);
    }
    Ok(GrantVersion {
        generation: entry.generation.clone(),
        token_revision: entry.token_revision,
        authorization_epoch: entry.authorization_epoch,
        descriptor_revision: entry.descriptor_revision.clone(),
    })
}

/// Accept only `<this account's digest>-<128-bit lowercase hex>.json`. Splitting
/// on the first hyphen means any path, dot segment or foreign digest fails the
/// equality below, so an authenticated pointer is refused before it selects a
/// file rather than after opening one.
#[cfg(unix)]
fn accepted_basename(basename: &str, digest: &str) -> Result<(), AccountError> {
    let named = basename
        .strip_suffix(".json")
        .and_then(|stem| stem.split_once('-'))
        .is_some_and(|(account, suffix)| account == digest && lower_hex(suffix, 32));
    if !named {
        return Err(AccountError::NotAuthentic);
    }
    Ok(())
}

/// Bound the read itself. The authoritative ciphertext bound stays in
/// `open_bytes`; this exists only to stop an unbounded read.
///
/// The overhead is MEASURED, never allowed for: serialize the widest envelope
/// this configuration can produce — real schema, a real encoded nonce, empty
/// ciphertext — once per configured key ID, and keep the largest. Escaping is
/// therefore counted as the serializer actually renders it, and a retained key
/// is bounded exactly like the current one, because any configured key may have
/// sealed the record being read and its id is not known until the file is open.
/// Nothing here restricts a key id; a longer one simply raises the bound.
#[cfg(unix)]
fn record_file_limit(config: &StoreConfig) -> Result<usize, AccountError> {
    let ciphertext = RECORD_BYTES
        .checked_add(16 + 2)
        .and_then(|size| (size / 3).checked_mul(4))
        .ok_or(AccountError::InvalidConfiguration)?;
    let mut frame = 0;
    for key_id in config.keys.keys() {
        let widest = TokenEnvelope {
            schema_version: TOKEN_SCHEMA.to_owned(),
            key_id: key_id.clone(),
            nonce: STANDARD.encode([0_u8; 12]),
            ciphertext: String::new(),
        };
        let width = serde_json::to_string(&widest)
            .map_err(|_| AccountError::InvalidConfiguration)?
            .len();
        frame = frame.max(width);
    }
    // Exact, not generous: a compact serializer cannot exceed this, and any
    // writer that adds framing of its own must be bounded against it too.
    frame
        .checked_add(ciphertext)
        .ok_or(AccountError::InvalidConfiguration)
}

/// Read one accepted candidate. A symlink, FIFO, directory, group- or
/// world-readable mode, oversize file or missing file is a physical-storage
/// failure. None of them is absence, and none may block the caller.
#[cfg(unix)]
fn read_record(config: &StoreConfig, path: &Path) -> Result<Vec<u8>, AccountError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let limit = record_file_limit(config)?;
    let bound = u64::try_from(limit).map_err(|_| AccountError::InvalidConfiguration)?;
    // A FIFO must reach the regular-file check instead of blocking inside open.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(path)
        .map_err(|_| AccountError::StorageUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| AccountError::StorageUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > bound {
        return Err(AccountError::StorageUnavailable);
    }
    let mut encoded = Vec::new();
    file.take(bound + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| AccountError::StorageUnavailable)?;
    if encoded.len() > limit {
        return Err(AccountError::StorageUnavailable);
    }
    Ok(encoded)
}

/// Open the one accepted candidate this entry names, and no other file. The
/// manifest's exact envelope digest is checked before decryption, and the
/// decrypted record must agree with the manifest's version afterwards.
#[cfg(unix)]
fn connected_record(
    config: &StoreConfig,
    authority: &Authority,
    entry: &AuthorityEntry,
    version: &GrantVersion,
    digest: &str,
    account: &AccountKey,
) -> Result<GrantRecord, AccountError> {
    let (basename, accepted) = entry
        .record_basename
        .as_deref()
        .zip(entry.record_sha256.as_deref())
        .ok_or(AccountError::NotAuthentic)?;
    accepted_basename(basename, digest)?;
    let encoded = read_record(config, &config.store_dir.join(basename))?;
    if hex::encode(Sha256::digest(&encoded)) != accepted {
        return Err(AccountError::NotAuthentic);
    }
    let envelope: TokenEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| AccountError::NotAuthentic)?;
    // Any configured decryption key may have sealed this record, so rotation
    // keeps old candidates readable; an unconfigured key id never opens one.
    let key = config
        .keys
        .get(&envelope.key_id)
        .ok_or(AccountError::NotAuthentic)?;
    let aad = token_aad(
        &envelope.key_id,
        &config.instance_id,
        &authority.store_epoch,
        account,
    )?;
    let record = open_token(key, &aad, &envelope)?;
    if record.generation != version.generation
        || record.token_revision != version.token_revision
        || record.authorization_epoch != version.authorization_epoch
        || record.descriptor_revision != version.descriptor_revision
    {
        return Err(AccountError::NotAuthentic);
    }
    Ok(record)
}

/// Resolve one exact account against the authenticated manifest. A missing
/// entry is the only absence: retained, orphaned or replayed ciphertext never
/// grants authority, and nothing here initializes, adopts or searches.
#[cfg(unix)]
pub(super) fn lookup(
    config: &StoreConfig,
    authority: &Authority,
    digest: &str,
    account: &AccountKey,
) -> Result<AccountLookup, AccountError> {
    let Some(entry) = authority.entries.get(digest) else {
        return Ok(AccountLookup::Absent);
    };
    let version = entry_version(entry)?;
    match entry.state {
        // A tombstone is authoritative on its own. It needs no ciphertext
        // pointer, so a retained, deleted or corrupt record cannot change it.
        GrantState::Revoked => Ok(AccountLookup::Revoked(version)),
        GrantState::ReconnectRequired => Ok(AccountLookup::ReconnectRequired(version)),
        GrantState::Connected => {
            connected_record(config, authority, entry, &version, digest, account)
                .map(AccountLookup::Connected)
        }
    }
}

#[cfg(not(unix))]
pub(super) fn lookup(
    _config: &StoreConfig,
    _authority: &Authority,
    _digest: &str,
    _account: &AccountKey,
) -> Result<AccountLookup, AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(super) fn initialize(_config: StoreConfig) -> Result<PersonalAccountStore, AccountError> {
    Err(AccountError::InvalidConfiguration)
}

#[cfg(not(unix))]
pub(super) fn open(_config: StoreConfig) -> Result<PersonalAccountStore, AccountError> {
    Err(AccountError::InvalidConfiguration)
}
