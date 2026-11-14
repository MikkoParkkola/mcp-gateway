// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unused entries: a generated suffix in a source, or a `file:` target, names one (ADR-028 rule 6).
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::{SecretStore, StoreError, StoreKind, UnusedEntry, Vault};
use crate::config_persistence::lock::{NotLocked, lock_file_blocking};
const CONFIG_UNREAD: &str = "the config could not be read";
const CONFIG_PARSE: &str = "the config did not parse";
const CAP_UNREAD: &str = "a capability file could not be read";
const CAP_TOO_DEEP: &str = "a capability directory is nested deeper than the scan reads";
/// How deep a capability directory is walked; anything deeper refuses.
const CAP_DEPTH: usize = 16;
const FILE_STAT: &str = "a file reference could not be stat'ed";
const INDEX_UNREAD: &str = "the secrets index could not be read";
const LINKS_UNVERIFIED: &str =
    "files-store entries cannot be deleted here: this platform cannot check the file's links";
/// Every source that can name an entry, read fresh for each check.
pub(crate) struct NamingSources {
    /// The selected `gateway.yaml`.
    pub(crate) config: PathBuf,
    /// Every env file the live overlay was built from.
    pub(crate) env_files: Vec<PathBuf>,
    /// The values the live overlay parsed from those env files.
    pub(crate) env_values: Vec<String>,
    /// Process environment values (the overlay falls through to them).
    pub(crate) process_env: Vec<OsString>,
    /// Capability directories, walked recursively.
    pub(crate) capability_dirs: Vec<PathBuf>,
    /// Where the files store keeps its entries: the directory the vault and the
    /// files store use, which can differ from the config's resolved directory.
    pub(crate) entries_dir: PathBuf,
}
/// Whether an entry is named, with the digest of every source read when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Naming {
    Named,
    NotNamed { digest: String },
}
/// Why a delete did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeleteRefused {
    BadName,
    NotListed,
    StoreMismatch,
    Named,
    Pending,
    Busy,
    TimedOut,
    Failed(String),
}
/// What a delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deleted {
    Removed,
    AlreadyGone,
}
/// `name` is `mcp-gateway.<slug>.<unix_ms>.<16 lowercase hex>`, as `fresh_name` makes it.
pub(crate) fn is_generated_name(name: &str) -> bool {
    suffix_of(name).is_some()
}
/// The generated 16-hex suffix of a well-shaped name.
pub(crate) fn suffix_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("mcp-gateway.")?;
    let mut parts = rest.split('.');
    let slug = parts.next()?;
    let unix_ms = parts.next()?;
    let suffix = parts.next()?;
    let slug_ok = (1..=40).contains(&slug.len())
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    let unix_ok =
        (1..=20).contains(&unix_ms.len()) && unix_ms.bytes().all(|byte| byte.is_ascii_digit());
    let suffix_ok = suffix.len() == 16
        && suffix
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if parts.next().is_some() || !slug_ok || !unix_ok || !suffix_ok {
        return None;
    }
    Some(suffix)
}
/// Whether any source names `name`. An unreadable source is an error, never "not named".
pub(crate) fn naming(sources: &NamingSources, name: &str) -> Result<Naming, String> {
    corpus(sources)?.naming(name)
}
/// Every source read once: the texts a suffix is searched in (lower-cased), the
/// identities `file:` values resolve to, and one digest over all of it.
struct Corpus {
    texts: Vec<String>,
    files: BTreeSet<FileId>,
    digest: String,
    entries_dir: PathBuf,
}
impl Corpus {
    fn naming(&self, name: &str) -> Result<Naming, String> {
        let Some(suffix) = suffix_of(name) else {
            return Err("the entry name has no generated suffix".to_owned());
        };
        if self.texts.iter().any(|text| text.contains(suffix)) {
            return Ok(Naming::Named);
        }
        let path = self.entries_dir.join(name);
        if let Some((id, links)) = entry_identity(&path)?
            && (links > 1 || self.files.contains(&id))
        {
            return Ok(Naming::Named);
        }
        Ok(Naming::NotNamed {
            digest: self.digest.clone(),
        })
    }
}
fn corpus(sources: &NamingSources) -> Result<Corpus, String> {
    let mut hasher = Sha256::new();
    let mut texts = Vec::new();
    let mut scalars = Vec::new();
    // Through the config guard, as every gateway.yaml read is: a config the
    // gateway would refuse to load is refused here too.
    let config =
        crate::config::read_checked_file(&sources.config, crate::config::CheckedFile::Config)
            .map_err(|_| CONFIG_UNREAD.to_owned())?
            .into_bytes();
    let root = sources.config.as_os_str().as_encoded_bytes();
    absorb(&mut hasher, 1, root);
    absorb(&mut hasher, 2, &config);
    texts.push(ascii_lower(&config));
    let text = std::str::from_utf8(&config).map_err(|_| CONFIG_UNREAD.to_owned())?;
    let parsed = crate::yaml::from_str::<Value>(text).map_err(|_| CONFIG_PARSE.to_owned())?;
    take_strings(&parsed, &mut scalars);
    for path in &sources.env_files {
        let bytes = read_regular(path, "an env file could not be read")?;
        absorb(&mut hasher, 3, path.as_os_str().as_encoded_bytes());
        absorb(&mut hasher, 4, &bytes);
        texts.push(ascii_lower(&bytes));
    }
    for value in &sources.env_values {
        absorb(&mut hasher, 5, value.as_bytes());
        scalars.push(value.clone());
    }
    for value in &sources.process_env {
        let bytes = value.as_encoded_bytes();
        absorb(&mut hasher, 6, bytes);
        match value.to_str() {
            Some(text) => scalars.push(text.to_owned()),
            None => texts.push(ascii_lower(bytes)),
        }
    }
    for dir in &sources.capability_dirs {
        read_caps(dir, &mut hasher, &mut texts, &mut scalars)?;
    }
    let mut files = BTreeSet::new();
    for scalar in &scalars {
        texts.push(scalar.to_lowercase());
        if let Some(rest) = scalar.strip_prefix("file:").filter(|rest| !rest.is_empty()) {
            record_file(Path::new(rest), &mut files)?;
        }
    }
    Ok(Corpus {
        texts,
        files,
        digest: hex::encode(hasher.finalize()),
        entries_dir: sources.entries_dir.clone(),
    })
}
fn read_regular(path: &Path, sentence: &str) -> Result<Vec<u8>, String> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => std::fs::read(path).map_err(|_| sentence.to_owned()),
        _ => Err(sentence.to_owned()),
    }
}
fn read_caps(
    dir: &Path,
    hasher: &mut Sha256,
    texts: &mut Vec<String>,
    scalars: &mut Vec<String>,
) -> Result<(), String> {
    match std::fs::metadata(dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Ok(meta) if meta.is_dir() => {}
        _ => return Err(CAP_UNREAD.to_owned()),
    }
    absorb(hasher, 7, dir.as_os_str().as_encoded_bytes());
    let mut paths = Vec::new();
    // One level past the bound is walked so that reaching it refuses: a loop or a
    // file left unread may name an entry, so neither is skipped.
    for item in WalkDir::new(dir)
        .follow_links(true)
        .max_depth(CAP_DEPTH + 1)
    {
        match item {
            Err(_) => return Err(CAP_UNREAD.to_owned()),
            Ok(entry) if entry.depth() > CAP_DEPTH => return Err(CAP_TOO_DEEP.to_owned()),
            Ok(entry) if entry.depth() == 0 || !entry.file_type().is_file() => {}
            Ok(entry) => paths.push(entry.path().to_path_buf()),
        }
    }
    paths.sort();
    for path in paths {
        let bytes = std::fs::read(&path).map_err(|_| CAP_UNREAD.to_owned())?;
        absorb(hasher, 8, path.as_os_str().as_encoded_bytes());
        absorb(hasher, 9, &bytes);
        texts.push(ascii_lower(&bytes));
        if let Ok(text) = std::str::from_utf8(&bytes)
            && let Ok(value) = crate::yaml::from_str::<Value>(text)
        {
            take_strings(&value, scalars);
        }
    }
    Ok(())
}
fn take_strings(value: &Value, out: &mut Vec<String>) {
    let mut pending = vec![value];
    while let Some(next) = pending.pop() {
        match next {
            Value::String(text) => out.push(text.clone()),
            Value::Array(items) => pending.extend(items),
            Value::Object(map) => {
                // A key can carry a name too, escaped like any scalar.
                out.extend(map.keys().cloned());
                pending.extend(map.values());
            }
            _ => {}
        }
    }
}
fn record_file(path: &Path, files: &mut BTreeSet<FileId>) -> Result<(), String> {
    if let Some((id, _)) = entry_identity(path).map_err(|_| FILE_STAT.to_owned())? {
        files.insert(id);
    }
    Ok(())
}
/// A file's (device, inode).
type FileId = (u64, u64);

fn entry_identity(path: &Path) -> Result<Option<(FileId, u64)>, String> {
    let meta = match std::fs::metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("the entry could not be stat'ed".to_owned()),
        Ok(meta) => meta,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(((meta.dev(), meta.ino()), meta.nlink())))
    }
    // Off Unix there is no link count to read: naming skips this check, and
    // `delete_unused` refuses every files-store delete there instead.
    #[cfg(not(unix))]
    {
        let _ = meta;
        Ok(None)
    }
}
fn absorb(hasher: &mut Sha256, tag: u8, bytes: &[u8]) {
    hasher.update([tag]);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}
/// `bytes` with ASCII letters lower-cased, so a suffix matches in any case.
fn ascii_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}
fn refuse(sentence: &str) -> DeleteRefused {
    DeleteRefused::Failed(sentence.to_owned())
}
fn unrecorded(_: StoreError) -> DeleteRefused {
    refuse("the removal could not be recorded")
}
/// Delete one unused entry from `store`, re-checking everything under the vault lock.
pub(crate) fn delete_unused(
    vault: &Vault,
    store: &dyn SecretStore,
    name: &str,
    sources: &NamingSources,
    deadline: Instant,
) -> Result<Deleted, DeleteRefused> {
    if !is_generated_name(name) {
        return Err(DeleteRefused::BadName);
    }
    if cfg!(not(unix)) && store.kind() == StoreKind::Files {
        return Err(refuse(LINKS_UNVERIFIED));
    }
    let _held =
        lock_file_blocking(vault.lock_path(), "the secret vault", deadline).map_err(|error| {
            if matches!(error, NotLocked::Busy) {
                DeleteRefused::Busy
            } else {
                refuse("the vault lock could not be taken")
            }
        })?;
    let kind = store.kind();
    let index = vault.index();
    let live = index.live().map_err(|_| refuse(INDEX_UNREAD))?;
    let in_this = live
        .iter()
        .any(|row| row.name == name && row.store == kind.as_str());
    if !in_this {
        if live.iter().any(|row| row.name == name) {
            return Err(DeleteRefused::StoreMismatch);
        }
        // Retired by an earlier line: already gone only when the store agrees.
        let recorded = index
            .recorded_in(name, kind)
            .map_err(|_| refuse(INDEX_UNREAD))?;
        if !recorded {
            return Err(DeleteRefused::NotListed);
        }
        return match store.exists(name) {
            Ok(false) => Ok(Deleted::AlreadyGone),
            Ok(true) => Err(DeleteRefused::NotListed),
            Err(StoreError::TimedOut) => Err(DeleteRefused::TimedOut),
            Err(_) => Err(refuse("the secret store could not be read")),
        };
    }
    let previous = match naming(sources, name).map_err(DeleteRefused::Failed)? {
        Naming::Named => return Err(DeleteRefused::Named),
        Naming::NotNamed { digest } => digest,
    };
    match store.exists(name) {
        Ok(true) => {}
        Ok(false) => {
            index.append_removed_in(name, kind).map_err(unrecorded)?;
            return Ok(Deleted::AlreadyGone);
        }
        Err(StoreError::TimedOut) => return Err(DeleteRefused::TimedOut),
        Err(_) => return Err(refuse("the secret store could not be read")),
    }
    #[cfg(test)]
    seam::BEFORE_RECHECK.with(|slot| {
        if let Some(run) = slot.borrow_mut().take() {
            run();
        }
    });
    match naming(sources, name).map_err(DeleteRefused::Failed)? {
        Naming::Named => return Err(DeleteRefused::Named),
        Naming::NotNamed { digest } if digest != previous => return Err(DeleteRefused::Named),
        Naming::NotNamed { .. } => {}
    }
    store.delete(name).map_err(|error| match error {
        StoreError::TimedOut => DeleteRefused::TimedOut,
        _ => refuse("the secret store could not delete the entry"),
    })?;
    #[cfg(test)]
    if seam::STOP_AFTER_STORE_DELETE.with(|cell| cell.get()) {
        return Err(refuse("stopped at the seam"));
    }
    index.append_removed_in(name, kind).map_err(unrecorded)?;
    Ok(Deleted::Removed)
}
/// What [`listing`] found: unused entries, and each store that could not be read.
#[derive(Debug, Default)]
pub(crate) struct Listing {
    pub(crate) entries: Vec<UnusedEntry>,
    pub(crate) errors: Vec<(StoreKind, String)>,
}
/// Unused entries per store, each filtered by one read of every naming source. A
/// store that fails is reported by kind and the others still list.
pub(crate) fn listing(
    vault: &Vault,
    stores: &[&dyn SecretStore],
    sources: &NamingSources,
) -> Listing {
    let mut listed = Listing::default();
    let built = match corpus(sources) {
        Ok(built) => built,
        Err(reason) => {
            listed.errors = stores
                .iter()
                .map(|store| (store.kind(), reason.clone()))
                .collect();
            return listed;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    for store in stores {
        match super::unused_entries_until(vault, &[*store], &BTreeSet::new(), deadline) {
            Err(error) => listed.errors.push((store.kind(), error.reason())),
            Ok(entries) => {
                for entry in entries {
                    match built.naming(&entry.name) {
                        Ok(Naming::NotNamed { .. }) => listed.entries.push(entry),
                        Ok(Naming::Named) => {}
                        Err(reason) => listed.errors.push((store.kind(), reason)),
                    }
                }
            }
        }
    }
    listed
}
/// Per-thread seams inside [`delete_unused`], set by a row.
#[cfg(test)]
mod seam {
    use std::cell::{Cell, RefCell};
    thread_local! {
        pub(super) static BEFORE_RECHECK: RefCell<Option<Box<dyn FnOnce()>>> =
            const { RefCell::new(None) };
        pub(super) static STOP_AFTER_STORE_DELETE: Cell<bool> = const { Cell::new(false) };
    }
}
#[cfg(test)]
#[path = "unused_delete_tests.rs"]
mod delete_tests;
#[cfg(test)]
#[path = "unused_seam_tests.rs"]
mod seam_tests;
#[cfg(test)]
#[path = "unused_tests.rs"]
mod tests;
