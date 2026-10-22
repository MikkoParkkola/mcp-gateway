// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fingerprint of the watched capability trees for the stale check.
//!
//! The loop in [`super`](super) compares this against the fingerprint taken
//! before the last complete reload; on drift it reloads through the normal
//! debounced path. See the parent module's docs for the check and its limits.

use std::path::{Path, PathBuf};

/// A snapshot of the watched capability files: the sorted `(directory index,
/// relative path, length, mtime)` tuples for every `*.yaml`/`*.yml` under the
/// watched roots. A `Vec`, not a hash: exact, and the trees are small.
pub(super) type Fingerprint = Vec<(usize, String, u64, u128)>;

/// Deepest level below a watched root the fingerprint descends to. This is
/// the backstop: the only cycle guard off unix, and a bound on deep real
/// trees everywhere.
const FINGERPRINT_MAX_DEPTH: u32 = 16;
/// Most directory entries the fingerprint visits across all watched roots.
const FINGERPRINT_MAX_ENTRIES: usize = 10_000;

/// The identity of a directory for cycle detection: (device, inode) on unix.
#[cfg(unix)]
fn dir_id(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

/// No stable directory identity off unix; the depth bound is the only cycle guard there.
#[cfg(not(unix))]
fn dir_id(_metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Fingerprint the watched directories: the sorted `(directory index,
/// relative path, length, mtime in nanoseconds since the Unix epoch)` of
/// every `*.yaml`/`*.yml`, recursive.
///
/// Mirrors the loader: hidden names are skipped, and file or directory is
/// decided with [`std::fs::metadata`], which follows symlinks. A missing
/// directory contributes nothing and an unreadable entry is skipped. Past
/// [`FINGERPRINT_MAX_DEPTH`] levels or [`FINGERPRINT_MAX_ENTRIES`] visited
/// entries the walk gives up and returns `None`. On unix, a symlink cycle (a
/// directory that is its own ancestor by device and inode) ends the walk at
/// its first repeat and returns `None`, like the bounds; off unix, the depth
/// bound is the only guard against a cycle. A non-cyclic chain of links
/// longer than the OS link limit fails to resolve and is skipped like any
/// unreadable entry; that is a named limit.
pub(super) fn fingerprint(dirs: &[String]) -> Option<Fingerprint> {
    let mut found: Fingerprint = Vec::new();
    let mut visited: usize = 0;
    for (index, dir) in dirs.iter().enumerate() {
        // The root is depth 0; each subdirectory descends one level.
        let root_ancestors: Vec<(u64, u64)> = match std::fs::metadata(dir) {
            Ok(m) => dir_id(&m).into_iter().collect(),
            Err(_) => Vec::new(),
        };
        let mut stack = vec![(PathBuf::from(dir), 0, root_ancestors)];
        while let Some((path, depth, ancestors)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                visited += 1;
                if visited > FINGERPRINT_MAX_ENTRIES {
                    return None;
                }
                let entry_path = entry.path();
                if entry_path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                {
                    continue;
                }
                // Follows symlinks, like the loader's `path.is_dir()`.
                let Ok(metadata) = std::fs::metadata(&entry_path) else {
                    continue;
                };
                if metadata.is_dir() {
                    if depth + 1 > FINGERPRINT_MAX_DEPTH {
                        return None;
                    }
                    let id = dir_id(&metadata);
                    if id.is_some_and(|id| ancestors.contains(&id)) {
                        return None;
                    }
                    let mut ancestors_plus_id = ancestors.clone();
                    if let Some(id) = id {
                        ancestors_plus_id.push(id);
                    }
                    stack.push((entry_path, depth + 1, ancestors_plus_id));
                    continue;
                }
                let is_yaml = entry_path
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml");
                if !is_yaml {
                    continue;
                }
                let Ok(modified) = metadata.modified() else {
                    continue;
                };
                let nanos = match modified.duration_since(std::time::UNIX_EPOCH) {
                    Ok(elapsed) => elapsed.as_nanos(),
                    Err(_) => 0,
                };
                let relative = match entry_path.strip_prefix(Path::new(dir)) {
                    Ok(relative) => relative.to_string_lossy().into_owned(),
                    Err(_) => continue,
                };
                found.push((index, relative, metadata.len(), nanos));
            }
        }
    }
    // `read_dir` order is unspecified; the comparison needs a canonical one.
    found.sort();
    Some(found)
}
