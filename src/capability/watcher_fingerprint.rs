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
/// a backstop for deep real trees.
const FINGERPRINT_MAX_DEPTH: u32 = 16;
/// Most directory entries the fingerprint visits across all watched roots.
const FINGERPRINT_MAX_ENTRIES: usize = 10_000;

/// Fingerprint the watched directories: the sorted `(directory index,
/// relative path, length, mtime in nanoseconds since the Unix epoch)` of
/// every `*.yaml`/`*.yml`, recursive.
///
/// Mirrors the loader: hidden names are skipped, and file or directory is
/// decided with [`std::fs::metadata`], which follows symlinks. A missing
/// directory contributes nothing and an unreadable entry is skipped. Past
/// [`FINGERPRINT_MAX_DEPTH`] levels or [`FINGERPRINT_MAX_ENTRIES`] visited
/// entries the walk gives up and returns `None`. A symlink cycle (a
/// directory whose canonical path equals one of its ancestors') ends the
/// walk at its first repeat on every platform, and returns `None` like the
/// bounds; the depth bound is a backstop for deep real trees. Each
/// directory is read through its canonical path, so only one entry's own
/// link chain counts against the OS link limit; a single chain longer than
/// that limit cannot resolve and is skipped like any unreadable entry; that
/// is a named limit. Two links to the same directory that is not an
/// ancestor are both walked. A bind mount of an ancestor onto its own child
/// is untested (a test needs root).
pub(super) fn fingerprint(dirs: &[String]) -> Option<Fingerprint> {
    let mut found: Fingerprint = Vec::new();
    let mut visited: usize = 0;
    for (index, dir) in dirs.iter().enumerate() {
        // The root is depth 0; each subdirectory descends one level.
        let Ok(root_canon) = std::fs::canonicalize(dir) else {
            continue;
        };
        let mut stack: Vec<(PathBuf, PathBuf, u32, Vec<PathBuf>)> =
            vec![(PathBuf::from(dir), root_canon.clone(), 0, vec![root_canon])];
        while let Some((logical, canonical, depth, ancestors)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&canonical) else {
                continue;
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                visited += 1;
                if visited > FINGERPRINT_MAX_ENTRIES {
                    return None;
                }
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.') {
                    continue;
                }
                let logical_path = logical.join(&name);
                let real_path = canonical.join(&name);
                // Follows symlinks, like the loader's `path.is_dir()`.
                let Ok(metadata) = std::fs::metadata(&real_path) else {
                    continue;
                };
                if metadata.is_dir() {
                    if depth + 1 > FINGERPRINT_MAX_DEPTH {
                        return None;
                    }
                    let Ok(child_canon) = std::fs::canonicalize(&real_path) else {
                        continue;
                    };
                    if ancestors.contains(&child_canon) {
                        return None;
                    }
                    let mut ancestors_plus = ancestors.clone();
                    ancestors_plus.push(child_canon.clone());
                    stack.push((logical_path, child_canon, depth + 1, ancestors_plus));
                    continue;
                }
                let is_yaml = logical_path
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
                let relative = match logical_path.strip_prefix(Path::new(dir)) {
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
