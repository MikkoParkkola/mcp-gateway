// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Install checks for the fetch phase (ADR-027): the npm lock holds nothing
//! from outside the registry, and the run's argv comes from the installed
//! package's own metadata, never from a listing of a bin directory.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls these")
)]

use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::Refusal;

const REGISTRY: &str = "https://registry.npmjs.org/";

/// Refuse unless `lock` (a `package-lock.json`, v2 or later) holds only
/// registry tarballs: every entry's `resolved` is a registry tarball (a
/// bundled entry ships inside its parent's), every declared dependency is a
/// registry range, and every declared edge, optional ones included, reaches
/// an entry by node's lookup, so a subtree npm pruned cannot hide a git edge.
pub(crate) fn check_lock(lock: &Value) -> Result<(), Refusal> {
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .ok_or_else(|| refuse("the npm lock has no package list (npm 7 or later writes one)"))?;
    for (key, entry) in packages {
        let bundled = entry.get("inBundle").and_then(Value::as_bool) == Some(true);
        let resolved = entry.get("resolved").and_then(Value::as_str);
        let registry = resolved.is_some_and(|r| {
            r.starts_with(REGISTRY) && r.rsplit_once('.').is_some_and(|(_, ext)| ext == "tgz")
        });
        let linked = entry.get("link").and_then(Value::as_bool) == Some(true);
        // The root need not have a tarball, but cannot redirect the install.
        if linked || !(registry || ((key.is_empty() || bundled) && resolved.is_none())) {
            return Err(not_registry(key));
        }
        // A peer is installed by npm 7 or later like any dependency, so its
        // spec must be a registry range too. Reachability is not checked: an
        // optional peer may be absent from the lock.
        for (peer, range) in entry
            .get("peerDependencies")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if !range.as_str().is_some_and(registry_range) {
                return Err(not_registry(&format!("{peer} of {}", shown(key))));
            }
        }
        for field in ["dependencies", "optionalDependencies"] {
            let Some(deps) = entry.get(field).and_then(Value::as_object) else {
                continue;
            };
            for (dep, range) in deps {
                if !range.as_str().is_some_and(registry_range) {
                    return Err(not_registry(&format!("{dep} of {}", shown(key))));
                }
                if !reaches(packages, key, dep) {
                    return Err(refuse(&format!(
                        "{dep}, needed by {}, has no entry in the lock",
                        shown(key)
                    )));
                }
            }
        }
    }
    Ok(())
}

/// A semver range or tag, or an `npm:` alias of a registry package: never a
/// git, file, link, URL or `user/repo` spec.
fn registry_range(range: &str) -> bool {
    match range.strip_prefix("npm:") {
        Some(alias) => {
            let unscoped = match alias.strip_prefix('@') {
                Some(scoped) => match scoped.split_once('/') {
                    Some((scope, rest)) if name_part(scope) => rest,
                    _ => return false,
                },
                None => alias,
            };
            // An alias without a version takes npm's default registry range.
            let (name, version) = unscoped
                .split_once('@')
                .map_or((unscoped, None), |(name, version)| (name, Some(version)));
            name_part(name) && version.is_none_or(semver)
        }
        None => semver(range),
    }
}

fn semver(range: &str) -> bool {
    // npm treats leading dots and archive suffixes (in any letter case) as
    // files, including in aliases; the empty range is its default `*`.
    let lower = range.to_ascii_lowercase();
    !range.starts_with('.')
        && ![".tgz", ".tar", ".tar.gz"]
            .into_iter()
            .any(|suffix| lower.ends_with(suffix))
        && range
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-^~<>=| *".contains(c))
}

fn name_part(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-._~".contains(c))
}

/// Whether `dep`, needed by the entry at `key`, resolves by node's lookup:
/// `<key>/node_modules/<dep>`, then the same under each enclosing package,
/// up to the root's `node_modules/<dep>`.
fn reaches(packages: &serde_json::Map<String, Value>, key: &str, dep: &str) -> bool {
    let mut at = key;
    loop {
        let candidate = if at.is_empty() {
            format!("node_modules/{dep}")
        } else {
            format!("{at}/node_modules/{dep}")
        };
        if packages.contains_key(&candidate) {
            return true;
        }
        if at.is_empty() {
            return false;
        }
        at = at
            .rfind("node_modules/")
            .map_or("", |i| at[..i].trim_end_matches('/'));
    }
}

fn shown(key: &str) -> &str {
    if key.is_empty() { "the package" } else { key }
}

fn refuse(reason: &str) -> Refusal {
    Refusal::Command(reason.to_owned())
}

fn not_registry(what: &str) -> Refusal {
    Refusal::Command(format!(
        "the install holds {what}, which is not from the registry"
    ))
}

const NO_ENTRY: &str = "the package has no single entry point";

/// Bound untrusted metadata reads even if the file grows after opening.
fn read_metadata(path: &Path) -> Option<Vec<u8>> {
    const LIMIT: usize = 1024 * 1024;
    let file = crate::open_nonblocking::open_nonblocking(path).ok()?;
    // Check the opened object so a replaced path cannot bypass the file check.
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= LIMIT).then_some(bytes)
}

/// The bin file of npm package `name` installed under `root`: `bin` as a
/// string, a map with one entry, or the entry named after the package's own
/// name (scope dropped), as npx picks it. The file must resolve, symlinks
/// followed, inside the package's directory; it runs directly, so its shebang
/// or native format picks the interpreter.
pub(crate) fn npm_bin(root: &Path, name: &str) -> Result<PathBuf, Refusal> {
    let root = root.canonicalize().map_err(|_| refuse(NO_ENTRY))?;
    let dir = root
        .join("node_modules")
        .join(name)
        .canonicalize()
        .map_err(|_| refuse(NO_ENTRY))?;
    if !dir.starts_with(&root) {
        return Err(refuse("the package's entry point is outside the package"));
    }
    let manifest: Value = read_metadata(&dir.join("package.json"))
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| refuse(NO_ENTRY))?;
    let own = name.rsplit('/').next().unwrap_or(name);
    let file = match manifest.get("bin") {
        Some(Value::String(file)) => Some(file.as_str()),
        Some(Value::Object(bins)) if bins.len() == 1 => {
            bins.values().next().and_then(Value::as_str)
        }
        Some(Value::Object(bins)) => bins.get(own).and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| refuse(NO_ENTRY))?;
    let target = dir
        .join(file)
        .canonicalize()
        .map_err(|_| refuse(NO_ENTRY))?;
    if !target.starts_with(&dir) {
        return Err(refuse("the package's entry point is outside the package"));
    }
    Ok(target)
}

/// The console script of `PyPI` package `name` in the uv tool environment
/// `env`, from the package's own `entry_points.txt`: the script named after
/// the package, or its only one. Never a listing of `bin/`, which also holds
/// every dependency's scripts.
pub(crate) fn uv_entry_point(env: &Path, name: &str) -> Result<PathBuf, Refusal> {
    let dist_info = dist_info(&site_packages(env)?, name)?;
    let text = read_metadata(&dist_info.join("entry_points.txt"))
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| refuse(NO_ENTRY))?;
    let scripts = console_scripts(&text);
    let wanted = normalize(name);
    let script = match scripts.as_slice() {
        [only] => Some(*only),
        many => many.iter().copied().find(|s| *s == name).or_else(|| {
            let mut matches = many.iter().copied().filter(|s| normalize(s) == wanted);
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        }),
    }
    .ok_or_else(|| refuse(NO_ENTRY))?;
    // A name is one path component: a script named `../x` would leave bin/.
    if script.is_empty() || script.contains(['/', '\\']) || script == "." || script == ".." {
        return Err(refuse(NO_ENTRY));
    }
    let path = env.join("bin").join(script);
    if path.is_file() {
        Ok(path)
    } else {
        Err(refuse(NO_ENTRY))
    }
}

/// The one `lib/python*/site-packages` of a tool environment.
fn site_packages(env: &Path) -> Result<PathBuf, Refusal> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(env.join("lib")).map_err(|_| no_metadata())? {
        let entry = entry.map_err(|_| no_metadata())?;
        let site = entry.path().join("site-packages");
        if entry.file_name().to_string_lossy().starts_with("python") && site.is_dir() {
            found.push(site);
        }
    }
    single(found)
}

/// The one `*.dist-info` directory whose name part, PEP 503-normalized,
/// equals the package's. Every directory is enumerated and compared; zero or
/// two matches refuse.
fn dist_info(site: &Path, name: &str) -> Result<PathBuf, Refusal> {
    let wanted = normalize(name);
    let mut found = Vec::new();
    for entry in std::fs::read_dir(site).map_err(|_| no_metadata())? {
        let entry = entry.map_err(|_| no_metadata())?;
        let file_name = entry.file_name();
        let Some(stem) = file_name
            .to_str()
            .and_then(|n| n.strip_suffix(".dist-info"))
        else {
            continue;
        };
        let dist = stem.rsplit_once('-').map_or(stem, |(dist, _)| dist);
        if normalize(dist) == wanted && entry.path().is_dir() {
            found.push(entry.path());
        }
    }
    single(found)
}

fn single(mut found: Vec<PathBuf>) -> Result<PathBuf, Refusal> {
    match found.len() {
        1 => Ok(found.remove(0)),
        _ => Err(no_metadata()),
    }
}

fn no_metadata() -> Refusal {
    refuse("the package's installed metadata was not found exactly once")
}

/// PEP 503: lowercase, each run of `-`, `_` and `.` as one `-`.
fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if "-_.".contains(c) {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The names under `[console_scripts]` in an `entry_points.txt`.
fn console_scripts(text: &str) -> Vec<&str> {
    let mut section = "";
    let mut names = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = header.trim();
        } else if section == "console_scripts"
            && !line.starts_with(['#', ';'])
            && let Some((name, _)) = line.split_once('=')
        {
            names.push(name.trim());
        }
    }
    names
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
