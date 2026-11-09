// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The command plan (ADR-027): whether a typed command fetches a registry
//! package before it runs. `npx` and `uvx` fetch exactly one npm or `PyPI`
//! package named by a plain registry spec; any other program runs as typed.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls plan")
)]

use std::ffi::OsString;

use super::{Refusal, Target};

/// The package a preview fetches before its run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fetch {
    /// An npm spec: `name` or `@scope/name`, optional `@version`.
    Npm(String),
    /// A `PyPI` spec: a name, optional `==version`.
    Uv(String),
}

/// A typed command split into its phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Phases {
    pub(crate) fetch: Option<Fetch>,
    /// The server's own arguments, after the spec.
    pub(crate) run_args: Vec<OsString>,
}

/// npm's limit on a package name, scope included.
const NPM_NAME_MAX: usize = 214;

/// Split `target` into its fetch and run phases. `npx` and `uvx`, matched by
/// the program's file name, take the first argument as the package spec; an
/// option before it refuses, apart from npx's `-y`/`--yes`, so nothing typed
/// can point the fetch at another registry or add a package.
pub(crate) fn plan(target: &Target) -> Result<Phases, Refusal> {
    let tool = target.program.file_name().and_then(|n| n.to_str());
    let npm = match tool {
        Some("npx") => true,
        Some("uvx") => false,
        _ => {
            return Ok(Phases {
                fetch: None,
                run_args: target.args.clone(),
            });
        }
    };
    let mut args = target.args.iter();
    let mut first = args.next();
    if npm {
        while first.is_some_and(|a| a == "-y" || a == "--yes") {
            first = args.next();
        }
    }
    let Some(spec) = first else {
        return Err(refuse("npx/uvx with no package"));
    };
    let spec = spec
        .to_str()
        .ok_or_else(|| refuse("not a registry package: a non-UTF-8 argument"))?;
    if mutant!("q7", false, spec.starts_with('-')) {
        return Err(refuse("an npx/uvx option before the package"));
    }
    let fetch = if npm {
        npm_spec(spec).map(|()| Fetch::Npm(spec.to_owned()))
    } else {
        pypi_spec(spec).map(|()| Fetch::Uv(spec.to_owned()))
    }?;
    Ok(Phases {
        fetch: Some(fetch),
        run_args: args.cloned().collect(),
    })
}

fn refuse(reason: &str) -> Refusal {
    Refusal::Command(reason.to_owned())
}

fn not_registry(spec: &str) -> Refusal {
    Refusal::Command(format!("not a registry package: {spec:?}"))
}

/// `name` or `@scope/name`, optional `@version` (npm's rules for new names:
/// lowercase URL-safe characters, no leading `.` or `_`, at most 214 long).
fn npm_spec(spec: &str) -> Result<(), Refusal> {
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(scoped) => {
            let (scope, rest) = scoped.split_once('/').ok_or_else(|| not_registry(spec))?;
            (Some(scope), rest)
        }
        None => (None, spec),
    };
    let (name, version) = match rest.split_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (rest, None),
    };
    let name_len = scope.map_or(0, |s| s.len() + 2) + name.len();
    let ok = scope.is_none_or(npm_name_part)
        && npm_name_part(name)
        && name_len <= NPM_NAME_MAX
        && version.is_none_or(|v| !v.is_empty() && v.chars().all(npm_version_char));
    if mutant!("q8", true, ok) {
        Ok(())
    } else {
        Err(not_registry(spec))
    }
}

fn npm_name_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with(['.', '_'])
        && part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-._~".contains(c))
}

/// A semver range's characters; never `:`, `/` or `\`, so no alias, URL or path.
fn npm_version_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || ".+-^~<>=| *".contains(c)
}

/// A PEP 508 name that starts and ends with a letter or digit, optional
/// `==version`. Extras refuse on their own: they pull optional dependencies.
fn pypi_spec(spec: &str) -> Result<(), Refusal> {
    let (name, version) = match spec.split_once("==") {
        Some((name, version)) => (name, Some(version)),
        None => (spec, None),
    };
    if mutant!("q16", false, name.contains('[')) {
        return Err(refuse("PyPI extras are not previewed"));
    }
    let ok = name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        && version.is_none_or(|v| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".!+-_*".contains(c))
        });
    if mutant!("q30", true, ok) {
        Ok(())
    } else {
        Err(not_registry(spec))
    }
}

#[cfg(test)]
#[path = "fetch_tests.rs"]
mod tests;
