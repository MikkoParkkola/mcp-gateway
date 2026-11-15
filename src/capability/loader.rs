// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability directory loader

use super::{
    CapabilityDefinition, Issue, IssueSeverity, validate_capability, validate_capability_definition,
};
use crate::{Error, Result};
use std::path::Path;
use tracing::{debug, info, warn};

/// Loader for capability definitions from directories
pub struct CapabilityLoader;

/// One capability file the loader parsed, with the bytes that parse accepted.
pub(crate) struct LoadedCapability {
    /// The configured directory as written, joined with the walk's relative path.
    pub(crate) path: String,
    /// The buffer [`super::parser::parse_capability_text`] accepted.
    pub(crate) bytes: Vec<u8>,
    /// The capability that parse produced.
    pub(crate) definition: CapabilityDefinition,
}

/// A file in a readable directory that could not be read or parsed.
pub(crate) struct FileFailure {
    /// [`source_path`] of the file that failed.
    pub(crate) path: String,
    /// The read or parse error, rendered.
    pub(crate) error: String,
}

/// What one directory read produced.
///
/// `Err` from the loader is a directory that itself could not be listed.
/// `failures` are files inside a directory that could.
pub(crate) struct DirectoryFiles {
    /// Files that parsed and passed the unloadable checks.
    pub(crate) files: Vec<LoadedCapability>,
    /// Files that did not. The directory itself was readable.
    pub(crate) failures: Vec<FileFailure>,
}

/// The path a served file is known by: `root` exactly as configured, joined
/// with the walk's relative path. No canonicalisation.
///
/// The trailing separator is stripped only to test the prefix. It stays in
/// the result, so `capabilities/` and `capabilities` stay different strings.
/// A file the prefix does not contain keeps `file`'s display, which is the
/// key rug-pull detection already looked up.
pub(crate) fn source_path(root: &str, file: &Path) -> String {
    let trimmed = root.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return file.display().to_string();
    }
    let Ok(relative) = file.strip_prefix(Path::new(trimmed)) else {
        return file.display().to_string();
    };
    if relative.as_os_str().is_empty() {
        return root.to_string();
    }
    let relative = relative.to_string_lossy();
    if root.ends_with('/') || root.ends_with('\\') {
        format!("{root}{relative}")
    } else {
        format!("{root}/{relative}")
    }
}

impl CapabilityLoader {
    /// Load all capabilities from a directory (recursive)
    ///
    /// Emits one INFO-level summary line (`N loaded, M unpinned`) per
    /// directory rather than one line per unpinned file — pinning is opt-in
    /// per file by design, so an unpinned public catalog is expected, not a
    /// misconfiguration to warn about file-by-file. Per-file detail (path +
    /// computed hash) is still logged at DEBUG from the text parser.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory does not exist or is not a valid directory.
    pub async fn load_directory(path: &str) -> Result<Vec<CapabilityDefinition>> {
        let loaded = Self::load_directory_with_paths(path).await?;
        Ok(loaded
            .files
            .into_iter()
            .map(|file| file.definition)
            .collect())
    }

    /// [`Self::load_directory`], each capability beside the path and the bytes
    /// the parse accepted, plus each file in that directory the read or the
    /// parse refused.
    ///
    /// One read per file. A missing directory, a path that is not a directory,
    /// or a listing that fails is still `Err`.
    ///
    /// # Errors
    ///
    /// As [`Self::load_directory`].
    pub(crate) async fn load_directory_with_paths(path: &str) -> Result<DirectoryFiles> {
        // Before the directory is read, and before any await, so a row can
        // hold this operation at its load on the thread that is polling it.
        #[cfg(test)]
        super::op_gate::reach(super::op_gate::Step::Load);
        let root = path;
        let path = Path::new(path);

        if !path.exists() {
            return Err(Error::Config(format!(
                "Capabilities directory does not exist: {}",
                path.display()
            )));
        }

        if !path.is_dir() {
            return Err(Error::Config(format!(
                "Capabilities path is not a directory: {}",
                path.display()
            )));
        }

        let mut files = Vec::new();
        let mut failures = Vec::new();
        Self::load_directory_recursive(root, path, &mut files, &mut failures).await?;

        let unpinned = files
            .iter()
            .filter(|file| lacks_pin(&file.definition))
            .count();
        info!(
            count = files.len(),
            unpinned,
            path = %path.display(),
            "Loaded capabilities: {} loaded, {unpinned} unpinned",
            files.len(),
        );

        Ok(DirectoryFiles { files, failures })
    }

    /// Recursively load capabilities from a directory.
    ///
    /// `root` stays the configured directory string. Subdirectories are not a
    /// new root: the path joined for each file is relative to `root`.
    async fn load_directory_recursive(
        root: &str,
        dir: &Path,
        files: &mut Vec<LoadedCapability>,
        failures: &mut Vec<FileFailure>,
    ) -> Result<()> {
        let mut entries = tokio::fs::read_dir(dir).await.map_err(|e| {
            Error::Config(format!("Failed to read directory {}: {e}", dir.display()))
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| Error::Config(format!("Failed to read directory entry: {e}")))?
        {
            // Large capability directories load in the background at startup;
            // yield between entries so the gateway listener remains responsive.
            tokio::task::yield_now().await;

            let path = entry.path();

            // Skip hidden files/directories
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }

            if path.is_dir() {
                // Recurse into subdirectories
                Box::pin(Self::load_directory_recursive(
                    root, &path, files, failures,
                ))
                .await?;
            } else if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                // Load YAML files. A file error does not fail the directory:
                // the caller hears it in `failures` and the file is not served.
                match Self::load_capability_file(&path).await {
                    Ok((bytes, definition)) => {
                        debug!(name = %definition.name, path = %path.display(), "Loaded capability");
                        files.push(LoadedCapability {
                            path: source_path(root, &path),
                            bytes,
                            definition,
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path.display(), "Failed to load capability");
                        failures.push(FileFailure {
                            path: source_path(root, &path),
                            error: e.to_string(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Load and validate a single capability file.
    ///
    /// One read. The returned bytes are the buffer the parse accepted.
    /// Structural errors cause the capability to be skipped (this function
    /// returns `Err`); structural warnings are logged but the capability is
    /// still loaded.
    async fn load_capability_file(path: &Path) -> Result<(Vec<u8>, CapabilityDefinition)> {
        let bytes = tokio::fs::read(path).await.map_err(|e| {
            Error::Config(format!(
                "Failed to read capability file {}: {e}",
                path.display()
            ))
        })?;
        // Invalid UTF-8 is a per-file failure, as a read error was.
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            Error::Config(format!(
                "Failed to read capability file {}: {e}",
                path.display()
            ))
        })?;
        let capability = super::parser::parse_capability_text(text, path)?;
        refuse_unloadable(&capability, path, IssueLog::EachIssue)?;
        Ok((bytes, capability))
    }

    /// Load capabilities from multiple directories
    ///
    /// # Errors
    ///
    /// Returns an error only if all directories fail to load. Individual failures are logged as warnings.
    pub async fn load_directories(paths: &[&str]) -> Result<Vec<CapabilityDefinition>> {
        let mut all_capabilities = Vec::new();

        for path in paths {
            match Self::load_directory(path).await {
                Ok(caps) => all_capabilities.extend(caps),
                Err(e) => {
                    warn!(error = %e, path = %path, "Failed to load capabilities directory");
                }
            }
        }

        Ok(all_capabilities)
    }
}

/// Whether [`refuse_unloadable`] logs each structural issue it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IssueLog {
    /// One warning line per issue: the loader, whose log is the operator's
    /// record of what was served.
    EachIssue,
    /// Nothing: the search index, which a CLI user runs interactively, where
    /// one line per catalogue warning buries the answer (MIK-8358 G6).
    Quiet,
}

/// The structural errors that make [`refuse_unloadable`] refuse `capability`,
/// one per issue, for a caller that shows them (the capability editor).
///
/// # Errors
///
/// The legacy `validate_capability` error, which refuses before any issue.
#[cfg(feature = "webui")]
pub(crate) fn unloadable_issues(
    capability: &CapabilityDefinition,
    path: &Path,
) -> Result<Vec<Issue>> {
    let issues = loader_issues(capability, &path.to_string_lossy())?;
    Ok(issues
        .into_iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .collect())
}

/// Both checks behind [`refuse_unloadable`] and [`unloadable_issues`], so the
/// two can never disagree on what loads.
fn loader_issues(capability: &CapabilityDefinition, path: &str) -> Result<Vec<Issue>> {
    validate_capability(capability)?;
    Ok(validate_capability_definition(capability, Some(path)))
}

/// The checks a parsed capability file must pass to be served: the legacy
/// `validate_capability` and the structural validator's errors. Warnings do
/// not refuse; `log` says whether each issue is logged. The loader and the
/// registry's search index both ask this, so search never lists a file the
/// loader skips (MIK-8358).
///
/// # Errors
///
/// The legacy check's error, or `Error::Config` counting the structural
/// errors when there are any.
pub(crate) fn refuse_unloadable(
    capability: &CapabilityDefinition,
    path: &Path,
    log: IssueLog,
) -> Result<()> {
    let path_str = path.to_string_lossy();
    let issues = loader_issues(capability, &path_str)?;
    for issue in issues.iter().filter(|_| log == IssueLog::EachIssue) {
        let kind = if issue.severity == IssueSeverity::Error {
            "error"
        } else {
            "warning"
        };
        warn!(
            code = issue.code,
            field = ?issue.field,
            path = %path_str,
            "Structural validation {kind}: {}",
            issue.message,
        );
    }
    let errors = issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .count();
    if errors > 0 {
        return Err(Error::Config(format!(
            "Capability '{path_str}' has {errors} structural error(s); skipping"
        )));
    }
    Ok(())
}

/// Count how many `capabilities` have no `sha256:` pin.
///
/// Pinning is opt-in per file by design (see
/// [`super::parser::parse_capability_file`]); this count feeds the
/// directory-level `N loaded, M unpinned` summary log so an operator can see
/// catalog pin coverage at a glance instead of scanning one INFO line per
/// unpinned file (MIK-6742).
fn lacks_pin(capability: &CapabilityDefinition) -> bool {
    capability.sha256.is_none()
}

fn count_unpinned(capabilities: &[CapabilityDefinition]) -> usize {
    capabilities.iter().filter(|c| lacks_pin(c)).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_directory() {
        let temp_dir = TempDir::new().unwrap();

        // Create a test capability file
        let cap_path = temp_dir.path().join("test_cap.yaml");
        let mut file = std::fs::File::create(&cap_path).unwrap();
        writeln!(
            file,
            r"
name: test_capability
description: A test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /test
"
        )
        .unwrap();

        let capabilities = CapabilityLoader::load_directory(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].name, "test_capability");
    }

    #[tokio::test]
    async fn test_load_nested_directories() {
        let temp_dir = TempDir::new().unwrap();

        // Create nested structure
        let subdir = temp_dir.path().join("google");
        std::fs::create_dir(&subdir).unwrap();

        let cap_path = subdir.join("gmail.yaml");
        let mut file = std::fs::File::create(&cap_path).unwrap();
        writeln!(
            file,
            r"
name: gmail_test
description: Gmail test
providers:
  primary:
    service: rest
    config:
      base_url: https://gmail.googleapis.com
"
        )
        .unwrap();

        let capabilities = CapabilityLoader::load_directory(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].name, "gmail_test");
    }

    // ── MIK-6742: unpinned-catalog log volume ───────────────────────────────
    //
    // A public capability catalog is unpinned by design (pinning is opt-in
    // per file). Loading it must not emit one INFO log line per unpinned
    // file — that produced a wall of ~118 INFO lines on every boot. The fix
    // demotes the per-file line in `parser::parse_capability_file` to DEBUG
    // and reports the unpinned count once, in `load_directory`'s existing
    // per-directory summary. `count_unpinned` is the arithmetic behind that
    // summary; testing tracing's own INFO/DEBUG routing would require
    // capturing log output, which is unreliable in a shared parallel test
    // binary (tracing caches an `Interest` decision per callsite the first
    // time it's hit, process-wide — a test-order-dependent trap, not
    // something a per-test subscriber can override). `count_unpinned` is
    // exactly the part of this change that carries regression risk (getting
    // the `Option::is_none()` polarity backwards silently reports "0
    // unpinned" against a fully-unpinned catalog), so that is what is
    // covered here.

    /// Build a minimal, valid [`CapabilityDefinition`] for counting tests,
    /// optionally embedding a `sha256:` pin.
    fn make_cap(name: &str, sha256: Option<&str>) -> CapabilityDefinition {
        let pin_line = sha256.map_or_else(String::new, |h| format!("sha256: {h}\n"));
        let yaml = format!(
            r"
{pin_line}name: {name}
description: Test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://internal.test
      path: /test
"
        );
        super::super::parse_capability(&yaml).unwrap()
    }

    /// GIVEN a mix of pinned and unpinned capability definitions
    /// WHEN counting unpinned entries
    /// THEN only the entries with `sha256: None` are counted.
    #[test]
    fn count_unpinned_counts_only_definitions_without_a_pin() {
        let pinned = make_cap("pinned_cap", Some("abc123"));
        let unpinned_a = make_cap("unpinned_a", None);
        let unpinned_b = make_cap("unpinned_b", None);

        assert_eq!(
            count_unpinned(&[pinned.clone(), unpinned_a.clone(), unpinned_b.clone()]),
            2
        );
        assert_eq!(count_unpinned(&[pinned]), 0);
        assert_eq!(count_unpinned(&[unpinned_a, unpinned_b]), 2);
    }

    /// GIVEN an empty capability list
    /// WHEN counting unpinned entries
    /// THEN the count is zero (no divide-by-zero or panic on an empty
    /// directory).
    #[test]
    fn count_unpinned_returns_zero_for_empty_slice() {
        assert_eq!(count_unpinned(&[]), 0);
    }

    /// GIVEN a directory of two unpinned capability files
    /// WHEN loaded via the public loader entry point
    /// THEN both files load successfully and carry no `sha256` pin — the
    /// precondition the INFO-summary unpinned count depends on.
    #[tokio::test]
    async fn load_directory_loads_unpinned_files_with_no_sha256_pin() {
        let temp_dir = TempDir::new().unwrap();
        for name in ["cap_a", "cap_b"] {
            let cap_path = temp_dir.path().join(format!("{name}.yaml"));
            let mut file = std::fs::File::create(&cap_path).unwrap();
            writeln!(
                file,
                r"
name: {name}
description: unpinned test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://internal.test
"
            )
            .unwrap();
        }

        let capabilities = CapabilityLoader::load_directory(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 2, "both unpinned files load");
        assert_eq!(
            count_unpinned(&capabilities),
            2,
            "neither file embeds a sha256: pin"
        );
    }
}
