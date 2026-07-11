// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability directory loader

use super::{
    CapabilityDefinition, IssueSeverity, parse_capability_file, validate_capability,
    validate_capability_definition,
};
use crate::{Error, Result};
use std::path::Path;
use tracing::{debug, info, warn};

/// Loader for capability definitions from directories
pub struct CapabilityLoader;

impl CapabilityLoader {
    /// Load all capabilities from a directory (recursive)
    ///
    /// Emits one INFO-level summary line (`N loaded, M unpinned`) per
    /// directory rather than one line per unpinned file — pinning is opt-in
    /// per file by design, so an unpinned public catalog is expected, not a
    /// misconfiguration to warn about file-by-file. Per-file detail (path +
    /// computed hash) is still available at DEBUG via
    /// [`super::parser::parse_capability_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if the directory does not exist or is not a valid directory.
    pub async fn load_directory(path: &str) -> Result<Vec<CapabilityDefinition>> {
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

        let mut capabilities = Vec::new();
        Self::load_directory_recursive(path, &mut capabilities).await?;

        let unpinned = count_unpinned(&capabilities);
        info!(
            count = capabilities.len(),
            unpinned,
            path = %path.display(),
            "Loaded capabilities: {} loaded, {unpinned} unpinned",
            capabilities.len(),
        );

        Ok(capabilities)
    }

    /// Recursively load capabilities from a directory
    async fn load_directory_recursive(
        dir: &Path,
        capabilities: &mut Vec<CapabilityDefinition>,
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
                Box::pin(Self::load_directory_recursive(&path, capabilities)).await?;
            } else if path
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                // Load YAML files
                match Self::load_capability_file(&path).await {
                    Ok(cap) => {
                        debug!(name = %cap.name, path = %path.display(), "Loaded capability");
                        capabilities.push(cap);
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path.display(), "Failed to load capability");
                    }
                }
            }
        }

        Ok(())
    }

    /// Load and validate a single capability file.
    ///
    /// Runs both the legacy `validate_capability` check and the structural
    /// validator.  Structural errors cause the capability to be skipped (this
    /// function returns `Err`); structural warnings are logged but the capability
    /// is still loaded.
    async fn load_capability_file(path: &Path) -> Result<CapabilityDefinition> {
        let capability = parse_capability_file(path).await?;
        validate_capability(&capability)?;

        let path_str = path.to_string_lossy();
        let issues = validate_capability_definition(&capability, Some(&path_str));

        let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);

        for issue in &issues {
            if issue.severity == IssueSeverity::Error {
                warn!(
                    code = issue.code,
                    field = ?issue.field,
                    path = %path_str,
                    "Structural validation error: {}",
                    issue.message,
                );
            } else {
                warn!(
                    code = issue.code,
                    field = ?issue.field,
                    path = %path_str,
                    "Structural validation warning: {}",
                    issue.message,
                );
            }
        }

        if has_errors {
            return Err(Error::Config(format!(
                "Capability '{}' has {} structural error(s); skipping",
                path_str,
                issues
                    .iter()
                    .filter(|i| i.severity == IssueSeverity::Error)
                    .count(),
            )));
        }

        Ok(capability)
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

/// Count how many `capabilities` have no `sha256:` pin.
///
/// Pinning is opt-in per file by design (see
/// [`super::parser::parse_capability_file`]); this count feeds the
/// directory-level `N loaded, M unpinned` summary log so an operator can see
/// catalog pin coverage at a glance instead of scanning one INFO line per
/// unpinned file (MIK-6742).
fn count_unpinned(capabilities: &[CapabilityDefinition]) -> usize {
    capabilities.iter().filter(|c| c.sha256.is_none()).count()
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
