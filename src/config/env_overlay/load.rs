// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Loading env files into an [`EnvOverlay`], and finding where a key was assigned.

use super::{
    EnvOverlay, Error, Path, PathBuf, Result, line_number_of, substitution_naming_defined_key,
};

impl EnvOverlay {
    /// Overlay for already-resolved paths.
    ///
    /// Unreadable or malformed files are warned about and skipped, matching the
    /// tolerance the process-mutating loader had.
    #[must_use]
    pub fn from_paths(paths: &[PathBuf]) -> Self {
        let mut overlay = Self::default();
        for path in paths {
            overlay.apply_file_tolerant(path);
        }
        overlay
    }

    /// As [`EnvOverlay::from_paths`], but a malformed file is an error.
    ///
    /// The diagnostic is rebuilt rather than forwarded: `dotenvy`'s own
    /// `Display` echoes the offending line, which would put a secret into a log
    /// line written because a secret was mistyped.
    pub fn from_paths_checked(paths: &[PathBuf]) -> Result<Self> {
        let mut overlay = Self::default();
        for path in paths {
            overlay.apply_file(path)?;
        }
        Ok(overlay)
    }

    /// Applies one env file, warning rather than failing on malformed content.
    pub(crate) fn apply_file_tolerant(&mut self, path: &Path) {
        if let Err(error) = self.apply_file(path) {
            tracing::warn!("Failed to load env file {}: {error}", path.display());
        }
    }

    /// Applies one env file. A missing file is not an error — the old loader
    /// skipped it silently and configs rely on that for optional files.
    pub(crate) fn apply_file(&mut self, path: &Path) -> Result<()> {
        // `try_exists`, not `exists`: a lookup that fails (a link loop, a
        // denied directory) is not absence. Treating it as absence would let a
        // reload succeed and drop every value the file supplied (#1286).
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!("Env file not found (skipped): {}", path.display());
                self.absent.push(path.to_path_buf());
                return Ok(());
            }
            Err(e) => {
                return Err(Error::Config(format!(
                    "Cannot read env file {}: {e}",
                    path.display()
                )));
            }
        }
        // The mode check and the read share one handle (CONFIG.2). A refusal
        // is fatal on the serving loaders and a WARN on the tolerant ones,
        // which route through `apply_file_tolerant`.
        let text = super::super::secret_file::read_secret_file(
            path,
            super::super::secret_file::SecretFile::EnvFile,
        )?;
        let iter = dotenvy::from_read_iter(std::io::Cursor::new(text.as_bytes()));
        for entry in iter {
            let (key, value) = entry.map_err(|e| Self::describe(path, &e, Some(&text)))?;
            self.insert(key, value);
        }
        self.sources.push((path.to_path_buf(), text));
        // Debug: a failed reload is retried every poll and would repeat this
        // line; startup logs the resolved list once at INFO instead.
        tracing::debug!("Loaded env file: {}", path.display());
        Ok(())
    }

    /// Where `key` is first assigned, in application order: the env file and
    /// the 1-based line, read from the bytes the overlay was parsed from.
    pub(crate) fn assignment_of(&self, key: &str) -> Option<(PathBuf, usize)> {
        self.sources.iter().find_map(|(path, text)| {
            // ponytail: one assignment per line; a quoted value spanning lines
            // that itself starts `KEY=` would be named instead of its owner.
            text.lines().enumerate().find_map(|(n, line)| {
                let line = line.trim_start();
                let line = line.strip_prefix("export ").map_or(line, str::trim_start);
                let (name, _) = line.split_once('=')?;
                (name.trim() == key).then(|| (path.clone(), n + 1))
            })
        })
    }

    /// The first env file whose own bytes substitute a key these same files
    /// define, with the key named.
    ///
    /// Scans the buffers the parser consumed, never the paths again.
    #[must_use]
    pub(crate) fn substitution_naming_owned_key(&self) -> Option<(PathBuf, String)> {
        self.sources.iter().find_map(|(path, text)| {
            substitution_naming_defined_key(text, &self.owned).map(|key| (path.clone(), key))
        })
    }

    fn insert(&mut self, key: String, value: String) {
        self.owned.insert(key.clone());
        self.vars.insert(key, value);
    }

    /// File, line and category — never the line's content.
    ///
    /// The line number is derived from the parser's own buffer rather than read
    /// off the error: `dotenvy`'s `LineParse` carries a byte offset *within* the
    /// offending line, and reporting that as the line number named line 6 of a
    /// two-line file.
    fn describe(path: &Path, error: &dotenvy::Error, text: Option<&str>) -> Error {
        let where_ = path.display();
        match error {
            dotenvy::Error::LineParse(line, _) => {
                match text.and_then(|text| line_number_of(text, line)) {
                    Some(number) => Error::Config(format!(
                        "Failed to parse env file {where_} line {number}: the line is not a \
                         KEY=value assignment. The offending text is withheld because env files \
                         carry secrets."
                    )),
                    None => Error::Config(format!(
                        "Failed to parse env file {where_}: a line is not a KEY=value assignment. \
                         The offending text is withheld because env files carry secrets."
                    )),
                }
            }
            dotenvy::Error::Io(io) => {
                Error::Config(format!("Cannot read env file {where_}: {}", io.kind()))
            }
            _ => Error::Config(format!("Cannot load env file {where_}: malformed content.")),
        }
    }
}
