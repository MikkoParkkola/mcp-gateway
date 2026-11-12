// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use crate::config_persistence::keyedit::{self, Change, FieldPath, Segment};
use crate::secret_store::{LOCK_WAIT, NewSecretOwned, PendingSecrets, SecretStore, create_secrets};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Creates an init config and samples, storing its generated admin credential.
/// Returns only the reference. Existing files are refused.
/// # Errors
/// Reports failed publication/cleanup and recovery for any retained entry.
pub(crate) fn write_init_files(
    destination: &Path,
    template: &str,
    samples: &[(PathBuf, &str)],
) -> Result<String, String> {
    let env_store = std::env::var_os("MCP_GATEWAY_SECRETS__STORE");
    write_init_files_with(
        crate::config::keychain::os_secret_store(),
        env_store.as_deref(),
        destination,
        template,
        samples,
    )
}

/// The init writer with explicit inputs for store selection.
/// The environment input is reserved; selection still follows the template.
pub(crate) fn write_init_files_with(
    os: Option<Arc<dyn SecretStore + Send + Sync>>,
    env_store: Option<&std::ffi::OsStr>,
    destination: &Path,
    template: &str,
    samples: &[(PathBuf, &str)],
) -> Result<String, String> {
    let _ = env_store;
    let destination = crate::identity_grants::journal::resolved(destination);
    let dir = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut undo = InitUndo::default();
    let mut reference = String::new();
    let result = crate::config_persistence::edit_config_text(&destination, |current| {
        if current.is_some() {
            return Err("init config already exists; left unchanged".into());
        }
        let choice = crate::config::Config::from_file_text(template)
            .map_err(|e| e.to_string())?
            .secrets
            .store;
        let field = FieldPath(vec![
            Segment::Key("auth".into()),
            Segment::Key("bearer_token".into()),
        ]);
        let slot = field.slot();
        let template = keyedit::edit_in_place(template, &[(field, Change::Secret(slot.clone()))])
            .map_err(|_| "cannot prepare init bearer slot".to_owned())?;
        if template.slot_ids().count() != 1
            || template.bytes().len() + 4 * crate::secret_store::MAX_REFERENCE_LEN + 2
                > crate::yaml::MAX_YAML_BYTES
        {
            return Err("init template exceeds slot or size bounds".into());
        }
        for (path, _) in samples {
            if crate::identity_grants::journal::resolved(path) == destination
                || path.try_exists().map_err(|e| e.to_string())?
            {
                return Err(format!("{} is not an absent sample target", path.display()));
            }
        }
        let chosen =
            crate::secret_store::choose_with(choice, dir, os).map_err(|e| e.to_string())?;
        crate::secret_store::log_choice(choice, &chosen);
        let vault = crate::secret_store::Vault::for_config_dir(dir).map_err(|e| e.to_string())?;
        let secret = NewSecretOwned {
            field: slot.display(),
            value: crate::wiped_bytes::WipedBytes::new(
                crate::random_secret::random_secret("mcpgw_").into_bytes(),
            ),
        };
        undo.pending = Some(create_secrets(vault, chosen.store, &[secret], std::time::Instant::now() + LOCK_WAIT)
            .map_err(|_| "init store failed; inspect unused entries with doctor and remove any orphan before retrying".to_owned())?);
        let refs = undo
            .pending
            .as_ref()
            .map(PendingSecrets::refs)
            .unwrap_or_default();
        if refs.len() != 1 || refs[0].len() > crate::secret_store::MAX_REFERENCE_LEN {
            return Err("init store returned invalid references".into());
        }
        reference.clone_from(&refs[0]);
        let bytes = template
            .fill(&std::collections::BTreeMap::from([(
                slot,
                reference.clone(),
            )]))
            .map_err(|_| "cannot fill init bearer slot".to_owned())?;
        let text = String::from_utf8(bytes).map_err(|_| "invalid init text".to_owned())?;
        for (path, content) in samples {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let file =
                std::fs::File::create_new(path).map_err(|e| format!("{}: {e}", path.display()))?;
            undo.files.push((path.clone(), file));
            let file = &mut undo.files.last_mut().ok_or("missing init sample")?.1;
            file.write_all(content.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
        // From here an unwind can follow a landed rename: never discard then.
        undo.may_publish = true;
        Ok(Some(text))
    });
    if result.is_ok() {
        if let Some(pending) = undo.pending.take() {
            pending.keep();
        }
        undo.files.clear();
        return Ok(reference);
    }
    // A handled failure may discard only after confirming absence.
    undo.may_publish &= !matches!(destination.try_exists(), Ok(false));
    let mut error = result
        .err()
        .unwrap_or_else(|| "init was not written".into());
    let retained = undo.rollback();
    if !retained.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(
            error,
            "; recovery required: retained {retained:?}. Inspect the config; remove partial init files and orphan store entries, then rerun init"
        );
    }
    Err(error)
}

#[derive(Default)]
struct InitUndo {
    pending: Option<PendingSecrets>,
    files: Vec<(PathBuf, std::fs::File)>,
    may_publish: bool,
}
impl InitUndo {
    fn rollback(&mut self) -> Vec<String> {
        let mut retained = Vec::new();
        for (path, file) in self.files.drain(..).rev() {
            let same = same_sample(&path, &file);
            drop(file);
            if !same || std::fs::remove_file(&path).is_err() {
                retained.push(path.display().to_string());
            }
        }
        if let Some(pending) = self.pending.take() {
            if self.may_publish {
                retained.extend_from_slice(pending.refs());
                pending.abandon();
            } else {
                retained.extend(pending.discard());
            }
        }
        retained
    }
}
impl Drop for InitUndo {
    fn drop(&mut self) {
        let retained = self.rollback();
        if !retained.is_empty() {
            tracing::warn!(?retained, "init recovery required");
        }
    }
}
fn same_sample(path: &Path, file: &std::fs::File) -> bool {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        file.metadata()
            .ok()
            .zip(std::fs::symlink_metadata(path).ok())
            .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
    }
    #[cfg(windows)]
    {
        std::fs::File::open(path)
            .ok()
            .and_then(|f| crate::win_acl::file_identity(&f).ok())
            .zip(crate::win_acl::file_identity(file).ok())
            .is_some_and(|(a, b)| a == b)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, file);
        false
    }
}
