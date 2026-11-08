// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a load read, captured for the config revision.

use std::collections::BTreeSet;

use super::config_file::ConfigFile;
use super::env_overlay::SecretFileDigests;
use super::{Config, EnvOverlay, OverlayEnv, ResolvedEnvFiles, secret_ref};
use crate::config_reload::revision::RawInputs;

impl Config {
    /// What a resolving evaluation read: the file's bytes, each env file's
    /// parsed bytes, and every value it consumed from outside the files.
    /// A `SecretRef` resolved lazily after load is not an input of the load.
    pub(super) fn raw_inputs(
        path: Option<&ConfigFile>,
        overlay: &EnvOverlay,
        env_paths: &ResolvedEnvFiles,
        secret_refs: &BTreeSet<String>,
        files: &SecretFileDigests,
    ) -> RawInputs {
        use crate::config_reload::revision::{ConsumedInput, ConsumedSource};
        let text = path.map_or("", ConfigFile::text);
        let env_names = secret_refs
            .iter()
            .map(String::as_str)
            .chain(secret_ref::template_names(text));
        let mut consumed: Vec<_> = env_names
            .filter_map(|name| {
                let value = overlay.resolve(name)?;
                Some(ConsumedInput {
                    source: ConsumedSource::EnvVar,
                    name: name.to_owned(),
                    value: value.into_bytes(),
                })
            })
            .collect();
        consumed.extend(
            OverlayEnv::new(overlay)
                .overrides(std::env::vars_os())
                .into_iter()
                .map(|(name, _, value)| ConsumedInput {
                    source: ConsumedSource::ProcessOverride,
                    name,
                    value: value.into_bytes(),
                }),
        );
        consumed.extend(files.iter().map(|(file, &digest)| ConsumedInput {
            source: ConsumedSource::SecretFile,
            name: file.to_string_lossy().into_owned(),
            value: digest.map(Vec::from).unwrap_or_default(),
        }));
        RawInputs {
            gateway_yaml: text.as_bytes().to_vec(),
            grants: None,
            env_files: overlay.env_file_inputs(env_paths.as_paths()),
            capabilities: Vec::new(),
            consumed,
        }
    }
}
