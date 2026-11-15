// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a load read, captured for the config revision.

use std::collections::BTreeSet;

use super::config_file::ConfigFile;
use super::env_overlay::SecretFileDigests;
use super::{Config, EnvOverlay, OverlayEnv, ResolvedEnvFiles, secret_ref};
use crate::config_reload::revision::{CapabilityPart, RawBytes, RawInputs};

impl Config {
    /// The capability part a startup revision carries.
    ///
    /// Stub: today's empty loaded list, whichever way `capabilities.enabled`
    /// reads. The two arms are where the real ones land: enabled has not read
    /// the files, disabled is this empty catalogue.
    #[allow(
        clippy::if_same_then_else,
        reason = "stub: both readings return today's empty loaded list"
    )]
    pub(crate) fn capability_part(&self) -> CapabilityPart<RawBytes> {
        if self.capabilities.enabled {
            CapabilityPart::Loaded(Vec::new())
        } else {
            CapabilityPart::Loaded(Vec::new())
        }
    }

    /// What a resolving evaluation read: the file's bytes, each env file's
    /// parsed bytes, and every value it consumed from outside the files.
    /// A `SecretRef` resolved lazily after load is not an input of the load.
    pub(super) fn raw_inputs(
        &self,
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
            capabilities: self.capability_part(),
            consumed,
        }
    }
}
