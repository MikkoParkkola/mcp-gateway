// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `accounts` block's secret references, recorded after validation (#2248).

use std::collections::BTreeSet;

use super::Config;
use super::env_overlay::{SecretFileDigests, SecretRefsRead, digest};
use super::secret_ref::{self, SecretRef};

impl Config {
    /// The `accounts` block's secret references: names, and a digest of each
    /// `file:` target, for reload's rotation report.
    ///
    /// Empty when the store is disabled AND no adapter is configured: then no
    /// holder ever reads them. An adapter runs with the store disabled and
    /// resolves its own secret and the store keys (no-reuse check), so its
    /// references are recorded either way.
    ///
    /// NAMES ONLY: the `env:` spellings stay in the config, so a rewrite cannot
    /// persist decoded key or signing material. Run only after validation, so a
    /// malformed block never opens a file (#2248).
    pub(super) fn record_account_refs(&self) -> SecretRefsRead {
        let (mut seen, mut files) = (BTreeSet::new(), SecretFileDigests::new());
        let Some(accounts) = self
            .accounts
            .as_ref()
            .filter(|a| a.enabled || !a.adapters.is_empty())
        else {
            return (seen, files);
        };
        let references = accounts.keys.values().chain(
            accounts
                .adapters
                .iter()
                .map(|adapter| &adapter.hmac_secret_ref),
        );
        for reference in references {
            match SecretRef::parse(reference) {
                SecretRef::Env(name) => {
                    seen.insert(name.to_string());
                }
                SecretRef::File(path) => {
                    let value = secret_ref::read_file_ref("", path).ok();
                    files.insert(path.to_path_buf(), value.as_deref().map(digest));
                }
                SecretRef::Literal(_) => {}
            }
        }
        (seen, files)
    }
}
