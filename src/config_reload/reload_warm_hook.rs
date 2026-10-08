// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Builders that attach optional collaborators to a [`ReloadContext`], and the
//! hook a reload uses to tell the server which backends it registered
//! (`MIK-8054`: a backend added or replaced by hot reload is warm-started).

use std::sync::Arc;

use super::ReloadContext;
use crate::config::{Config, LiveEnv};

/// What a fully applied reload changed in the backend registry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredChange {
    /// Backends the reload added or replaced: a new instance is registered.
    pub(crate) registered: Vec<String>,
    /// Backends the reload removed.
    pub(crate) removed: Vec<String>,
}

/// Told about every fully applied reload, after its config is published and
/// while the reload transaction still holds `lock_reload`, so reloads report
/// in commit order against their own config and instances.
pub(crate) type OnRegistered = Arc<dyn Fn(&RegisteredChange, &Config) + Send + Sync>;

impl ReloadContext {
    /// Attach the environment startup published.
    ///
    /// Consuming builder rather than a constructor argument: every existing
    /// call site keeps working, and the one that has a `LiveEnv` says so.
    #[must_use]
    pub fn with_env(mut self, env: Arc<LiveEnv>) -> Self {
        self.env = env;
        self
    }

    /// Attach the hook told which backends each applied reload registered.
    #[must_use]
    pub(crate) fn with_on_registered(mut self, hook: OnRegistered) -> Self {
        self.on_registered = Some(hook);
        self
    }

    /// Report an applied reload to the hook, if one is attached.
    pub(super) fn report_registered(&self, change: &RegisteredChange, config: &Config) {
        if let Some(hook) = &self.on_registered {
            hook(change, config);
        }
    }
}

impl super::ConfigPatch {
    /// The registry change this patch makes once fully applied.
    pub(crate) fn registered_change(&self) -> RegisteredChange {
        let names = |list: &[(String, crate::config::BackendConfig)]| {
            list.iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        };
        let mut registered = names(&self.backends_added);
        registered.extend(names(&self.backends_modified));
        RegisteredChange {
            registered,
            removed: self.backends_removed.clone(),
        }
    }
}
