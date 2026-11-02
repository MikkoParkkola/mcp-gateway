// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The registry's record of each backend's configured credentials, and the
//! scrub of stored answers against every value set it retains.

use std::sync::Arc;

use super::{Backend, BackendRegistry};

impl BackendRegistry {
    /// The backend names registered now whose configured credentials differ
    /// from `configured`'s record for them (a name the map lacks counts as
    /// empty). Names only. A reload makes each such backend modified, so its
    /// instance is replaced and the new one seeded.
    pub(crate) fn marking_changes(
        &self,
        configured: &crate::config::configured_secrets::ConfiguredByBackend,
    ) -> Vec<String> {
        let empty = crate::config::configured_secrets::ConfiguredSecrets::default();
        let instances: Vec<Arc<Backend>> = self
            .backends
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let mut names: Vec<String> = instances
            .iter()
            .filter(|backend| {
                backend.configured_record() != *configured.get(&backend.name).unwrap_or(&empty)
            })
            .map(|backend| backend.name.clone())
            .collect();
        names.sort();
        names
    }

    /// Scrubs a stored answer on its way out against every value set this
    /// registry retains: registered backends and removed ones still inside
    /// their grace. The sets are collected first, so no map guard is held
    /// while it scrubs.
    pub(crate) fn scrub_stored(
        &self,
        response: &mut crate::protocol::JsonRpcResponse,
    ) -> crate::security::needles::Scrubbed {
        crate::security::needles::scrub_stored(&self.retained_sets(), response)
    }

    /// Every value set this registry retains, registered or removed, by
    /// backend name: where one set's redaction meets another's value, the
    /// order decides between a redaction and a refusal, so it must not be
    /// the map's (seeded per process).
    fn retained_sets(&self) -> Vec<Arc<crate::security::needles::NeedleSet>> {
        let mut sets: Vec<_> = self
            .needles
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        sets.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        sets.into_iter().map(|(_, set)| set).collect()
    }

    /// [`Self::scrub_stored`] for a stored tool result held as a bare value;
    /// an `Err` is the refusal to deliver instead.
    pub(crate) fn scrub_stored_value(
        &self,
        value: &mut serde_json::Value,
    ) -> crate::Result<crate::security::needles::Scrubbed> {
        crate::security::needles::scrub_stored_value(&self.retained_sets(), value)
    }

    /// [`Self::scrub_stored`] for a stored error's message text; an `Err` is
    /// the refusal to deliver instead.
    pub(crate) fn scrub_stored_text(
        &self,
        text: &mut String,
    ) -> crate::Result<crate::security::needles::Scrubbed> {
        crate::security::needles::scrub_stored_text(&self.retained_sets(), text)
    }

    /// Test hook: holds `value` as a configured secret of `name` from now on,
    /// as a reload that marks it would, without replacing the instance.
    #[cfg(test)]
    pub(crate) fn mark_for_test(&self, name: &str, value: &str) {
        use crate::config::configured_secrets::{
            ConfiguredSecret, ConfiguredSecrets, SecretOrigin,
        };
        let set = self
            .needles
            .get(name)
            .map(|entry| Arc::clone(entry.value()));
        let set = set.unwrap_or_else(|| panic!("{name} holds no value set"));
        set.pin_configured(
            name,
            &ConfiguredSecrets::of(vec![ConfiguredSecret {
                field: "headers.X-Marked".to_owned(),
                value: value.to_owned(),
                origin: SecretOrigin::Explicit,
            }]),
        );
    }

    /// Test hook: fills `name`'s value set past its bound, so it refuses.
    #[cfg(test)]
    pub(crate) fn overflow_for_test(&self, name: &str) {
        let set = self
            .needles
            .get(name)
            .map(|entry| Arc::clone(entry.value()));
        let set = set.unwrap_or_else(|| panic!("{name} holds no value set"));
        for i in 0..=crate::security::needles::MAX_NEEDLES {
            set.insert(name, &format!("overflow-value-{i:05}"));
        }
        assert!(set.overflowed(), "premise: the set refuses");
    }

    /// Makes `configured` the record a backend registering from now on is
    /// seeded with: set at startup before the register loop, and by a reload
    /// before it applies its patch.
    pub(crate) fn set_load_record(
        &self,
        configured: crate::config::configured_secrets::ConfiguredByBackend,
    ) {
        *self.configured.write() = Arc::new(configured);
        self.record_armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether this load's record was set since the last patch took it:
    /// `apply_patch` asserts it, so a patch applied without its load's record
    /// (which would seed new instances from an older load) fails in tests.
    pub(crate) fn take_load_record(&self) -> bool {
        self.record_armed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
#[path = "registry_secret_record_tests.rs"]
mod tests;
