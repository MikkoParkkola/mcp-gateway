// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Linux: the access labels a replacement keeps (`security.selinux`,
//! `security.SMACK64`), and the access ACL a scratch inherits from its folder.

#[cfg(test)]
pub(crate) use fake::{Call, FakeLabels, SetSeen, Times};

/// The label store the writer rows inject in place of the kernel's
/// `security.*` calls, keyed by file identity. Test builds only.
#[cfg(test)]
mod fake {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    /// Which of the writer's label calls an injected errno answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Call {
        /// The target's (or a backup source's) label read.
        Read,
        /// The set on the scratch.
        Set,
        /// The scratch's read-back after a set.
        ReadBack,
        /// The removal of the scratch's access ACL (the kernel's own call
        /// unless an errno is injected).
        AclStrip,
        /// The final check that the scratch still has no access ACL.
        AclRead,
    }

    /// How often an injected errno answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Times {
        /// Only the next matching call.
        Once,
        /// Every matching call.
        Always,
    }

    /// One set on a scratch: the label's name, and the scratch's mode and
    /// size at that moment.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SetSeen {
        pub(crate) name: &'static str,
        pub(crate) mode: u32,
        pub(crate) size: u64,
    }

    #[derive(Default)]
    pub(super) struct Store {
        pub(super) values: HashMap<(u64, u64), HashMap<&'static str, Vec<u8>>>,
        pub(super) errors: Vec<(Call, &'static str, i32, Times)>,
        pub(super) rewrite: Option<(&'static str, Vec<u8>)>,
        pub(super) erange_once: bool,
        pub(super) sets: Vec<SetSeen>,
        /// What a file with no label of that name reads, as a folder's
        /// default context does for a new file.
        pub(super) defaults: HashMap<&'static str, Vec<u8>>,
    }

    /// The store, shared with the row that armed it.
    #[derive(Clone, Default)]
    pub(crate) struct FakeLabels(Arc<Mutex<Store>>);

    fn id(path: &Path) -> (u64, u64) {
        let meta = std::fs::symlink_metadata(path).expect("a labelled file exists");
        (meta.dev(), meta.ino())
    }

    impl FakeLabels {
        pub(super) fn store(&self) -> MutexGuard<'_, Store> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Gives the file at `path` the label `name` = `value`.
        pub(crate) fn label(&self, path: &Path, name: &'static str, value: &[u8]) {
            self.store()
                .values
                .entry(id(path))
                .or_default()
                .insert(name, value.to_vec());
        }

        /// The label `name` of the file at `path`, if it has one.
        pub(crate) fn get(&self, path: &Path, name: &str) -> Option<Vec<u8>> {
            self.store()
                .values
                .get(&id(path))
                .and_then(|labels| labels.get(name))
                .cloned()
        }

        /// `call` for `name` answers `errno`, `times`.
        pub(crate) fn fail(&self, call: Call, name: &'static str, errno: i32, times: Times) {
            self.store().errors.push((call, name, errno, times));
        }

        /// Between the next set of `name` and its read-back, the scratch's
        /// value becomes `value`.
        pub(crate) fn rewrite_after_set(&self, name: &'static str, value: &[u8]) {
            self.store().rewrite = Some((name, value.to_vec()));
        }

        /// The next sized read answers `ERANGE`, as when the label grew
        /// between the length probe and the read.
        pub(crate) fn erange_once(&self) {
            self.store().erange_once = true;
        }

        /// Every set so far, in order.
        pub(crate) fn sets(&self) -> Vec<SetSeen> {
            self.store().sets.clone()
        }

        /// Any file without its own `name` label reads `value`.
        pub(crate) fn folder_default(&self, name: &'static str, value: &[u8]) {
            self.store().defaults.insert(name, value.to_vec());
        }
    }
}
