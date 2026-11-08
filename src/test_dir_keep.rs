// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A store's test-only share of the temporary directory it lives in, so the
//! directory is removed only after the store's last handle drops: a write
//! still in flight when its test ends lands before the directory goes.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

/// Held as a store field; set once, by [`Self::keep`].
#[derive(Debug, Default)]
pub(crate) struct TestDirKeep {
    dir: OnceLock<Arc<tempfile::TempDir>>,
    /// Set by the gateway's own openers: a test that builds a gateway never
    /// holds the store, so it has nothing to keep it with.
    opened_by_gateway: AtomicBool,
}

impl TestDirKeep {
    /// The gateway opened this store, not a test.
    pub(crate) fn opened_by_gateway(&self) {
        self.opened_by_gateway.store(true, Ordering::Relaxed);
    }

    /// A worker is about to start on this store. A store a test opened
    /// itself must keep its directory first, or a late write from the worker
    /// can land while the directory is being removed.
    pub(crate) fn assert_kept(&self, worker: &str) {
        assert!(
            self.dir.get().is_some() || self.opened_by_gateway.load(Ordering::Relaxed),
            "{worker} started on a store whose test never kept its directory; call keep_test_dir"
        );
    }

    /// Keep `dir` for a store living at `store_path`. The store must live
    /// inside `dir`, and a second call must name the same directory: keeping
    /// another one would leave this store's directory unowned.
    pub(crate) fn keep(&self, dir: Arc<tempfile::TempDir>, store_path: &Path) {
        assert!(
            store_path.starts_with(dir.path()),
            "a store at {} keeps {}, a directory it does not live in",
            store_path.display(),
            dir.path().display()
        );
        if let Err(other) = self.dir.set(dir) {
            let kept = self.dir.get().expect("set");
            assert!(
                Arc::ptr_eq(kept, &other),
                "a store keeps one test directory"
            );
        }
    }
}

// The registry of kept temp dirs. A transparency log opened
// inside a dir from `kept_tempdir()` keeps that dir, and every registered dir
// containing it, until its last handle drops; a log opened in an unregistered
// temp dir is reported. The registry holds only `Weak`s, so it never keeps a
// dir alive by itself.

/// Each registered dir in normal form and as its absolute path as written,
/// and a `Weak` of it: the registry never keeps a dir alive by itself.
/// Advisory state, so a panic while it is held does not poison every later
/// test's lookup.
struct Entry {
    normal: std::path::PathBuf,
    written: std::path::PathBuf,
    dir: Weak<tempfile::TempDir>,
}
static KEPT_DIRS: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn registry() -> MutexGuard<'static, Vec<Entry>> {
    KEPT_DIRS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register(dir: tempfile::TempDir) -> Arc<tempfile::TempDir> {
    let dir = Arc::new(dir);
    let normal = norm(dir.path());
    let written = std::path::absolute(dir.path()).unwrap_or_else(|_| dir.path().to_path_buf());
    let mut entries = registry();
    entries.retain(|entry| entry.dir.strong_count() > 0);
    entries.push(Entry {
        normal,
        written,
        dir: Arc::downgrade(&dir),
    });
    dir
}

/// A temp dir that any transparency log opened inside it keeps.
pub(crate) fn kept_tempdir() -> Arc<tempfile::TempDir> {
    register(tempfile::tempdir().expect("a temp dir"))
}

/// [`kept_tempdir`] with a name prefix, for a helper whose dirs carry one.
pub(crate) fn kept_tempdir_prefixed(prefix: &str) -> Arc<tempfile::TempDir> {
    register(
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("a temp dir"),
    )
}

/// [`kept_tempdir`], created inside `parent`.
pub(crate) fn kept_tempdir_in(parent: &Path) -> Arc<tempfile::TempDir> {
    register(tempfile::tempdir_in(parent).expect("a temp dir"))
}

/// Every live registered dir that contains `path`, in normal form or as
/// written: a log keeps them all. Dropping a parent dir then cannot remove a
/// child dir the log lives in, and a dir holding a symlink the path goes
/// through cannot remove the link while the log still uses it.
pub(crate) fn kept_dirs_for(path: &Path) -> Vec<Arc<tempfile::TempDir>> {
    let normal = norm(path);
    let written = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    registry()
        .iter()
        .filter(|entry| contains(&entry.normal, &normal) || contains(&entry.written, &written))
        .filter_map(|entry| entry.dir.upgrade())
        .collect()
}

/// `path` made absolute, its deepest existing ancestor canonicalised, and the
/// rest re-appended: the one form every comparison here uses (`/tmp` and
/// `/private/tmp` are one dir on macOS). A `..` in the part that does not
/// exist yet is resolved lexically against what came before it. With no
/// ancestor that canonicalises, `path` itself.
pub(crate) fn norm(path: &Path) -> std::path::PathBuf {
    // Resolving a `..` can bring an existing symlink into the part already
    // re-appended (`A/missing/../link`): pass again until nothing changes.
    let mut current = norm_once(path);
    for _ in 0..8 {
        let next = norm_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn norm_once(path: &Path) -> std::path::PathBuf {
    let Ok(mut base) = std::path::absolute(path) else {
        return path.to_path_buf();
    };
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(&base) {
            return rest.iter().rev().fold(canonical, |mut acc, name| {
                if name == ".." {
                    acc.pop();
                } else {
                    acc.push(name);
                }
                acc
            });
        }
        let Some(last) = base.components().next_back() else {
            return path.to_path_buf();
        };
        let name = last.as_os_str().to_owned();
        if !base.pop() {
            return path.to_path_buf();
        }
        rest.push(name);
    }
}

/// Whether `dir` contains `path`, compared per path component: `/r/a` does
/// not contain `/r/ab/x`.
pub(crate) fn contains(dir: &Path, path: &Path) -> bool {
    path.starts_with(dir)
}

/// Whether `path` lies under the process temp dir, or under this thread's
/// [`temp_root_for_test`] root while one is set.
pub(crate) fn under_temp_root(path: &Path) -> bool {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    if let Some(root) = TEMP_ROOT.with(|root| root.borrow().clone()) {
        return contains(&root, &norm(path));
    }
    let root = ROOT.get_or_init(|| norm(&std::env::temp_dir()));
    contains(root, &norm(path))
}

/// While held, this thread judges "under the temp dir" against `root`
/// instead of the process temp dir: a row gets a real "outside" dir as a
/// sibling of `root`, inside a temp dir it owns, without writing anywhere
/// else. Thread-bound, like the state it sets.
pub(crate) struct TempRoot(
    Option<std::path::PathBuf>,
    std::marker::PhantomData<*const ()>,
);

pub(crate) fn temp_root_for_test(root: &Path) -> TempRoot {
    let outer = TEMP_ROOT.with(|slot| slot.replace(Some(norm(root))));
    TempRoot(outer, std::marker::PhantomData)
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let outer = self.0.take();
        TEMP_ROOT.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// The dirs a parent test process keeps for a child it spawned, in
/// `MCP_GATEWAY_TEST_KEPT_DIRS`'s format (`std::env::join_paths`).
pub(crate) fn parse_external(list: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    std::env::split_paths(list)
        .filter(|dir| !dir.as_os_str().is_empty())
        .collect()
}

/// Whether one of `external` contains `path`, both in normal form.
pub(crate) fn is_external_in(external: &[std::path::PathBuf], path: &Path) -> bool {
    let path = norm(path);
    external.iter().any(|dir| contains(&norm(dir), &path))
}

/// Whether this process's parent keeps the dir `path` lies in.
fn is_external(path: &Path) -> bool {
    static EXTERNAL: OnceLock<Vec<std::path::PathBuf>> = OnceLock::new();
    let external = EXTERNAL.get_or_init(|| {
        std::env::var_os("MCP_GATEWAY_TEST_KEPT_DIRS")
            .map(|list| parse_external(&list))
            .unwrap_or_default()
    });
    is_external_in(external, path)
}

/// One unkept open: its kind (`AUDIT_LOG` or `TELEMETRY_WINDOW`), its path,
/// and the test it is attributed to.
pub(crate) type Unkept = (&'static str, std::path::PathBuf, String);

/// The kind a transparency log reports as.
pub(crate) const AUDIT_LOG: &str = "audit log";

/// The kind a protocol-revision telemetry window reports as.
pub(crate) const TELEMETRY_WINDOW: &str = "telemetry window";

std::thread_local! {
    /// The open `expect_unkept` scope on this thread, if any.
    static EXPECTED: std::cell::RefCell<Option<Vec<Unkept>>> =
        const { std::cell::RefCell::new(None) };
    /// This thread's override of the temp root (`temp_root_for_test`).
    static TEMP_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
    /// A row's checkpoint inside the next open (`before_first_fs_call`).
    static CHECKPOINT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Report a log opened at `path` that keeps no registered dir: one line on
/// raw stderr naming the test, for the CI shard check, unless the path is
/// outside the temp dir or a parent process keeps its dir. Inside an
/// `expect_unkept` scope it is recorded there instead.
pub(crate) fn report_unkept(kind: &'static str, path: &Path) {
    if !under_temp_root(path) || is_external(path) {
        return;
    }
    let creator = crate::test_late_write::Creator::default();
    let recorded = EXPECTED.with(|expected| {
        expected.borrow_mut().as_mut().map(|seen| {
            seen.push((kind, path.to_path_buf(), creator.name().to_owned()));
        })
    });
    if recorded.is_none() {
        crate::test_late_write::report(&format!(
            "{kind} at {} is in a temp dir no test kept; created by {}\n",
            path.display(),
            creator.name()
        ));
    }
}

/// While held, an unkept open on this thread is recorded here instead of
/// reported, for a row that opens one on purpose.
pub(crate) struct ExpectUnkept(Option<Vec<Unkept>>, std::marker::PhantomData<*const ()>);

/// Start recording this thread's unkept opens until the guard drops.
pub(crate) fn expect_unkept() -> ExpectUnkept {
    ExpectUnkept(
        EXPECTED.with(|expected| expected.replace(Some(Vec::new()))),
        std::marker::PhantomData,
    )
}

impl ExpectUnkept {
    /// The unkept opens recorded so far, in order: each path and the test
    /// it is attributed to.
    #[allow(
        clippy::unused_self,
        reason = "the record lives in a thread-local; the guard scopes it"
    )]
    pub(crate) fn recorded(&self) -> Vec<Unkept> {
        EXPECTED.with(|expected| expected.borrow().clone().unwrap_or_default())
    }
}

impl Drop for ExpectUnkept {
    fn drop(&mut self) {
        let outer = self.0.take();
        EXPECTED.with(|expected| *expected.borrow_mut() = outer);
    }
}

/// The normalised paths of the registry's entries, live or not yet pruned.
pub(crate) fn registered_paths() -> Vec<std::path::PathBuf> {
    registry()
        .iter()
        .map(|entry| entry.normal.clone())
        .collect()
}

/// A row's checkpoint: `f` runs once, on this thread, inside the next log
/// open after its kept-dir lookup and before the open's first filesystem
/// write (the lookup itself only reads, to canonicalise).
pub(crate) fn before_first_fs_call(f: impl FnOnce() + 'static) {
    CHECKPOINT.with(|slot| *slot.borrow_mut() = Some(Box::new(f)));
}

/// Run and clear this thread's checkpoint, if one is set.
pub(crate) fn run_before_first_fs_call() {
    if let Some(f) = CHECKPOINT.with(|slot| slot.borrow_mut().take()) {
        f();
    }
}

#[path = "test_dir_keep_registry_tests.rs"]
mod registry_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_outside_the_kept_directory_is_refused() {
        let kept = Arc::new(tempfile::tempdir().expect("a directory"));
        let elsewhere = tempfile::tempdir().expect("another directory");
        let refused = std::panic::catch_unwind(|| {
            TestDirKeep::default().keep(Arc::clone(&kept), elsewhere.path());
        });
        assert!(refused.is_err(), "a keep of the wrong directory must fail");
    }

    #[test]
    fn a_second_different_directory_is_refused() {
        let first = Arc::new(tempfile::tempdir().expect("a directory"));
        let second = Arc::new(tempfile::tempdir().expect("another directory"));
        let keep = TestDirKeep::default();
        keep.keep(Arc::clone(&first), &first.path().join("tasks"));
        keep.keep(Arc::clone(&first), &first.path().join("tasks"));
        let refused = std::panic::catch_unwind(|| {
            keep.keep(Arc::clone(&second), &first.path().join("tasks"));
        });
        assert!(refused.is_err(), "a second, different directory must fail");
    }

    #[test]
    fn a_worker_on_an_unkept_test_store_is_refused() {
        let refused = std::panic::catch_unwind(|| TestDirKeep::default().assert_kept("a worker"));
        assert!(refused.is_err(), "an unkept store must not start a worker");
        let kept = Arc::new(tempfile::tempdir().expect("a directory"));
        let keep = TestDirKeep::default();
        keep.keep(Arc::clone(&kept), &kept.path().join("tasks"));
        keep.assert_kept("a worker");
        let gateway = TestDirKeep::default();
        gateway.opened_by_gateway();
        gateway.assert_kept("a worker");
    }
}
