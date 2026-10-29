// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One call's path resolution (design section 4): a no-follow walk, links
//! resolved by canonicalising the prefix, the equivalent-spelling check on
//! every existing component and the first missing one, and the entry cap.
//! Every read goes through a [`Resolve`] against the call's one deadline,
//! and roots, prefixes and listings are cached within the call.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use super::{Clock, DIRECTORY_ENTRY_CAP, EntryKind, Resolve, ResolveOp, Resolved, RootReason};

pub(super) struct Walk<'a> {
    io: &'a dyn Resolve,
    clock: &'a dyn Clock,
    deadline: Instant,
    canonical: HashMap<PathBuf, Result<PathBuf, std::io::ErrorKind>>,
    listings: HashMap<PathBuf, Result<Vec<OsString>, RootReason>>,
}

impl<'a> Walk<'a> {
    pub(super) fn new(io: &'a dyn Resolve, clock: &'a dyn Clock, deadline: Instant) -> Self {
        Self {
            io,
            clock,
            deadline,
            canonical: HashMap::new(),
            listings: HashMap::new(),
        }
    }

    /// One read, refused `timeout` once the call's deadline has passed: no
    /// read starts after it.
    fn read(&self, op: ResolveOp) -> Result<std::io::Result<Resolved>, RootReason> {
        if self.clock.now() >= self.deadline {
            return Err(RootReason::Timeout);
        }
        Ok(self.io.resolve(&op, self.deadline))
    }

    fn canonicalize(
        &mut self,
        path: &Path,
    ) -> Result<Result<PathBuf, std::io::ErrorKind>, RootReason> {
        if let Some(known) = self.canonical.get(path) {
            return Ok(known.clone());
        }
        let got = match self.read(ResolveOp::Canonicalize(path.to_path_buf()))? {
            Ok(Resolved::Path(p)) => Ok(p),
            Ok(_) => Err(std::io::ErrorKind::InvalidData),
            Err(e) => Err(e.kind()),
        };
        self.canonical.insert(path.to_path_buf(), got.clone());
        Ok(got)
    }

    /// A root's canonical form; any failure is `root_unresolvable`, but a
    /// timeout stays a timeout.
    pub(super) fn root(&mut self, root: &Path) -> Result<PathBuf, RootReason> {
        self.canonicalize(root)?
            .map_err(|_| RootReason::RootUnresolvable)
    }

    /// The names in `dir`, read once per call. A failed listing or entry is
    /// `unresolvable`, never an empty folder; more than the cap is
    /// `directory_too_large`, never skipped.
    fn listing(&mut self, dir: &Path) -> Result<Vec<OsString>, RootReason> {
        if let Some(known) = self.listings.get(dir) {
            return known.clone();
        }
        let got = match self.read(ResolveOp::ReadDir(dir.to_path_buf()))? {
            Ok(Resolved::Entries(entries)) if entries.len() > DIRECTORY_ENTRY_CAP => {
                Err(RootReason::DirectoryTooLarge)
            }
            Ok(Resolved::Entries(entries)) => entries
                .into_iter()
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| RootReason::Unresolvable),
            _ => Err(RootReason::Unresolvable),
        };
        self.listings.insert(dir.to_path_buf(), got.clone());
        got
    }

    /// The equivalent-spelling rule for `name` in `dir`: refused when more
    /// than one entry shares its key, or when `name` is missing and any
    /// entry does.
    fn spelling(
        &mut self,
        dir: &Path,
        name: &std::ffi::OsStr,
        exists: bool,
    ) -> Result<(), RootReason> {
        let wanted = key(name);
        let sharing = self
            .listing(dir)?
            .iter()
            .filter(|entry| match (&wanted, key(entry)) {
                (Some(w), Some(k)) => *w == k,
                // A name that is not UTF-8 has no key: bytes only.
                _ => entry.as_os_str() == name,
            })
            .count();
        if sharing > 1 || (!exists && sharing > 0) {
            return Err(RootReason::EquivalentSpelling);
        }
        Ok(())
    }

    /// Where `value` resolves: its existing prefix canonicalised (links
    /// followed only there), then the missing remainder, which holds no `.`
    /// or `..` after the precheck.
    pub(super) fn resolve(&mut self, value: &Path) -> Result<PathBuf, RootReason> {
        let mut current = PathBuf::new();
        let mut components = value.components().peekable();
        while let Some(c) = components.peek() {
            match c {
                Component::Prefix(_) | Component::RootDir => {
                    current.push(c.as_os_str());
                    components.next();
                }
                _ => break,
            }
        }
        while let Some(component) = components.next() {
            let name = component.as_os_str();
            let next = current.join(name);
            match self.read(ResolveOp::Metadata(next.clone()))? {
                Ok(Resolved::Kind(kind)) => {
                    self.spelling(&current, name, true)?;
                    current = if kind == EntryKind::Symlink {
                        match self.canonicalize(&next)? {
                            Ok(target) => target,
                            Err(std::io::ErrorKind::NotFound) => {
                                return Err(RootReason::DanglingLink);
                            }
                            Err(_) => return Err(RootReason::Unresolvable),
                        }
                    } else {
                        next
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.spelling(&current, name, false)?;
                    let base = self
                        .canonicalize(&current)?
                        .map_err(|_| RootReason::Unresolvable)?;
                    return Ok(components.fold(base.join(name), |p, c| p.join(c.as_os_str())));
                }
                _ => return Err(RootReason::Unresolvable),
            }
        }
        self.canonicalize(&current)?
            .map_err(|_| RootReason::Unresolvable)
    }
}

/// The reference filesystem server's match key: NFC, with every Unicode
/// space separator read as a plain space. `None` for a name that is not
/// UTF-8.
fn key(name: &std::ffi::OsStr) -> Option<String> {
    static SPACES: OnceLock<regex::Regex> = OnceLock::new();
    let spaces = SPACES.get_or_init(|| regex::Regex::new(r"\p{Zs}").expect("a valid class"));
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(name.to_str()?);
    Some(spaces.replace_all(&nfc, " ").into_owned())
}

/// The real filesystem.
pub(super) struct Real;

impl Resolve for Real {
    fn resolve(&self, op: &ResolveOp, _deadline: Instant) -> std::io::Result<Resolved> {
        match op {
            ResolveOp::Metadata(p) => {
                let t = std::fs::symlink_metadata(p)?.file_type();
                Ok(Resolved::Kind(if t.is_symlink() {
                    EntryKind::Symlink
                } else if t.is_dir() {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                }))
            }
            ResolveOp::Canonicalize(p) => std::fs::canonicalize(p).map(Resolved::Path),
            ResolveOp::ReadDir(p) => Ok(Resolved::Entries(
                // One past the cap is enough to refuse: never read a huge
                // folder to the end.
                std::fs::read_dir(p)?
                    .take(DIRECTORY_ENTRY_CAP + 1)
                    .map(|e| e.map(|e| e.file_name()))
                    .collect(),
            )),
        }
    }
}

/// The system clock.
pub(super) struct System;

impl Clock for System {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Resolver threads. A call takes one free slot or is refused at once; a
/// read still blocked in a syscall keeps its slot.
pub(crate) struct Pool {
    jobs: std::sync::Mutex<std::sync::mpsc::Sender<Job>>,
    free: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Pool {
    pub(crate) fn new(threads: usize) -> std::sync::Arc<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<Job>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        for i in 0..threads {
            let rx = std::sync::Arc::clone(&rx);
            std::thread::Builder::new()
                .name(format!("folder-check-{i}"))
                .spawn(move || {
                    while let Ok(job) = rx.lock().map_or(Err(()), |r| r.recv().map_err(|_| ())) {
                        job();
                    }
                })
                .expect("a resolver thread starts");
        }
        std::sync::Arc::new(Self {
            jobs: std::sync::Mutex::new(tx),
            free: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(threads)),
        })
    }

    /// The process's pool, created on first use.
    pub(super) fn shared() -> std::sync::Arc<Self> {
        static SHARED: OnceLock<std::sync::Arc<Pool>> = OnceLock::new();
        std::sync::Arc::clone(SHARED.get_or_init(|| Self::new(super::RESOLVER_THREADS)))
    }

    /// Runs `work` on a free slot; `None` when every slot is held.
    pub(super) fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<std::sync::mpsc::Receiver<T>> {
        use std::sync::atomic::Ordering;
        let mut free = self.free.load(Ordering::Acquire);
        loop {
            if free == 0 {
                return None;
            }
            match self.free.compare_exchange_weak(
                free,
                free - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(now) => free = now,
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let free = std::sync::Arc::clone(&self.free);
        let job: Job = Box::new(move || {
            let _ = tx.send(work());
            free.fetch_add(1, Ordering::AcqRel);
        });
        if self.jobs.lock().map(|jobs| jobs.send(job)).is_err() {
            self.free.fetch_add(1, Ordering::AcqRel);
            return None;
        }
        Some(rx)
    }
}

/// Waits up to `limit` for a pool result. On a multi-thread runtime the
/// wait moves off its worker (`block_in_place`); anywhere else, including
/// a current-thread runtime where that would panic, it waits directly.
pub(super) fn wait<T>(rx: &std::sync::mpsc::Receiver<T>, limit: std::time::Duration) -> Option<T> {
    let recv = || rx.recv_timeout(limit).ok();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(recv)
        }
        _ => recv(),
    }
}
