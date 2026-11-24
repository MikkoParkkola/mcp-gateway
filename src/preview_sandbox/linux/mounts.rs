// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private root `__preview-sandbox` builds and enters (ADR-027, Linux
//! steps 2 and 3).
//!
//! Every call here is a safe rustix or std function. A mount a user namespace
//! inherited keeps its locked flags (`nosuid`, `nodev`, `noexec` and the atime
//! mode): a remount that drops one fails with `EPERM`, so every remount carries
//! the flags the mount already has, read from `/proc/self/mountinfo`.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use rustix::mount::{
    MountFlags, UnmountFlags, mount, mount_bind, mount_bind_recursive, mount_remount, unmount,
};

use super::helper::{SetupFailure, step_call};
use super::plan::{self, Plan};
use crate::preview_sandbox::control_msg::SetupStep;

/// The new root is staged on a tmpfs mounted over `/tmp`, which hides the
/// host's `/tmp` from this mount namespace only. The launcher refuses any
/// plan path under `/tmp` for that reason.
pub(super) const STAGE: &str = "/tmp";
const OLD_ROOT: &str = ".old-root";
const EMPTY_FILE: &str = ".empty";

/// Devices bound from the host: the first two writable, `urandom` read-only.
const DEVICES: [(&str, bool); 3] = [
    ("/dev/null", true),
    ("/dev/zero", true),
    ("/dev/urandom", false),
];

/// A setup step: every failure names the step the gateway is told.
type Step = Result<(), SetupFailure>;

/// A failure in words alone: a pure check's, mapped to its step by its
/// caller, or the fetch teardown's own.
type Words = Result<(), String>;

fn at(step: &str, path: &Path) -> impl FnOnce(io::Error) -> String {
    let what = format!("{step} {}", path.display());
    move |e| format!("{what} ({e})")
}

/// One fallible call of `step` on `path`, its failure "`verb` `path`
/// (error)"; in a debug build the plan's fault may fail it first.
fn call<T>(
    step: SetupStep,
    verb: &str,
    path: &Path,
    op: impl FnOnce() -> io::Result<T>,
) -> Result<T, SetupFailure> {
    step_call(step, || format!("{verb} {}", path.display()), op)
}

fn staged(path: &str) -> PathBuf {
    Path::new(STAGE).join(path.trim_start_matches('/'))
}

/// Where the fetch's CA trust files sit in the root.
pub(super) const PREVIEW_CONFIG: &str = "/etc/mcp-gateway-preview";

/// Where the gateway proxy's Unix socket is bound for an npm fetch (D5): a
/// file on the root's own `/tmp`, so the helper alone can unmount and remove
/// it before the run.
pub(super) const PROXY_SOCKET: &str = "/tmp/proxy.sock";

/// Build the whole root under [`STAGE`], then read every mount back. `ca` is
/// the fetch's CA snapshot, opened before staging covered host `/tmp`.
pub(super) fn build_root(
    plan: &Plan,
    ca: Option<&rustix::fd::OwnedFd>,
    proxy: Option<&rustix::fd::OwnedFd>,
) -> Step {
    let root = Path::new(STAGE);
    call(
        SetupStep::Mounting,
        "mounting the root tmpfs on",
        root,
        || {
            let flags = MountFlags::NOSUID | MountFlags::NODEV;
            Ok(mount("tmpfs", root, "tmpfs", flags, plan::ROOT_SIZE)?)
        },
    )?;
    let empty = root.join(EMPTY_FILE);
    call(SetupStep::Mounting, "creating", &empty, || {
        fs::write(&empty, b"")
    })?;

    for path in &plan.read_only {
        bind_read_only(Path::new(path))?;
    }
    for path in &plan.masked {
        mask(plan, Path::new(path), BindBacks::Restore)?;
    }
    // Last, and with nothing bound back: a gateway path covers whatever lies
    // beneath it, an interpreter bind-back included.
    for path in &plan.hidden {
        mask(plan, Path::new(path), BindBacks::None)?;
    }
    for (device, writable) in DEVICES {
        bind_device(Path::new(device), writable)?;
    }
    for (path, size) in [(plan::HOME, plan::HOME_SIZE), ("/tmp", plan::TMP_SIZE)] {
        let target = staged(path);
        call(SetupStep::Mounting, "creating", &target, || {
            fs::create_dir_all(&target)
        })?;
        call(SetupStep::Mounting, "mounting a tmpfs on", &target, || {
            let flags = MountFlags::NOSUID | MountFlags::NODEV;
            Ok(mount("tmpfs", &target, "tmpfs", flags, size)?)
        })?;
    }
    let proc = staged("/proc");
    call(SetupStep::Mounting, "creating", &proc, || {
        fs::create_dir_all(&proc)
    })?;
    // The PID namespace's own /proc (`--mount-proc` made one fully visible, so
    // the kernel lets a user namespace mount another). `hidepid=2` hides every
    // process the viewer cannot ptrace: the target runs as the namespace's
    // root, which owns a non-dumpable helper's `/proc/1/fd` and could list it.
    // `gid=1` is never mapped here, so no group is exempt (by default host
    // group 0 is, and a user namespace cannot drop a supplementary group).
    let proc_flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    let proc_options = c"hidepid=2,gid=1";
    call(SetupStep::Mounting, "mounting proc on", &proc, || {
        Ok(mount("proc", &proc, "proc", proc_flags, proc_options)?)
    })?;
    // Before Linux 5.8 the options live on the PID namespace's one proc
    // superblock, which `--mount-proc` created without them and the mount
    // above reused; a remount applies them there too.
    call(SetupStep::Remounting, "remounting proc on", &proc, || {
        Ok(mount_remount(&proc, proc_flags, proc_options)?)
    })?;
    // After the masks and hidden binds, so nothing covers it.
    if let Some(ca) = ca {
        preview_config(ca)?;
    }
    if let Some(proxy) = proxy {
        proxy_socket(proxy)?;
    }

    verify(plan)
}

/// The preview config's files, checked directly once mounted: exactly
/// `ca.pem`, `empty-certs`, `empty-global.npmrc` and `empty-user.npmrc`; the
/// empty ones empty and of their type (npm refuses one file as both configs); `ca.pem` the snapshot itself, by the device and inode the
/// helper read from the descriptor it bound.
pub(super) fn check_preview_config(snapshot: (u64, u64)) -> Step {
    // The mounts are not as planned: never a denial.
    check_config_dir(&staged(PREVIEW_CONFIG), snapshot)
        .map_err(|detail| SetupFailure::new(SetupStep::Mounting, detail))
}

/// [`check_preview_config`] over any directory, so rows can build one.
fn check_config_dir(dir: &Path, snapshot: (u64, u64)) -> Words {
    use std::os::unix::fs::MetadataExt as _;
    let fail = |why: &str| Err(format!("checking {} ({why})", dir.display()));
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(at("listing", dir))? {
        let entry = entry.map_err(at("listing", dir))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    if names
        != [
            "ca.pem",
            "empty-certs",
            "empty-global.npmrc",
            "empty-user.npmrc",
        ]
    {
        return fail("unexpected entries");
    }
    let certs = dir.join("empty-certs");
    let certs_meta = fs::symlink_metadata(&certs).map_err(at("reading", &certs))?;
    if !certs_meta.is_dir()
        || fs::read_dir(&certs)
            .map_err(at("listing", &certs))?
            .next()
            .is_some()
    {
        return fail("empty-certs is not an empty directory");
    }
    for name in ["empty-global.npmrc", "empty-user.npmrc"] {
        let npmrc = dir.join(name);
        let npmrc_meta = fs::symlink_metadata(&npmrc).map_err(at("reading", &npmrc))?;
        if !npmrc_meta.is_file() || npmrc_meta.len() != 0 {
            return fail(&format!("{name} is not an empty file"));
        }
    }
    let ca = dir.join("ca.pem");
    let ca_meta = fs::symlink_metadata(&ca).map_err(at("reading", &ca))?;
    if !ca_meta.is_file() || (ca_meta.dev(), ca_meta.ino()) != snapshot {
        return fail("ca.pem is not the snapshot");
    }
    Ok(())
}

/// The proxy socket at [`PROXY_SOCKET`]: bound from its descriptor (it may sit
/// under host `/tmp`, which staging covers), then read-only, nosuid, nodev; a
/// socket still accepts a connect on a read-only mount.
fn proxy_socket(proxy: &rustix::fd::OwnedFd) -> Step {
    use std::os::fd::AsRawFd as _;
    let target = staged(PROXY_SOCKET);
    call(SetupStep::Binding, "creating", &target, || {
        fs::write(&target, b"")
    })?;
    let source = PathBuf::from(format!("/proc/self/fd/{}", proxy.as_raw_fd()));
    call(
        SetupStep::Binding,
        "binding the proxy socket on",
        &target,
        || Ok(mount_bind(&source, &target)?),
    )?;
    remount(
        &target,
        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
    )
}

/// The bound proxy socket is the gateway's, by the device and inode the
/// helper read from the descriptor it bound.
pub(super) fn check_proxy_socket(socket: (u64, u64)) -> Step {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let target = staged(PROXY_SOCKET);
    // The mounts are not as planned: never a denial.
    let wrong = |detail: String| SetupFailure::new(SetupStep::Mounting, detail);
    let meta = fs::symlink_metadata(&target).map_err(|e| wrong(at("reading", &target)(e)))?;
    if !meta.file_type().is_socket() || (meta.dev(), meta.ino()) != socket {
        return Err(wrong(format!(
            "checking {} (not the proxy socket)",
            target.display()
        )));
    }
    Ok(())
}

/// After the fetch, in the new root: unmount the proxy socket and remove its
/// file, so nothing of it reaches the run.
pub(super) fn remove_proxy_socket() -> Words {
    let path = Path::new(PROXY_SOCKET);
    unmount(path, UnmountFlags::DETACH)
        .map_err(io::Error::from)
        .map_err(at("unmounting the proxy socket at", path))?;
    fs::remove_file(path).map_err(at("removing", path))?;
    if path.exists() {
        return Err(format!("removing {} (still there)", path.display()));
    }
    Ok(())
}

/// The fetch's CA trust files at [`PREVIEW_CONFIG`]: a tmpfs holding
/// `ca.pem` (the snapshot, bound from its descriptor), an empty `empty-certs`
/// and two empty npmrc files (user and global: npm refuses one file as both);
/// the bind and the tmpfs then read-only.
fn preview_config(ca: &rustix::fd::OwnedFd) -> Step {
    use std::os::fd::AsRawFd as _;
    let dir = staged(PREVIEW_CONFIG);
    call(SetupStep::Mounting, "creating", &dir, || {
        fs::create_dir_all(&dir)
    })?;
    call(SetupStep::Mounting, "mounting a tmpfs on", &dir, || {
        let flags = MountFlags::NOSUID | MountFlags::NODEV;
        Ok(mount("tmpfs", &dir, "tmpfs", flags, plan::MASK_SIZE)?)
    })?;
    let ca_pem = dir.join("ca.pem");
    call(SetupStep::Mounting, "creating", &ca_pem, || {
        fs::write(&ca_pem, b"")
    })?;
    let certs = dir.join("empty-certs");
    call(SetupStep::Mounting, "creating", &certs, || {
        fs::create_dir(&certs)
    })?;
    for name in ["empty-global.npmrc", "empty-user.npmrc"] {
        let npmrc = dir.join(name);
        call(SetupStep::Mounting, "creating", &npmrc, || {
            fs::write(&npmrc, b"")
        })?;
    }
    let source = PathBuf::from(format!("/proc/self/fd/{}", ca.as_raw_fd()));
    call(
        SetupStep::Binding,
        "binding the CA snapshot on",
        &ca_pem,
        || Ok(mount_bind(&source, &ca_pem)?),
    )?;
    remount(
        &ca_pem,
        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
    )?;
    // A tmpfs remount (no bind flag) makes its superblock read-only, as for
    // the masks.
    let verb = "making the preview config read-only at";
    call(SetupStep::Remounting, verb, &dir, || {
        let flags = MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV;
        Ok(mount_remount(&dir, flags, plan::MASK_SIZE)?)
    })
}

/// Bind `path` at the same place in the new root, read-only with every
/// submount, or recreate it as a symlink when the host's is one.
fn bind_read_only(path: &Path) -> Step {
    let target = staged(&path.to_string_lossy());
    let Some(meta) = call(SetupStep::Binding, "reading", path, || {
        fs::symlink_metadata(path)
            .map(Some)
            .or_else(|e| match e.kind() {
                // A runtime path this host does not have (`/etc/pki/tls` on Debian).
                io::ErrorKind::NotFound => Ok(None),
                _ => Err(e),
            })
    })?
    else {
        return Ok(());
    };
    if let Some(parent) = target.parent() {
        call(SetupStep::Binding, "creating", parent, || {
            fs::create_dir_all(parent)
        })?;
    }
    if meta.file_type().is_symlink() {
        let link = call(SetupStep::Binding, "reading the link", path, || {
            fs::read_link(path)
        })?;
        return call(SetupStep::Binding, "linking", &target, || {
            symlink(&link, &target)
        });
    }
    call(SetupStep::Binding, "creating", &target, || {
        if meta.is_dir() {
            fs::create_dir_all(&target)
        } else {
            fs::write(&target, b"")
        }
    })?;
    call(SetupStep::Binding, "binding", path, || {
        Ok(mount_bind_recursive(path, &target)?)
    })?;
    // An initial bind ignores the read-only flag and a remount reaches one
    // mount, so the bind and every submount under it is remounted.
    for mounted in mounts_under(&target)? {
        remount(
            &mounted,
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
        )?;
    }
    Ok(())
}

/// Cover `path` with an empty read-only tmpfs (a directory) or the empty file
/// (a file), binding back any plan path that lies under it first.
/// Whether a mask restores the interpreter's bind-backs beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindBacks {
    /// A system mask (`/usr/local`): the interpreter's directories return.
    Restore,
    /// A gateway path: nothing beneath it returns.
    None,
}

fn mask(plan: &Plan, path: &Path, bind_backs: BindBacks) -> Step {
    let target = staged(&path.to_string_lossy());
    let meta = call(SetupStep::Masking, "reading", &target, || {
        fs::symlink_metadata(&target)
            .map(Some)
            .or_else(|e| match e.kind() {
                // Nothing to hide: the path is not inside any bind.
                io::ErrorKind::NotFound => Ok(None),
                _ => Err(e),
            })
    })?;
    match meta {
        None => return Ok(()),
        Some(meta) if !meta.is_dir() => {
            call(SetupStep::Masking, "masking", path, || {
                Ok(mount_bind(Path::new(STAGE).join(EMPTY_FILE), &target)?)
            })?;
            return remount(
                &target,
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            );
        }
        Some(_) => {}
    }
    call(SetupStep::Masking, "masking", path, || {
        let flags = MountFlags::NOSUID | MountFlags::NODEV;
        Ok(mount("tmpfs", &target, "tmpfs", flags, plan::MASK_SIZE)?)
    })?;
    for back in plan
        .bound_back
        .iter()
        .map(Path::new)
        .filter(|b| bind_backs == BindBacks::Restore && b.starts_with(path))
    {
        // A bind-back is bind_read_only's own call: its failures report as
        // binding (and its remounts as remounting), not as this mask's
        // masking, which covers only mask()'s own calls.
        bind_read_only(back)?;
    }
    // A tmpfs remount (no bind flag) makes the mask's superblock read-only.
    call(
        SetupStep::Remounting,
        "making the mask read-only at",
        &target,
        || {
            let flags = MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV;
            Ok(mount_remount(&target, flags, plan::MASK_SIZE)?)
        },
    )
}

fn bind_device(device: &Path, writable: bool) -> Step {
    let target = staged(&device.to_string_lossy());
    if let Some(parent) = target.parent() {
        call(SetupStep::Binding, "creating", parent, || {
            fs::create_dir_all(parent)
        })?;
    }
    call(SetupStep::Binding, "creating", &target, || {
        fs::write(&target, b"")
    })?;
    call(SetupStep::Binding, "binding", device, || {
        Ok(mount_bind(device, &target)?)
    })?;
    let mut flags = MountFlags::NOSUID | MountFlags::NOEXEC;
    if !writable {
        flags |= MountFlags::RDONLY;
    }
    remount(&target, flags)
}

/// Remount one mount as a bind with `wanted`, keeping the flags it has.
fn remount(target: &Path, wanted: MountFlags) -> Step {
    // The last row at a mount point is the topmost mount there.
    let current = call(
        SetupStep::Remounting,
        "reading",
        Path::new(MOUNTINFO),
        mountinfo,
    )?
    .into_iter()
    .rev()
    .find(|m| m.point == target)
    .map_or(MountFlags::empty(), |m| m.flags);
    let locked = current
        & (MountFlags::NOSUID
            | MountFlags::NODEV
            | MountFlags::NOEXEC
            | MountFlags::NOATIME
            | MountFlags::NODIRATIME
            | MountFlags::RELATIME
            | MountFlags::STRICTATIME);
    call(SetupStep::Remounting, "remounting", target, || {
        Ok(mount_remount(
            target,
            MountFlags::BIND | wanted | locked,
            c"",
        )?)
    })
}

/// Read every mount in the new root back and refuse on any mismatch: all
/// `nosuid`; all read-only and `nodev` except the home, `/tmp`, `/proc` and
/// the writable devices; nothing outside the plan's paths.
///
/// Only mounts descending from the root tmpfs are checked, by mount id: the
/// host's own `/tmp` and anything mounted under it are covered by the root
/// tmpfs but still listed at the same paths.
fn verify(plan: &Plan) -> Step {
    // The mounts are not as planned: never a denial.
    let wrong = |detail: String| SetupFailure::new(SetupStep::Mounting, detail);
    let rows = mountinfo().map_err(|e| wrong(at("reading", Path::new(MOUNTINFO))(e)))?;
    verify_rows(plan, &rows).map_err(wrong)
}

/// [`verify`] over mountinfo `rows`. With a fetch planned, the preview config
/// must be exactly its read-only tmpfs and the read-only `ca.pem` bind (no
/// mount nested under it, neither missing); with none planned, neither exists.
fn verify_rows(plan: &Plan, rows: &[Mount]) -> Words {
    let root = Path::new(STAGE);
    let root_id = rows
        .iter()
        .rev()
        .find(|m| m.point == root)
        .map(|m| m.id)
        .ok_or("verifying the root (no mount at the staging path)")?;
    let writable: Vec<PathBuf> = [plan::HOME, "/tmp", "/proc"]
        .into_iter()
        .map(staged)
        .collect();
    let devices: Vec<(PathBuf, bool)> = DEVICES.into_iter().map(|(d, w)| (staged(d), w)).collect();
    let allowed: Vec<PathBuf> = plan
        .read_only
        .iter()
        .chain(&plan.masked)
        .chain(&plan.hidden)
        .chain(&plan.bound_back)
        .map(|p| staged(p))
        .collect();
    let config = staged(PREVIEW_CONFIG);
    let ca_pem = config.join("ca.pem");
    let (mut saw_config, mut saw_ca) = (false, false);
    let proxy_socket = staged(PROXY_SOCKET);
    let fetcher_planned = plan
        .fetch
        .as_ref()
        .is_some_and(|f| f.npm.is_some() || f.uv.is_some());
    let mut saw_proxy = false;
    for m in rows.iter().filter(|m| descends_from(rows, m, root_id)) {
        let fail = |why: &str| Err(format!("verifying {} ({why})", m.point.display()));
        if !m.flags.contains(MountFlags::NOSUID) {
            return fail("not nosuid");
        }
        if m.point == proxy_socket {
            if !fetcher_planned {
                return fail("a proxy socket with no npm fetch planned");
            }
            saw_proxy = true;
            if !m.flags.contains(MountFlags::RDONLY) || !m.flags.contains(MountFlags::NODEV) {
                return fail("not read-only and nodev");
            }
            continue;
        }
        if m.point.starts_with(&config) {
            if plan.fetch.is_none() {
                return fail("a fetch mount with no fetch planned");
            }
            if m.point == config {
                saw_config = true;
            } else if m.point == ca_pem {
                saw_ca = true;
            } else {
                return fail("nested under the preview config");
            }
            if !m.flags.contains(MountFlags::RDONLY) {
                return fail("writable");
            }
            if !m.flags.contains(MountFlags::NODEV) {
                return fail("not nodev");
            }
            continue;
        }
        if m.point == root || writable.contains(&m.point) {
            continue;
        }
        if let Some((_, writable)) = devices.iter().find(|(d, _)| *d == m.point) {
            if !*writable && !m.flags.contains(MountFlags::RDONLY) {
                return fail("a read-only device is writable");
            }
            continue;
        }
        if !allowed.iter().any(|a| m.point.starts_with(a)) {
            return fail("not in the plan");
        }
        if !m.flags.contains(MountFlags::RDONLY) {
            return fail("writable");
        }
        if !m.flags.contains(MountFlags::NODEV) {
            return fail("not nodev");
        }
    }
    if fetcher_planned && !saw_proxy {
        return Err(format!("verifying {} (missing)", proxy_socket.display()));
    }
    if plan.fetch.is_some() && !(saw_config && saw_ca) {
        return Err(format!(
            "verifying {} (the preview config or its ca.pem is missing)",
            config.display()
        ));
    }
    Ok(())
}

/// `pivot_root` into the staged root, leave nothing of the old one, and make
/// the new root itself read-only.
pub(super) fn enter_root() -> Step {
    let old = Path::new(STAGE).join(OLD_ROOT);
    call(SetupStep::Pivoting, "creating", &old, || {
        fs::create_dir(&old)
    })?;
    call(
        SetupStep::Pivoting,
        "pivoting into",
        Path::new(STAGE),
        || Ok(rustix::process::pivot_root(STAGE, &old)?),
    )?;
    // At once: a working directory left in the old root survives a lazy unmount.
    call(
        SetupStep::Pivoting,
        "changing directory to",
        Path::new("/"),
        || Ok(rustix::process::chdir("/")?),
    )?;
    let old = Path::new("/").join(OLD_ROOT);
    call(
        SetupStep::Pivoting,
        "detaching the old root at",
        &old,
        || Ok(unmount(&old, UnmountFlags::DETACH)?),
    )?;
    call(SetupStep::Pivoting, "removing", &old, || {
        fs::remove_dir(&old)
    })?;
    // Through the same helper as every bind, so the root keeps its locked
    // flags rather than failing the remount with an opaque EPERM.
    remount(
        Path::new("/"),
        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
    )
}

/// `m` is the mount `ancestor` or lies below it in the mount tree.
fn descends_from(rows: &[Mount], m: &Mount, ancestor: u64) -> bool {
    let mut current = Some(m);
    // Bounded by the row count, so a malformed table cannot loop.
    for _ in 0..=rows.len() {
        match current {
            Some(row) if row.id == ancestor => return true,
            Some(row) if row.parent != row.id => {
                current = rows.iter().find(|r| r.id == row.parent);
            }
            _ => return false,
        }
    }
    false
}

/// One `/proc/self/mountinfo` row: ids, the mount point and its per-mount
/// flags.
#[derive(Debug, PartialEq, Eq)]
struct Mount {
    id: u64,
    parent: u64,
    point: PathBuf,
    flags: MountFlags,
}

/// Where the kernel lists this namespace's mounts.
const MOUNTINFO: &str = "/proc/self/mountinfo";

fn mountinfo() -> io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&fs::read_to_string(MOUNTINFO)?))
}

/// Fields 1 and 2 are the mount and parent ids, 5 the mount point
/// (octal-escaped), 6 the per-mount options.
fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let id = fields.next()?.parse().ok()?;
            let parent = fields.next()?.parse().ok()?;
            let mut fields = fields.skip(2);
            let point = unescape(fields.next()?);
            let flags = fields
                .next()?
                .split(',')
                .fold(MountFlags::empty(), |acc, option| {
                    acc | match option {
                        "ro" => MountFlags::RDONLY,
                        "nosuid" => MountFlags::NOSUID,
                        "nodev" => MountFlags::NODEV,
                        "noexec" => MountFlags::NOEXEC,
                        "noatime" => MountFlags::NOATIME,
                        "nodiratime" => MountFlags::NODIRATIME,
                        "relatime" => MountFlags::RELATIME,
                        "strictatime" => MountFlags::STRICTATIME,
                        _ => MountFlags::empty(),
                    }
                });
            Some(Mount {
                id,
                parent,
                point,
                flags,
            })
        })
        .collect()
}

/// The kernel writes space, tab, newline and backslash in a mount point as a
/// three-digit octal escape.
fn unescape(field: &str) -> PathBuf {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = bytes.get(i + 1..i + 4).filter(|_| bytes[i] == b'\\');
        if let Some(byte) =
            escape.and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok())
        {
            out.push(byte);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    PathBuf::from(OsString::from_vec(out))
}

/// `target` and every mount below it.
fn mounts_under(target: &Path) -> Result<Vec<PathBuf>, SetupFailure> {
    let rows = call(
        SetupStep::Remounting,
        "reading",
        Path::new(MOUNTINFO),
        mountinfo,
    )?;
    Ok(rows
        .into_iter()
        .map(|m| m.point)
        .filter(|p| p.starts_with(target))
        .collect())
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "mounts_tests.rs"]
mod tests;
