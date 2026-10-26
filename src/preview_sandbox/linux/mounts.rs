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

use super::plan::{self, Plan};

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

type Step = Result<(), String>;

fn at(step: &str, path: &Path) -> impl FnOnce(io::Error) -> String {
    let what = format!("{step} {}", path.display());
    move |e| format!("{what} ({e})")
}

fn staged(path: &str) -> PathBuf {
    Path::new(STAGE).join(path.trim_start_matches('/'))
}

/// Build the whole root under [`STAGE`], then read every mount back.
pub(super) fn build_root(plan: &Plan) -> Step {
    let root = Path::new(STAGE);
    mount(
        "tmpfs",
        root,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        plan::ROOT_SIZE,
    )
    .map_err(io::Error::from)
    .map_err(at("mounting the root tmpfs on", root))?;
    fs::write(root.join(EMPTY_FILE), b"").map_err(at("creating", &root.join(EMPTY_FILE)))?;

    for path in &plan.read_only {
        bind_read_only(Path::new(path))?;
    }
    for path in &plan.masked {
        mask(plan, Path::new(path))?;
    }
    for (device, writable) in DEVICES {
        bind_device(Path::new(device), writable)?;
    }
    for (path, size) in [(plan::HOME, plan::HOME_SIZE), ("/tmp", plan::TMP_SIZE)] {
        let target = staged(path);
        fs::create_dir_all(&target).map_err(at("creating", &target))?;
        mount(
            "tmpfs",
            &target,
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            size,
        )
        .map_err(io::Error::from)
        .map_err(at("mounting a tmpfs on", &target))?;
    }
    let proc = staged("/proc");
    fs::create_dir_all(&proc).map_err(at("creating", &proc))?;
    // The PID namespace's own /proc (`--mount-proc` made one fully visible, so
    // the kernel lets a user namespace mount another).
    mount(
        "proc",
        &proc,
        "proc",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )
    .map_err(io::Error::from)
    .map_err(at("mounting proc on", &proc))?;

    verify(plan)
}

/// Bind `path` at the same place in the new root, read-only with every
/// submount, or recreate it as a symlink when the host's is one.
fn bind_read_only(path: &Path) -> Step {
    let target = staged(&path.to_string_lossy());
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        // A runtime path this host does not have (`/etc/pki/tls` on Debian).
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("reading", path)(e)),
    };
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(at("creating", parent))?;
    }
    if meta.file_type().is_symlink() {
        let link = fs::read_link(path).map_err(at("reading the link", path))?;
        return symlink(&link, &target).map_err(at("linking", &target));
    }
    if meta.is_dir() {
        fs::create_dir_all(&target).map_err(at("creating", &target))?;
    } else {
        fs::write(&target, b"").map_err(at("creating", &target))?;
    }
    mount_bind_recursive(path, &target)
        .map_err(io::Error::from)
        .map_err(at("binding", path))?;
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
fn mask(plan: &Plan, path: &Path) -> Step {
    let target = staged(&path.to_string_lossy());
    match fs::symlink_metadata(&target) {
        // Nothing to hide: the path is not inside any bind.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("reading", &target)(e)),
        Ok(meta) if !meta.is_dir() => {
            mount_bind(Path::new(STAGE).join(EMPTY_FILE), &target)
                .map_err(io::Error::from)
                .map_err(at("masking", path))?;
            return remount(
                &target,
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            );
        }
        Ok(_) => {}
    }
    mount(
        "tmpfs",
        &target,
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        plan::MASK_SIZE,
    )
    .map_err(io::Error::from)
    .map_err(at("masking", path))?;
    for back in plan
        .bound_back
        .iter()
        .map(Path::new)
        .filter(|b| b.starts_with(path))
    {
        bind_read_only(back)?;
    }
    // A tmpfs remount (no bind flag) makes the mask's superblock read-only.
    mount_remount(
        &target,
        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
        plan::MASK_SIZE,
    )
    .map_err(io::Error::from)
    .map_err(at("making the mask read-only at", &target))
}

fn bind_device(device: &Path, writable: bool) -> Step {
    let target = staged(&device.to_string_lossy());
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(at("creating", parent))?;
    }
    fs::write(&target, b"").map_err(at("creating", &target))?;
    mount_bind(device, &target)
        .map_err(io::Error::from)
        .map_err(at("binding", device))?;
    let mut flags = MountFlags::NOSUID | MountFlags::NOEXEC;
    if !writable {
        flags |= MountFlags::RDONLY;
    }
    remount(&target, flags)
}

/// Remount one mount as a bind with `wanted`, keeping the flags it has.
fn remount(target: &Path, wanted: MountFlags) -> Step {
    // The last row at a mount point is the topmost mount there.
    let current = mountinfo()?
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
    mount_remount(target, MountFlags::BIND | wanted | locked, c"")
        .map_err(io::Error::from)
        .map_err(at("remounting", target))
}

/// Read every mount in the new root back and refuse on any mismatch: all
/// `nosuid`; all read-only and `nodev` except the home, `/tmp`, `/proc` and
/// the writable devices; nothing outside the plan's paths.
///
/// Only mounts descending from the root tmpfs are checked, by mount id: the
/// host's own `/tmp` and anything mounted under it are covered by the root
/// tmpfs but still listed at the same paths.
fn verify(plan: &Plan) -> Step {
    let root = Path::new(STAGE);
    let rows = mountinfo()?;
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
        .chain(&plan.bound_back)
        .map(|p| staged(p))
        .collect();
    for m in rows.iter().filter(|m| descends_from(&rows, m, root_id)) {
        let fail = |why: &str| Err(format!("verifying {} ({why})", m.point.display()));
        if !m.flags.contains(MountFlags::NOSUID) {
            return fail("not nosuid");
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
    Ok(())
}

/// `pivot_root` into the staged root, leave nothing of the old one, and make
/// the new root itself read-only.
pub(super) fn enter_root() -> Step {
    let old = Path::new(STAGE).join(OLD_ROOT);
    fs::create_dir(&old).map_err(at("creating", &old))?;
    rustix::process::pivot_root(STAGE, &old)
        .map_err(io::Error::from)
        .map_err(at("pivoting into", Path::new(STAGE)))?;
    // At once: a working directory left in the old root survives a lazy unmount.
    rustix::process::chdir("/")
        .map_err(io::Error::from)
        .map_err(at("changing directory to", Path::new("/")))?;
    let old = Path::new("/").join(OLD_ROOT);
    unmount(&old, UnmountFlags::DETACH)
        .map_err(io::Error::from)
        .map_err(at("detaching the old root at", &old))?;
    fs::remove_dir(&old).map_err(at("removing", &old))?;
    mount_remount(
        "/",
        MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
        c"",
    )
    .map_err(io::Error::from)
    .map_err(at("making the new root read-only at", Path::new("/")))
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

fn mountinfo() -> Result<Vec<Mount>, String> {
    let text = fs::read_to_string("/proc/self/mountinfo")
        .map_err(at("reading", Path::new("/proc/self/mountinfo")))?;
    Ok(parse_mountinfo(&text))
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
fn mounts_under(target: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(mountinfo()?
        .into_iter()
        .map(|m| m.point)
        .filter(|p| p.starts_with(target))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_rows_parse_with_escapes_and_locked_flags() {
        let text = "36 35 98:0 / /usr rw,nosuid,nodev,relatime master:1 - ext4 /dev/root rw\n\
                    37 36 0:5 / /tmp/a\\040b ro,noexec shared:2 - tmpfs none rw\n";
        let rows = parse_mountinfo(text);
        assert_eq!(
            rows,
            vec![
                Mount {
                    id: 36,
                    parent: 35,
                    point: PathBuf::from("/usr"),
                    flags: MountFlags::NOSUID | MountFlags::NODEV | MountFlags::RELATIME,
                },
                Mount {
                    id: 37,
                    parent: 36,
                    point: PathBuf::from("/tmp/a b"),
                    flags: MountFlags::RDONLY | MountFlags::NOEXEC,
                },
            ]
        );
    }

    /// The host's own mount at the staging path is not checked; the root
    /// tmpfs stacked on it and that tmpfs's children are.
    #[test]
    fn only_mounts_below_the_root_tmpfs_descend_from_it() {
        let rows = parse_mountinfo(
            "1 1 0:1 / / rw - x x rw\n\
             20 1 0:2 / /tmp rw - tmpfs t rw\n\
             21 20 0:3 / /tmp/.X11-unix rw - tmpfs t rw\n\
             30 20 0:4 / /tmp rw,nosuid,nodev - tmpfs t rw\n\
             31 30 0:5 / /tmp/usr ro,nosuid,nodev - ext4 r rw\n",
        );
        let below: Vec<u64> = rows
            .iter()
            .filter(|m| descends_from(&rows, m, 30))
            .map(|m| m.id)
            .collect();
        assert_eq!(below, vec![30, 31]);
    }

    #[test]
    fn a_backslash_not_followed_by_three_octal_digits_stays() {
        assert_eq!(unescape("a\\9b"), PathBuf::from("a\\9b"));
        assert_eq!(unescape("a\\134b"), PathBuf::from("a\\b"));
    }
}
