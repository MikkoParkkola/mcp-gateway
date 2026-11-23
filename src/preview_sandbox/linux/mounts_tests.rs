// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the private root: mountinfo parsing, verify and the preview
//! config's direct checks.

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

fn fetch_plan(fetch: bool) -> Plan {
    Plan {
        host: plan::HostNamespaces {
            user: 1,
            mnt: 1,
            pid: 1,
            net: 1,
            ipc: 1,
            uts: 1,
        },
        read_only: Vec::new(),
        masked: Vec::new(),
        hidden: Vec::new(),
        bound_back: Vec::new(),
        limits: plan::limits(1),
        env: Vec::new(),
        program: "/bin/true".into(),
        target: vec!["true".into()],
        control: "/run/x/control.sock".into(),
        fetch: fetch.then(|| plan::FetchPaths {
            ca: "/run/x/ca.pem".into(),
            npm: None,
            uv: None,
        }),
        #[cfg(debug_assertions)]
        fault: None,
    }
}

fn row(id: u64, parent: u64, point: PathBuf, read_only: bool) -> Mount {
    let mut flags = MountFlags::NOSUID | MountFlags::NODEV;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    Mount {
        id,
        parent,
        point,
        flags,
    }
}

/// The staged root, the preview config tmpfs and its `ca.pem` bind, each
/// read-only as given.
fn rows(config: Option<bool>, ca: Option<bool>, nested: bool) -> Vec<Mount> {
    let config_dir = staged(PREVIEW_CONFIG);
    let mut rows = vec![row(10, 1, PathBuf::from(STAGE), false)];
    if let Some(read_only) = config {
        rows.push(row(11, 10, config_dir.clone(), read_only));
    }
    if let Some(read_only) = ca {
        rows.push(row(12, 11, config_dir.join("ca.pem"), read_only));
    }
    if nested {
        rows.push(row(13, 11, config_dir.join("empty-certs"), true));
    }
    rows
}

/// The preview config as `preview_config` leaves it, under `root/cfg`,
/// with `root/outside` (an empty file) and `root/outside-dir` (an empty
/// directory) for symlinks to point at; returns `ca.pem`'s identity.
fn config_dir(root: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let dir = root.join("cfg");
    fs::create_dir_all(dir.join("empty-certs")).expect("empty-certs");
    fs::write(dir.join("ca.pem"), b"pem").expect("ca.pem");
    fs::write(dir.join("empty-user.npmrc"), b"").expect("empty-user.npmrc");
    fs::write(dir.join("empty-global.npmrc"), b"").expect("empty-global.npmrc");
    fs::write(root.join("outside"), b"").expect("outside");
    fs::create_dir(root.join("outside-dir")).expect("outside-dir");
    let meta = fs::metadata(dir.join("ca.pem")).expect("ca.pem metadata");
    (meta.dev(), meta.ino())
}

/// Replaces `cfg/name` with a symlink to `target`.
fn relink(root: &Path, name: &str, target: &Path) {
    let path = root.join("cfg").join(name);
    if path.is_dir() {
        fs::remove_dir(&path).expect("remove dir");
    } else {
        fs::remove_file(&path).expect("remove file");
    }
    symlink(target, &path).expect("symlink");
}

/// Kills each dropped or weakened direct check: the layout `preview_config`
/// makes passes; an extra entry, a non-empty `empty-certs` or
/// `empty-user.npmrc`, a FIFO `empty-global.npmrc`, a symlink in place of an
/// entry, and a `ca.pem` with another inode each refuse.
#[test]
fn the_preview_config_check_refuses_every_deviation() {
    type Spoil = fn(&Path);
    let cases: [(&str, Spoil); 8] = [
        ("as made", |_| {}),
        ("extra entry", |r| {
            fs::write(r.join("cfg/extra"), b"").expect("extra");
        }),
        ("certs not empty", |r| {
            fs::write(r.join("cfg/empty-certs/x.pem"), b"").expect("x.pem");
        }),
        ("certs a symlink", |r| {
            relink(r, "empty-certs", &r.join("outside-dir"));
        }),
        ("npmrc not empty", |r| {
            fs::write(r.join("cfg/empty-user.npmrc"), b"registry=x").expect("npmrc");
        }),
        ("npmrc a fifo", |r| {
            let path = r.join("cfg/empty-global.npmrc");
            fs::remove_file(&path).expect("remove npmrc");
            let (fifo, mode) = (rustix::fs::FileType::Fifo, rustix::fs::Mode::RUSR);
            rustix::fs::mknodat(rustix::fs::CWD, path.as_path(), fifo, mode, 0).expect("fifo");
        }),
        ("npmrc a symlink", |r| {
            relink(r, "empty-user.npmrc", &r.join("outside"));
        }),
        ("ca another inode", |r| {
            // Made before the old one goes, so its inode cannot be reused.
            fs::write(r.join("cfg/ca.new"), b"pem").expect("new ca.pem");
            fs::rename(r.join("cfg/ca.new"), r.join("cfg/ca.pem")).expect("replace");
        }),
    ];
    for (name, spoil) in cases {
        let root = tempfile::tempdir().expect("root");
        let identity = config_dir(root.path());
        spoil(root.path());
        let checked = check_config_dir(&root.path().join("cfg"), identity);
        assert_eq!(checked.is_ok(), name == "as made", "{name}: {checked:?}");
    }
    // The symlink to the snapshot itself, so following it would match.
    let root = tempfile::tempdir().expect("root");
    let identity = config_dir(root.path());
    fs::rename(root.path().join("cfg/ca.pem"), root.path().join("snapshot")).expect("move");
    symlink(root.path().join("snapshot"), root.path().join("cfg/ca.pem")).expect("symlink");
    let checked = check_config_dir(&root.path().join("cfg"), identity);
    assert!(
        checked.is_err(),
        "ca.pem a symlink to the snapshot: {checked:?}"
    );
}

/// 2b-1, kills "verify accepts a missing, extra or writable preview
/// mount" and "a fetch mount passes with no fetch planned".
#[test]
fn verify_requires_exactly_the_read_only_preview_config() {
    let fetch = fetch_plan(true);
    assert!(verify_rows(&fetch, &rows(Some(true), Some(true), false)).is_ok());
    assert!(
        verify_rows(&fetch, &rows(None, None, false)).is_err(),
        "tmpfs missing"
    );
    assert!(
        verify_rows(&fetch, &rows(Some(true), None, false)).is_err(),
        "ca.pem missing"
    );
    assert!(
        verify_rows(&fetch, &rows(Some(true), Some(true), true)).is_err(),
        "nested"
    );
    assert!(
        verify_rows(&fetch, &rows(Some(true), Some(false), false)).is_err(),
        "ca writable"
    );
    assert!(
        verify_rows(&fetch, &rows(Some(false), Some(true), false)).is_err(),
        "tmpfs writable"
    );
    let no_fetch = fetch_plan(false);
    assert!(verify_rows(&no_fetch, &rows(None, None, false)).is_ok());
    assert!(
        verify_rows(&no_fetch, &rows(Some(true), Some(true), false)).is_err(),
        "no fetch planned"
    );
}

/// Kills "verify skips the proxy socket": with an npm fetch planned, the
/// proxy socket's bind must be there, read-only and nodev; with none
/// planned, a proxy socket mount refuses.
#[test]
fn verify_requires_the_read_only_proxy_socket_only_with_an_npm_fetch() {
    let mut npm = fetch_plan(true);
    if let Some(fetch) = npm.fetch.as_mut() {
        fetch.npm = Some(plan::NpmFetch {
            spec: "mcp-fake".into(),
            run_args: Vec::new(),
            npm: "/opt/npm/bin/npm-cli.js".into(),
            node_dir: "/opt/node/bin".into(),
            ip: "/usr/sbin/ip".into(),
            proxy: "/run/x/proxy.sock".into(),
        });
    }
    let proxy = |read_only: bool, nodev: bool| {
        let mut mount = row(14, 10, staged(PROXY_SOCKET), read_only);
        if !nodev {
            mount.flags.remove(MountFlags::NODEV);
        }
        mount
    };
    let with = |extra: Option<Mount>| {
        let mut all = rows(Some(true), Some(true), false);
        all.extend(extra);
        all
    };
    assert!(verify_rows(&npm, &with(Some(proxy(true, true)))).is_ok());
    assert!(
        verify_rows(&npm, &with(None)).is_err(),
        "proxy socket missing"
    );
    assert!(
        verify_rows(&npm, &with(Some(proxy(false, true)))).is_err(),
        "writable"
    );
    assert!(
        verify_rows(&npm, &with(Some(proxy(true, false)))).is_err(),
        "not nodev"
    );
    let no_npm = fetch_plan(true);
    // Base rows pass without npm, so the refusal below is the proxy mount's.
    assert!(verify_rows(&no_npm, &with(None)).is_ok());
    assert!(
        verify_rows(&no_npm, &with(Some(proxy(true, true)))).is_err(),
        "no npm fetch planned"
    );
}
