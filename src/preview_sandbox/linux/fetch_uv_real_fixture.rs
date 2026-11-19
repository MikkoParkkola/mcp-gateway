// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The real-uv rows' fixtures: the packages the fake `PyPI` serves, the
//! copied interpreter trees and the spawn recorder, and the runner that
//! finds the real uv (or prints the row's skip line) and previews a target.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::fetch_pypi::{Index, IndexFile, sdist, wheel};

/// `probe-cli`'s `pcli`: `cli-ran`, each argument, whether a proxy is set,
/// then per option the outcome of a read, a connect, or a file's lines.
const PROBE_CLI: &str = r#"import os, socket, sys

def main():
    print("cli-ran")
    for a in sys.argv[1:]:
        print(a)
    print("proxy set" if "HTTPS_PROXY" in os.environ else "proxy unset")
    for a in sys.argv[1:]:
        if a.startswith("--read="):
            p = a[len("--read="):]
            try:
                open(p, "rb").close()
                print("READ " + p)
            except OSError:
                print("denied " + p)
        elif a.startswith("--connect="):
            hp = a[len("--connect="):]
            host, _, port = hp.rpartition(":")
            try:
                socket.create_connection((host, int(port)), timeout=2).close()
                print("connect ok " + hp)
            except OSError:
                print("connect failed " + hp)
        elif a.startswith("--cat="):
            p = a[len("--cat="):]
            try:
                with open(p) as f:
                    text = f.read()
                print("== " + p)
                for line in text.splitlines():
                    print(line)
            except OSError:
                print("== " + p + " missing")
"#;

/// `probe-hook`'s `phook` (and `probe-pth`'s `ppth`): the tool env's python
/// link, both markers, the spawn record, then the control (this interpreter
/// without -S, a dummy proxy set) and both markers again.
const PROBE_HOOK: &str = r#"import os, subprocess, sys

def marks():
    for m in ("HOOK_RAN", "PTH_RAN"):
        there = os.path.exists(os.path.join(os.environ["HOME"], m))
        print("marker %s %s" % (m, "present" if there else "absent"))

def main():
    print("link " + os.path.realpath(os.path.join(sys.prefix, "bin", "python")))
    marks()
    p = os.path.join(os.environ["HOME"], ".spawns")
    try:
        with open(p) as f:
            text = f.read()
    except OSError:
        text = ""
    print("== spawns")
    for line in text.splitlines():
        print(line)
    print("== end")
    env = dict(os.environ, HTTPS_PROXY="http://control")
    subprocess.run([sys.executable, "-c", "pass"], env=env, check=False)
    marks()
"#;

/// `probe_pth.pth`: a marker when a proxy is set at interpreter start.
const PTH: &str = "import os; os.environ.get('HTTPS_PROXY') and open(os.path.join(os.environ['HOME'], 'PTH_RAN'), 'w').close()\n";

/// `probe-sdist`'s in-tree backend: its build signals the index first (the
/// request outlives the home), then writes a marker.
const BACKEND: &str = r#"import os, urllib.request

def _signal():
    try:
        urllib.request.urlopen("https://pypi.org/simple/build-ran/", timeout=5)
    except Exception:
        pass
    open(os.path.join(os.environ.get("HOME", "/tmp"), "BUILD_RAN"), "w").close()

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _signal()
    raise RuntimeError("the row's backend never builds")

def build_sdist(sdist_directory, config_settings=None):
    _signal()
    raise RuntimeError("the row's backend never builds")
"#;

/// The URL `probe-url` names its dependency by.
pub(super) const URL_DEP: &str =
    "https://files.pythonhosted.org/direct/url_dep-1.0-py3-none-any.whl";

/// Every package the real-uv rows fetch, as the index serves them.
fn index_files() -> Vec<IndexFile> {
    let marker = |text: &'static str| -> String { format!("def main():\n    print({text:?})\n") };
    let fbb =
        "import sys\n\ndef main():\n    print('argv0 ' + sys.argv[0])\n    print('fbb-ran')\n";
    vec![
        wheel(
            "probe-cli",
            "probe-cli",
            "probe_cli",
            &[
                ("probe/__init__.py", ""),
                ("probe/cli.py", PROBE_CLI),
                (
                    "probe_cli-1.0.data/scripts/probe-cli",
                    "#!python\nprint('decoy')\n",
                ),
            ],
            &[("pcli", "probe.cli:main")],
            &[],
        ),
        wheel(
            "probe-hook",
            "probe-hook",
            "probe_hook",
            &[("probe_hook.py", PROBE_HOOK)],
            &[("phook", "probe_hook:main")],
            &[],
        ),
        wheel(
            "probe-pth",
            "probe-pth",
            "probe_pth",
            &[("probe_pth_cli.py", PROBE_HOOK), ("probe_pth.pth", PTH)],
            &[("ppth", "probe_pth_cli:main")],
            &[],
        ),
        wheel(
            "url-dep",
            "url-dep",
            "url_dep",
            &[("url_dep.py", "")],
            &[],
            &[],
        )
        .at("/direct/url_dep-1.0-py3-none-any.whl"),
        wheel(
            "probe-url",
            "probe-url",
            "probe_url",
            &[("probe_url.py", &marker("url-ran"))],
            &[("purl", "probe_url:main")],
            &[&format!("url-dep @ {URL_DEP}")],
        ),
        sdist(
            "probe-sdist",
            "probe_sdist",
            &[
                (
                    "pyproject.toml",
                    "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n\n[project]\nname = \"probe-sdist\"\nversion = \"1.0\"\n",
                ),
                ("backend.py", BACKEND),
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: probe-sdist\nVersion: 1.0\n",
                ),
            ],
        ),
        wheel(
            "foo-bar-baz",
            "Foo.Bar_Baz",
            "foo_bar_baz",
            &[("fbb.py", fbb)],
            &[("fbb", "fbb:main")],
            &[],
        ),
    ]
}

/// The real uv's directory, from the `uvx` on the test's PATH; `None` (the
/// skip line printed) where there is none. A uv other than 0.13.1 fails.
fn real_uv(row: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Some(uvx) = std::env::split_paths(&path)
        .map(|dir| dir.join("uvx"))
        .find(|p| p.is_file())
    else {
        println!("real-uv row skipped: {row}: no uvx");
        return None;
    };
    let dir = std::fs::canonicalize(&uvx)
        .expect("uvx's real file")
        .parent()
        .expect("uvx's directory")
        .to_owned();
    let out = std::process::Command::new(dir.join("uv"))
        .arg("--version")
        .output()
        .expect("uv --version runs");
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(
        version.starts_with("uv 0.13.1 "),
        "the real-uv rows need uv 0.13.1, found {version:?}"
    );
    println!("real-uv row ran: {row}");
    Some(dir)
}

/// `cp -a from to`, which must succeed.
fn copy(from: &Path, to: &Path) {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(to)
        .status()
        .expect("cp runs");
    assert!(
        status.success(),
        "cp -a {} {}",
        from.display(),
        to.display()
    );
}

/// A copied interpreter tree in the row's own scratch directory (outside
/// `/tmp`, which the plan refuses to bind a program from).
pub(super) struct Layout {
    _scratch: tempfile::TempDir,
    /// The interpreter's directory: first on the row's PATH.
    pub(super) bin: PathBuf,
    /// The tree's prefix (`bin`, `lib`, `etc` under it).
    pub(super) prefix: PathBuf,
    /// The interpreter's `pythonX.Y`.
    pub(super) version: String,
    /// The canaries the run must not read, each checked readable here first.
    pub(super) canaries: Vec<PathBuf>,
}

/// How the interpreter's real file is made.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Real {
    /// The copied binary itself.
    Binary,
    /// An ELF that logs each spawn (`proxy=set|unset env=<n>`, then argv,
    /// tab-separated) to `$HOME/.spawns`, or the host log without HOME, then
    /// execs the copied binary (kept inside the bound stdlib dir) with its
    /// argv untouched.
    Recorder,
}

/// The recorder's C source for the binary at `real`, logging to `host_log`
/// when HOME is unset.
fn recorder_source(real: &Path, host_log: &Path) -> String {
    use super::elf_fixture::c_str;
    format!(
        r#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {{
    const char *home = getenv("HOME");
    char path[4096];
    if (home) snprintf(path, sizeof path, "%s/.spawns", home);
    else snprintf(path, sizeof path, "%s", {host_log});
    int n = 0;
    for (char **e = environ; *e; e++) n++;
    FILE *f = fopen(path, "a");
    if (f) {{
        fprintf(f, "proxy=%s env=%d", getenv("HTTPS_PROXY") ? "set" : "unset", n);
        for (int i = 0; i < argc; i++) fprintf(f, "\t%s", argv[i]);
        fputc('\n', f);
        fclose(f);
    }}
    execv({real}, argv);
    return 127;
}}
"#,
        host_log = c_str(host_log.to_str().expect("UTF-8")),
        real = c_str(real.to_str().expect("UTF-8")),
    )
}

/// Fresh package directories with a canary each, the tree's own `etc` and
/// `bin` canaries, every one checked readable before the row runs.
fn plant_canaries(prefix: &Path, version: &str) -> Vec<PathBuf> {
    let stdlib = prefix.join("lib").join(version);
    let mut canaries = Vec::new();
    for (dir, pkg) in [
        ("site-packages", "canary-pkg"),
        ("dist-packages", "canary-dp"),
    ] {
        let _ = std::fs::remove_dir_all(stdlib.join(dir));
        std::fs::create_dir_all(stdlib.join(dir).join(pkg)).expect("package dir");
        canaries.push(stdlib.join(dir).join(pkg).join("TOKEN"));
    }
    std::fs::create_dir_all(prefix.join("etc")).expect("etc");
    canaries.push(prefix.join("etc/pip.conf"));
    canaries.push(prefix.join("bin/other-tool"));
    for canary in &canaries {
        std::fs::write(canary, "canary").expect("canary");
        assert!(
            std::fs::read(canary).is_ok(),
            "{} is readable on the host",
            canary.display()
        );
    }
    canaries
}

/// The runner's toolcache Python that links its libpython: its install tree
/// and its `python3.Y` name. Premise asserted: the binary itself names its
/// libpython (a linked build), so a missing libpython bind fails end to end.
fn linked_toolcache() -> (PathBuf, String) {
    let toolcache = Path::new("/opt/hostedtoolcache/Python");
    let mut found = None;
    for entry in std::fs::read_dir(toolcache).expect("the runner's Python toolcache") {
        let tree = entry.expect("entry").path().join("x64");
        let Ok(bins) = std::fs::read_dir(tree.join("bin")) else {
            continue;
        };
        for bin in bins.flatten() {
            let name = bin.file_name().to_string_lossy().into_owned();
            let is_versioned = name
                .strip_prefix("python3.")
                .is_some_and(|y| y.parse::<u32>().is_ok());
            if is_versioned && tree.join("lib").join(format!("lib{name}.so.1.0")).is_file() {
                found = Some((tree.clone(), name));
            }
        }
    }
    let (tree, version) = found.expect("a linked Python in the runner's toolcache");
    let binary = std::fs::read(tree.join("bin").join(&version)).expect("the toolcache binary");
    let soname = format!("lib{version}.so");
    assert!(
        binary.windows(soname.len()).any(|w| w == soname.as_bytes()),
        "the toolcache {version} links {soname}"
    );
    (tree, version)
}

impl Layout {
    /// The host's system interpreter and stdlib, copied under `under` (a
    /// directory name, spaces and quotes allowed): an interpreter that links
    /// no libpython.
    pub(super) fn unlinked(under: &str, real: Real) -> Self {
        let system =
            std::fs::canonicalize("/usr/bin/python3").expect("the host has /usr/bin/python3");
        let version = system
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a file name")
            .to_owned();
        let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
        let prefix = scratch.path().join(under).join("u");
        Self::build(
            scratch,
            prefix,
            &version,
            &system,
            &Path::new("/usr/lib").join(&version),
            &[],
            real,
        )
    }

    /// A Python from the runner's hosted toolcache, linked to its libpython
    /// (a premise asserted here), copied pyenv-shaped under `under`. The
    /// toolcache build finds libpython through a search path fixed to its own
    /// install directory, so the copy is pointed at its new prefix's `lib`
    /// (with patchelf), as a pyenv build is at its own.
    pub(super) fn pyenv(under: &str) -> Self {
        let (tree, version) = linked_toolcache();
        let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
        let prefix = scratch.path().join(under).join(".pyenv/versions/3.0.0");
        let lib = tree.join("lib").join(format!("lib{version}.so.1.0"));
        let layout = Self::build(
            scratch,
            prefix,
            &version,
            &tree.join("bin").join(&version),
            &tree.join("lib").join(&version),
            &[lib],
            Real::Binary,
        );
        let status = std::process::Command::new("patchelf")
            .arg("--set-rpath")
            .arg(layout.prefix.join("lib"))
            .arg(layout.bin.join(&version))
            .status()
            .expect("patchelf runs (the pyenv rows need it on PATH)");
        assert!(
            status.success(),
            "patchelf pointed the copy at its prefix's lib"
        );
        layout
    }

    /// The toolcache's linked Python where it is installed: no copy, no
    /// canaries (the rows never write into a host install). Its libpython
    /// sits in its own prefix's `lib`, which the sandbox shows only through
    /// the interpreter's libpython bind.
    pub(super) fn toolcache_in_place() -> Self {
        let (tree, version) = linked_toolcache();
        Self {
            _scratch: tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch"),
            bin: tree.join("bin"),
            prefix: tree,
            version,
            canaries: Vec::new(),
        }
    }

    fn build(
        scratch: tempfile::TempDir,
        prefix: PathBuf,
        version: &str,
        binary: &Path,
        stdlib: &Path,
        libs: &[PathBuf],
        real: Real,
    ) -> Self {
        let bin = prefix.join("bin");
        let lib = prefix.join("lib");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&lib).expect("lib");
        copy(stdlib, &lib);
        for l in libs {
            copy(l, &lib);
        }
        let host_log = scratch.path().join("host.spawns");
        let file = bin.join(version);
        match real {
            Real::Binary => copy(binary, &file),
            Real::Recorder => {
                let saved = lib.join(version).join(".real-python3");
                copy(binary, &saved);
                let built =
                    super::elf_fixture::cc(&bin, version, &recorder_source(&saved, &host_log), &[]);
                assert_eq!(built, file);
            }
        }
        std::os::unix::fs::symlink(version, bin.join("python3")).expect("python3 link");
        let canaries = plant_canaries(&prefix, version);
        Self {
            _scratch: scratch,
            bin,
            prefix,
            version: version.to_owned(),
            canaries,
        }
    }

    /// The copied stdlib dir.
    pub(super) fn stdlib(&self) -> PathBuf {
        self.prefix.join("lib").join(&self.version)
    }
}

/// What a real-uv row needs before it builds anything: the gateway binary
/// and the real uv's directory.
pub(super) struct Ready {
    gateway: PathBuf,
    uv_dir: PathBuf,
}

impl Ready {
    /// The real uv's directory.
    pub(super) fn uv_dir(&self) -> &Path {
        &self.uv_dir
    }

    /// The same host, with uv and uvx taken from `dir` instead.
    pub(super) fn with_uv_dir(&self, dir: PathBuf) -> Self {
        Self {
            gateway: self.gateway.clone(),
            uv_dir: dir,
        }
    }
}

/// `Some` where this host can run the real-uv rows (a gateway binary, user
/// namespaces, and uv 0.13.1); `None` after the row's skip line otherwise.
/// Every real-uv row calls this before it builds a fixture.
pub(super) async fn ready(row: &str) -> Option<Ready> {
    use super::fetch_rows::{gateway_bin, sandbox_runs};
    let gateway = gateway_bin()?;
    if !sandbox_runs(&gateway).await {
        return None;
    }
    let uv_dir = real_uv(row)?;
    Some(Ready { gateway, uv_dir })
}

/// `uvx spec <args(port)>` with the real uv against the fake `PyPI` on
/// `port`, the fetch's bundle holding the index's CA (`Bundle::Registry`) or
/// an unrelated one; the interpreter is `layout`'s, else the system's. The
/// start's refusal or the run's stdout, and the index, still serving, with
/// its request log.
pub(super) async fn real_uvx(
    ready: &Ready,
    layout: Option<&Layout>,
    spec: &str,
    args: impl FnOnce(u16) -> Vec<String>,
    bundle: super::fetch_rows::Bundle,
) -> (Result<String, crate::preview_sandbox::Refusal>, Index) {
    use super::fetch_rows::{Bundle, GUARD, preview};
    let index = Index::start(index_files(), "fake PyPI CA").await;
    let ca = match bundle {
        Bundle::Registry => index.ca_pem.clone(),
        Bundle::Other => crate::test_fixture_host::test_pki("pypi.org", "unrelated CA")
            .ca
            .pem(),
    };
    let mut path = OsString::new();
    if let Some(layout) = layout {
        path.push(&layout.bin);
        path.push(":");
    }
    path.push(&ready.uv_dir);
    path.push(":/usr/bin:/bin");
    let target = crate::preview_sandbox::Target {
        program: PathBuf::from("uvx"),
        args: std::iter::once(spec.to_owned())
            .chain(args(index.port))
            .map(OsString::from)
            .collect(),
    };
    let out = preview(&ready.gateway, &target, &ca, index.port, Some(path), GUARD).await;
    (out, index)
}

/// Arguments that do not depend on the index's port.
pub(super) fn fixed(args: &[&str]) -> impl FnOnce(u16) -> Vec<String> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    move |_| args
}

pub(super) fn lines(out: &str) -> Vec<&str> {
    super::fetch_rows::lines(out)
}

/// The spawn record `phook` printed, between `== spawns` and `== end`.
pub(super) fn spawns(out: &str) -> Vec<&str> {
    lines(out)
        .into_iter()
        .skip_while(|l| *l != "== spawns")
        .skip(1)
        .take_while(|l| *l != "== end")
        .collect()
}

/// Whether `-S` is among the interpreter options of the tab-separated argv
/// in `line` (after `proxy=... env=...`), before the first `-c`, script path
/// or `--`; a combined short option such as `-SI` counts.
pub(super) fn site_off(line: &str) -> bool {
    for arg in line.split('\t').skip(2) {
        if arg == "-c" || arg == "--" || !arg.starts_with('-') {
            return false;
        }
        if !arg.starts_with("--") && arg[1..].contains('S') {
            return true;
        }
    }
    false
}

/// Put `bytes` at `path` inside a copied tree as a new regular file. The
/// copy may hold a link there into the host (Debian's stdlib links
/// `sitecustomize.py` into `/etc`): the entry is removed first, without
/// following it, and the file is created new, so nothing is ever written
/// through a link. No row writes a host path.
pub(super) fn plant_new(path: &Path, bytes: &[u8]) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("removing the copied {}: {e}", path.display()),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|e| panic!("creating {} new: {e}", path.display()));
    std::io::Write::write_all(&mut file, bytes).expect("the planted bytes");
}

/// Kills "a planted file is written through a copied link": with a link at
/// the path pointing at a decoy outside the copy, planting leaves the decoy
/// byte for byte unchanged and puts a regular file there. Control: a plain
/// create-new open of a path holding a link refuses, so the link is gone
/// before the write, never followed by it. Holds whatever the decoy's owner.
#[cfg(tp4)]
#[test]
fn plant_new_never_writes_through_a_link() {
    let root = tempfile::tempdir().expect("root");
    let decoy = root.path().join("host-etc/sitecustomize.py");
    std::fs::create_dir_all(decoy.parent().expect("dir")).expect("decoy dir");
    std::fs::write(&decoy, "decoy").expect("decoy");
    let copy = root.path().join("copy/lib/python3.13");
    std::fs::create_dir_all(&copy).expect("copy");
    let planted = copy.join("sitecustomize.py");
    std::os::unix::fs::symlink(&decoy, &planted).expect("link");
    let refused = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&planted)
        .map(|_| ());
    assert_eq!(
        refused.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::AlreadyExists),
        "create-new refuses a path holding a link"
    );
    plant_new(&planted, b"hook");
    assert_eq!(std::fs::read(&decoy).expect("decoy"), b"decoy");
    let meta = std::fs::symlink_metadata(&planted).expect("planted");
    assert!(meta.file_type().is_file(), "a regular file, not a link");
    assert_eq!(std::fs::read(&planted).expect("planted"), b"hook");
}
