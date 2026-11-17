// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The uv fetch with the real uv 0.13.1 against the fake PyPI (its test plan,
//! the real-uv rows). Each row looks for `uvx` on the test's PATH: absent,
//! it skips with a named line; present, it requires uv 0.13.1 and prints a
//! named `ran` line before its first assertion. The enabling PR deletes the
//! skip, so a missing uv then fails the row.

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
    /// Where the recorder logs a spawn with no HOME (the gateway's probe).
    pub(super) host_log: PathBuf,
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
    /// (a premise asserted here), copied pyenv-shaped under `under`.
    pub(super) fn pyenv(under: &str) -> Self {
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
        let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
        let prefix = scratch.path().join(under).join(".pyenv/versions/3.0.0");
        let lib = tree.join("lib").join(format!("lib{version}.so.1.0"));
        Self::build(
            scratch,
            prefix,
            &version,
            &tree.join("bin").join(&version),
            &tree.join("lib").join(&version),
            &[lib],
            Real::Binary,
        )
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
            host_log,
        }
    }

    /// The copied stdlib dir.
    pub(super) fn stdlib(&self) -> PathBuf {
        self.prefix.join("lib").join(&self.version)
    }
}

/// `uvx spec <args(port)>` with the real uv against the fake PyPI on
/// `port`, the fetch's bundle holding the index's CA (`Bundle::Registry`) or
/// an unrelated one; the interpreter is `layout`'s, else the system's.
/// `None` where the host has no sandbox or no uv (the skip line printed);
/// else the start's refusal or the run's stdout, and the index, still
/// serving, with its request log.
async fn real_uvx(
    row: &str,
    layout: Option<&Layout>,
    spec: &str,
    args: impl FnOnce(u16) -> Vec<String>,
    bundle: super::fetch_rows::Bundle,
) -> Option<(Result<String, crate::preview_sandbox::Refusal>, Index)> {
    use super::fetch_rows::{Bundle, GUARD, gateway_bin, preview, sandbox_runs};
    let gateway = gateway_bin()?;
    if !sandbox_runs(&gateway).await {
        return None;
    }
    let uv_dir = real_uv(row)?;
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
    path.push(&uv_dir);
    path.push(":/usr/bin:/bin");
    let target = crate::preview_sandbox::Target {
        program: PathBuf::from("uvx"),
        args: std::iter::once(spec.to_owned())
            .chain(args(index.port))
            .map(OsString::from)
            .collect(),
    };
    let out = preview(&gateway, &target, &ca, index.port, Some(path), GUARD).await;
    Some((out, index))
}

/// Arguments that do not depend on the index's port.
fn fixed(args: &[&str]) -> impl FnOnce(u16) -> Vec<String> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    move |_| args
}

fn lines(out: &str) -> Vec<&str> {
    super::fetch_rows::lines(out)
}

/// The spawn record `phook` printed, between `== spawns` and `== end`.
fn spawns(out: &str) -> Vec<&str> {
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
fn site_off(line: &str) -> bool {
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

/// U-spawn-S (design 3), kills m-no-wrapper and m-unquoted-wrapper: with
/// the recorder as the interpreter's real file, the fetch's one interpreter
/// spawn (uv 0.13.1 makes one: uvprobe2.out) carries -S; the run's own spawn
/// is the only other line; the tool env's python resolves to the recorder.
#[tokio::test]
async fn u_spawn_s_every_fetch_spawn_of_the_interpreter_has_site_off() {
    use super::fetch_rows::Bundle;
    for under in ["plain", "it's"] {
        let layout = Layout::unlinked(under, Real::Recorder);
        let Some((out, _)) = real_uvx(
            "u_spawn_s",
            Some(&layout),
            "probe-hook",
            fixed(&[]),
            Bundle::Registry,
        )
        .await
        else {
            return;
        };
        let out = out.expect("the fetch and the run succeeded");
        let recorder = layout.bin.join(&layout.version);
        assert_eq!(
            lines(&out).first().copied(),
            Some(format!("link {}", recorder.display()).as_str()),
            "{under}: {out}"
        );
        let record = spawns(&out);
        let fetch: Vec<&&str> = record
            .iter()
            .filter(|l| l.starts_with("proxy=set "))
            .collect();
        let run: Vec<&&str> = record
            .iter()
            .filter(|l| l.starts_with("proxy=unset "))
            .collect();
        assert_eq!(
            (fetch.len(), run.len(), record.len()),
            (1, 1, 2),
            "{under}: {out}"
        );
        assert!(
            site_off(fetch[0]),
            "{under}: the fetch spawn lacks -S: {}",
            fetch[0]
        );
        assert!(
            run[0].contains("/preview-home/uv-tools/probe-hook/bin/phook"),
            "{under}: the run's spawn: {}",
            run[0]
        );
    }
}

/// The marker hook planted in a copied stdlib: written at interpreter start
/// when a proxy is set.
const HOOK: &str = "import os\nif os.environ.get('HTTPS_PROXY'):\n    open(os.path.join(os.environ.get('HOME', '/tmp'), 'HOOK_RAN'), 'w').close()\n";

/// U-hostpth (design 3), kills m-no-wrapper end to end: a sitecustomize in
/// the interpreter's own stdlib that would mark a proxied start never runs
/// in the fetch, whose one spawn had the proxy set (armed); the control, the
/// same interpreter and hook without -S and with a dummy proxy, marks.
#[tokio::test]
async fn u_hostpth_a_stdlib_sitecustomize_never_runs_during_the_fetch() {
    use super::fetch_rows::Bundle;
    let layout = Layout::unlinked("plain", Real::Recorder);
    std::fs::write(layout.stdlib().join("sitecustomize.py"), HOOK).expect("hook");
    let Some((out, _)) = real_uvx(
        "u_hostpth",
        Some(&layout),
        "probe-hook",
        fixed(&[]),
        Bundle::Registry,
    )
    .await
    else {
        return;
    };
    let out = out.expect("the fetch and the run succeeded");
    let recorder = layout.bin.join(&layout.version);
    let all = lines(&out);
    assert_eq!(
        all.get(..3),
        Some(
            &[
                format!("link {}", recorder.display()).as_str(),
                "marker HOOK_RAN absent",
                "marker PTH_RAN absent",
            ][..]
        ),
        "{out}"
    );
    assert_eq!(
        spawns(&out)
            .iter()
            .filter(|l| l.starts_with("proxy=set "))
            .count(),
        1,
        "the fetch's armed spawn: {out}"
    );
    assert_eq!(
        all.iter().rev().take(2).rev().copied().collect::<Vec<_>>(),
        ["marker HOOK_RAN present", "marker PTH_RAN absent"],
        "{out}"
    );
}

/// U-run-layout (design 2), kills m-tree-bind, m-no-mask, a missing stdlib
/// or libpython bind and m-unquoted-wrapper: a linked pyenv-shaped Python,
/// under plain, spaced and quoted paths, installs through the wrapper and
/// its console script runs, every canary of the tree denied.
#[tokio::test]
async fn u_run_layout_the_narrow_binds_run_and_hide_the_tree() {
    use super::fetch_rows::Bundle;
    for under in ["plain", "a b", "it's"] {
        let layout = Layout::pyenv(under);
        let reads: Vec<String> = layout
            .canaries
            .iter()
            .map(|c| format!("--read={}", c.display()))
            .collect();
        let args: Vec<&str> = reads.iter().map(String::as_str).collect();
        let Some((out, _)) = real_uvx(
            "u_run_layout",
            Some(&layout),
            "probe-cli",
            fixed(&args),
            Bundle::Registry,
        )
        .await
        else {
            return;
        };
        let out = out.expect("the fetch and the run succeeded");
        let mut want = vec!["cli-ran".to_owned()];
        want.extend(reads.iter().cloned());
        want.push("proxy unset".to_owned());
        want.extend(
            layout
                .canaries
                .iter()
                .map(|c| format!("denied {}", c.display())),
        );
        assert_eq!(lines(&out), want, "{under}: {out}");
    }
}

/// L7b, the uv path end to end: a cold wheel fetch through the proxy; the
/// console script runs offline with its arguments as given: it cannot reach
/// the index the host reaches at the same moment.
#[tokio::test]
async fn l7b_a_cold_wheel_fetch_runs_its_console_script_offline() {
    use super::fetch_rows::Bundle;
    let sentinels = ["alpha", "b c", "--flag=d'e"];
    let args = |port: u16| {
        let mut args: Vec<String> = sentinels.iter().map(|a| (*a).to_owned()).collect();
        args.push(format!("--connect=127.0.0.1:{port}"));
        args
    };
    let Some((out, index)) = real_uvx("l7b", None, "probe-cli", args, Bundle::Registry).await
    else {
        return;
    };
    let out = out.expect("the fetch and the run succeeded");
    // Positive control: the index still answers on the host.
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", index.port)).is_ok(),
        "the host reaches the index"
    );
    assert!(
        index.requests().contains(
            &"files.pythonhosted.org /packages/probe_cli-1.0-py3-none-any.whl".to_owned()
        ),
        "{:?}",
        index.requests()
    );
    let port = index.port;
    assert_eq!(
        lines(&out),
        [
            "cli-ran".to_owned(),
            "alpha".to_owned(),
            "b c".to_owned(),
            "--flag=d'e".to_owned(),
            format!("--connect=127.0.0.1:{port}"),
            "proxy unset".to_owned(),
            format!("connect failed 127.0.0.1:{port}"),
        ],
        "{out}"
    );
}

/// L7c-sdist (design 6), joint red with both no-build mechanisms dropped: a
/// project with only an sdist refuses at the uv install, and its build hook
/// never signalled the index (the signal outlives the destroyed home).
#[tokio::test]
async fn l7c_sdist_an_sdist_only_project_is_never_built() {
    use super::fetch_rows::{Bundle, at_step};
    let Some((out, index)) = real_uvx(
        "l7c_sdist",
        None,
        "probe-sdist",
        fixed(&[]),
        Bundle::Registry,
    )
    .await
    else {
        return;
    };
    let refused = out.expect_err("an sdist-only project refuses");
    assert!(at_step(&refused, "the fetch's uv install"), "{refused:?}");
    let requests = index.requests();
    assert!(
        requests.contains(&"pypi.org /simple/probe-sdist/".to_owned()),
        "{requests:?}"
    );
    assert!(
        !requests.iter().any(|r| r.ends_with("/simple/build-ran/")),
        "the build ran: {requests:?}"
    );
}

/// L7c-url (design 7), kills m-direct-url end to end: uv installs a
/// dependency named by URL from the allowed host, and the direct-URL check
/// refuses the install.
#[tokio::test]
async fn l7c_url_a_dependency_by_url_refuses_at_the_direct_url_check() {
    use super::fetch_rows::{Bundle, at_step};
    let Some((out, index)) =
        real_uvx("l7c_url", None, "probe-url", fixed(&[]), Bundle::Registry).await
    else {
        return;
    };
    let requests = index.requests();
    assert!(
        requests
            .contains(&"files.pythonhosted.org /direct/url_dep-1.0-py3-none-any.whl".to_owned()),
        "uv fetched the URL dependency: {requests:?}"
    );
    let refused = out.expect_err("a URL dependency refuses");
    assert!(
        at_step(&refused, "the fetch's direct-URL check"),
        "{refused:?}"
    );
}

/// L7c-pth (design 3 and 6), joint red with the no-compile switch and
/// variable both dropped: a `.pth` the package installs never runs in the
/// fetch, whose one interpreter spawn had the proxy set (armed); the
/// control, the tool env's python with a dummy proxy, runs it.
#[tokio::test]
async fn l7c_pth_an_installed_pth_never_runs_during_the_fetch() {
    use super::fetch_rows::Bundle;
    let layout = Layout::unlinked("plain", Real::Recorder);
    let Some((out, _)) = real_uvx(
        "l7c_pth",
        Some(&layout),
        "probe-pth",
        fixed(&[]),
        Bundle::Registry,
    )
    .await
    else {
        return;
    };
    let out = out.expect("the fetch and the run succeeded");
    let all = lines(&out);
    assert_eq!(
        all.get(1..3),
        Some(&["marker HOOK_RAN absent", "marker PTH_RAN absent"][..]),
        "{out}"
    );
    assert_eq!(
        spawns(&out)
            .iter()
            .filter(|l| l.starts_with("proxy=set "))
            .count(),
        1,
        "the fetch's armed spawn: {out}"
    );
    assert_eq!(
        all.iter().rev().take(2).rev().copied().collect::<Vec<_>>(),
        ["marker HOOK_RAN absent", "marker PTH_RAN present"],
        "{out}"
    );
}

/// L-name (design 4), kills m-raw-name end to end: `Foo.Bar_Baz` installs
/// into the env named by its PEP 503 name, and its script runs from there.
#[tokio::test]
async fn l_name_a_dotted_mixed_case_name_runs_from_its_normalized_env() {
    use super::fetch_rows::Bundle;
    let Some((out, _)) =
        real_uvx("l_name", None, "Foo.Bar_Baz", fixed(&[]), Bundle::Registry).await
    else {
        return;
    };
    let out = out.expect("the fetch and the run succeeded");
    assert_eq!(
        lines(&out),
        [
            "argv0 /preview-home/uv-tools/foo-bar-baz/bin/fbb",
            "fbb-ran"
        ],
        "{out}"
    );
}

/// U-tls (UV.4): the same index and package twice, the fetch's bundle
/// staged per run; with the index's CA it installs, with an unrelated CA no
/// request completes a handshake and the install refuses.
#[tokio::test]
async fn u_tls_only_the_bundles_ca_is_trusted() {
    use super::fetch_rows::{Bundle, at_step};
    let Some((out, index)) =
        real_uvx("u_tls", None, "probe-cli", fixed(&[]), Bundle::Registry).await
    else {
        return;
    };
    let out = out.expect("the trusted fetch and the run succeeded");
    assert_eq!(lines(&out).first().copied(), Some("cli-ran"), "{out}");
    // uv may ask for one file more than once (range reads): the set counts.
    let mut asked = index.requests();
    asked.sort();
    asked.dedup();
    assert_eq!(
        asked,
        [
            "files.pythonhosted.org /packages/probe_cli-1.0-py3-none-any.whl",
            "pypi.org /simple/probe-cli/",
        ],
        "{out}"
    );
    let Some((out, index)) = real_uvx("u_tls", None, "probe-cli", fixed(&[]), Bundle::Other).await
    else {
        return;
    };
    let refused = out.expect_err("an untrusted index refuses");
    assert!(at_step(&refused, "the fetch's uv install"), "{refused:?}");
    assert_eq!(index.requests(), Vec::<String>::new());
}
