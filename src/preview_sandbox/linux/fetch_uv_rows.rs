// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The uv fetch step around a uv stand-in (its test plan, U-env, U-run-spawn,
//! U-sweep, U-setup, U-dark): an ELF uv in a lone tools directory records
//! what its install saw under `/preview-home/obs`, lays out the tool env the
//! scenario names, and the console script it leaves prints those records in
//! the run phase, the only way out of the root's tmpfs.

use std::ffi::OsString;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::elf_fixture::sh_elf;
use super::fetch_rows::{GUARD, gateway_bin, lines, preview, sandbox_runs};
use crate::preview_sandbox::{Refusal, Target};

/// What the uv stand-in installs: the dist name, its one console script, and
/// whether a decoy `bin/<dist>` sits beside it.
pub(super) struct Scenario {
    pub(super) dist: &'static str,
    pub(super) script: &'static str,
    pub(super) decoy: bool,
    /// Shell run after the layout, before the stand-in exits 0.
    pub(super) hook: &'static str,
    /// Shell the console script runs after its own lines.
    pub(super) run_tail: &'static str,
    /// The line `uv --version` prints.
    pub(super) version: &'static str,
}

pub(super) const PROBE_CLI: Scenario = Scenario {
    dist: "probe_cli",
    script: "pcli",
    decoy: true,
    hook: "",
    run_tail: "",
    version: "uv 0.13.1 (x86_64-linux-gnu)",
};

/// The console script the stand-in leaves: what the run sees (its `$0`, its
/// PATH as given, its whole environment), every obs record, then `bin-ran`,
/// `argc <n>` and each argument on its own line.
const RUN_BIN: &str = r#"#!/bin/sh
echo "argv0 $0"
echo "PATH=$PATH"
PATH=/usr/bin:/bin
tr '\0' '\n' < /proc/$$/environ | LC_ALL=C sort | sed 's/^/env /'
for f in /preview-home/obs/*; do [ -e "$f" ] && { echo "== ${f##*/}"; cat "$f"; }; done
echo bin-ran
echo "argc $#"
for a in "$@"; do printf '%s\n' "$a"; done
"#;

/// The uv stand-in's script: `--version` answers on the host; `tool install`
/// records its argv and exact environment (numbered per call), lays out the
/// tool env of the package the spec names, then runs the scenario's hook.
fn uv_script(scenario: &Scenario, tools: &Path) -> String {
    let run_bin = format!("{RUN_BIN}{}\n", scenario.run_tail);
    let decoy = if scenario.decoy {
        format!(
            "printf '#!/bin/sh\\necho decoy\\n' > \"$env/bin/{dist}\"; chmod 755 \"$env/bin/{dist}\"\n",
            dist = scenario.dist.replace('_', "-")
        )
    } else {
        String::new()
    };
    format!(
        r#"case "$1" in
--version) : > '{called}'; echo '{version}'; exit 0;;
tool) ;;
*) echo "shim: unexpected $1" >&2; exit 2;;
esac
PATH=/usr/bin:/bin
export PATH
obs=/preview-home/obs
mkdir -p "$obs"
n=1
while [ -e "$obs/uv.$n.argv" ]; do n=$((n+1)); done
printf '%s\n' "$@" > "$obs/uv.$n.argv"
tr '\0' '\n' < /proc/$$/environ | LC_ALL=C sort > "$obs/uv.$n.env"
spec=$(eval "echo \"\${{$#}}\"")
name=$(printf '%s' "${{spec%%==*}}" | tr 'A-Z_.' 'a-z--' | tr -s '-')
env=/preview-home/uv-tools/$name
info=$env/lib/python3.12/site-packages/{dist}-1.0.dist-info
mkdir -p "$info" "$env/bin"
printf 'Metadata-Version: 2.1\nName: {dist}\nVersion: 1.0\n' > "$info/METADATA"
: > "$info/RECORD"
printf '[console_scripts]\n{script} = probe:main\n' > "$info/entry_points.txt"
cat > "$env/bin/{script}" <<'RUNBIN'
{run_bin}RUNBIN
chmod 755 "$env/bin/{script}"
{decoy}{hook}
exit 0
"#,
        dist = scenario.dist,
        script = scenario.script,
        run_bin = run_bin,
        hook = scenario.hook,
        version = scenario.version,
        called = path_of(&tools.join("version-called")),
    )
}

/// A pyenv-shaped Python 3.12 outside `/tmp` (the plan refuses to bind a
/// program there) whose `python3` is an ELF answering the probe with
/// `3.12`, and a lone tools directory holding the uv stand-in and `uvx`.
pub(super) struct UvShim {
    _scratch: tempfile::TempDir,
    /// The interpreter's directory: first on the fetch's and the run's PATH.
    pub(super) python_dir: PathBuf,
    /// uv's directory.
    pub(super) tools: PathBuf,
}

impl UvShim {
    pub(super) fn new(scenario: &Scenario) -> Self {
        let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
        let prefix = scratch.path().join(".pyenv/versions/3.12.1");
        let python_dir = prefix.join("bin");
        std::fs::create_dir_all(&python_dir).expect("bin");
        std::fs::create_dir_all(prefix.join("lib/python3.12")).expect("stdlib");
        sh_elf(&python_dir, "python3.12", "printf '3.12\\n'");
        symlink("python3.12", python_dir.join("python3")).expect("python3 link");
        let tools = scratch.path().join("tools");
        std::fs::create_dir_all(&tools).expect("tools");
        sh_elf(&tools, "uv", &uv_script(scenario, &tools));
        sh_elf(&tools, "uvx", "exit 3");
        Self {
            _scratch: scratch,
            python_dir,
            tools,
        }
    }

    /// The gateway's PATH for the rows: the interpreter, uv, the system.
    pub(super) fn path(&self) -> OsString {
        let mut path = OsString::from(&self.python_dir);
        path.push(":");
        path.push(&self.tools);
        path.push(":/usr/bin:/bin");
        path
    }

    /// `uvx spec args` through the fetch step with the preview's deadline
    /// `limit` away; `None` where the host cannot run the sandbox.
    pub(super) async fn uvx(
        &self,
        spec: &str,
        args: &[&str],
        limit: Duration,
    ) -> Option<Result<String, Refusal>> {
        let gateway = gateway_bin()?;
        if !sandbox_runs(&gateway).await {
            return None;
        }
        let target = Target {
            program: PathBuf::from("uvx"),
            args: std::iter::once(spec)
                .chain(args.iter().copied())
                .map(OsString::from)
                .collect(),
        };
        let ca = crate::test_fixture_host::test_pki("pypi.org", "uv shim CA")
            .ca
            .pem();
        Some(preview(&gateway, &target, &ca, 0, Some(self.path()), limit).await)
    }
}

/// The lines after `== name` up to the next record or `bin-ran`.
fn record<'a>(out: &'a str, name: &str) -> Vec<&'a str> {
    let head = format!("== {name}");
    lines(out)
        .into_iter()
        .skip_while(|l| *l != head)
        .skip(1)
        .take_while(|l| !l.starts_with("== ") && !l.starts_with("bin-ran"))
        .collect()
}

/// The run's own lines after `bin-ran`.
fn after_bin_ran(out: &str) -> Vec<&str> {
    lines(out)
        .into_iter()
        .skip_while(|l| *l != "bin-ran")
        .skip(1)
        .collect()
}

/// The value the run printed for `key` (`argv0 <v>` or `PATH=<v>`).
fn printed<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    lines(out).into_iter().find_map(|l| l.strip_prefix(prefix))
}

fn path_of(p: &Path) -> String {
    p.to_str().expect("UTF-8").to_owned()
}

/// The fetch environment design 6 fixes, for a row whose interpreter lives in
/// `python_dir` and uv in `tools`, with the credential and port the record
/// showed. Written out here, never built by production code.
fn design_6_env(python_dir: &Path, tools: &Path, credential: &str, port: &str) -> Vec<String> {
    let proxy = format!("http://x:{credential}@127.0.0.1:{port}");
    let mut env = vec![
        format!("PATH={}:{}", path_of(python_dir), path_of(tools)),
        "HOME=/preview-home".to_owned(),
        "TMPDIR=/preview-home".to_owned(),
        format!("HTTPS_PROXY={proxy}"),
        format!("HTTP_PROXY={proxy}"),
        "NO_PROXY=".to_owned(),
        "UV_INDEX_URL=https://pypi.org/simple".to_owned(),
        "UV_NO_BUILD=1".to_owned(),
        "UV_NO_CONFIG=1".to_owned(),
        "UV_PYTHON_DOWNLOADS=never".to_owned(),
        "UV_TOOL_DIR=/preview-home/uv-tools".to_owned(),
        "UV_TOOL_BIN_DIR=/preview-home/uv-tools/bin".to_owned(),
        "UV_CACHE_DIR=/preview-home/uv-cache".to_owned(),
        "SSL_CERT_FILE=/etc/mcp-gateway-preview/ca.pem".to_owned(),
        "SSL_CERT_DIR=/etc/mcp-gateway-preview/empty-certs".to_owned(),
    ];
    env.sort();
    env
}

/// The credential and port in the record's `HTTPS_PROXY`.
fn credential_and_port(env: &[&str]) -> (String, String) {
    let proxy = env
        .iter()
        .find_map(|l| l.strip_prefix("HTTPS_PROXY="))
        .expect("the install saw a proxy");
    let (credential, port) = proxy
        .strip_prefix("http://x:")
        .and_then(|rest| rest.split_once("@127.0.0.1:"))
        .expect("the proxy URL's form");
    (credential.to_owned(), port.to_owned())
}

/// U-env (design 6), kills m-native-tls, m-no-build-flag, m-uv-no-build,
/// m-no-config, m-cert-dir, m-compile-bytecode, m-python-flag, m-extra-var
/// and m-name-for-spec: uv runs once, with exactly design 6's argv and
/// environment, the validated spec (its pin kept) last; the env takes the
/// spec's PEP 503 name.
#[cfg(tp4)]
#[tokio::test]
async fn u_env_the_install_sees_exactly_the_fetch_argv_and_environment() {
    for (spec, name) in [("probe-cli", "probe-cli"), ("Probe_Cli==1.0", "probe-cli")] {
        let shim = UvShim::new(&PROBE_CLI);
        let Some(ran) = shim.uvx(spec, &[], GUARD).await else {
            return;
        };
        let out = ran.expect("the fetch and the run succeeded");
        assert_eq!(
            record(&out, "uv.1.argv"),
            [
                "tool",
                "install",
                "--native-tls",
                "--no-build",
                "--no-compile-bytecode",
                "--python",
                "/preview-home/.preview-python",
                spec,
            ],
            "{spec}: {out}"
        );
        assert!(!out.contains("== uv.2.argv"), "{spec}: uv ran twice: {out}");
        let seen = record(&out, "uv.1.env");
        let (credential, port) = credential_and_port(&seen);
        let python_dir = std::fs::canonicalize(&shim.python_dir).expect("python dir");
        let tools = std::fs::canonicalize(&shim.tools).expect("tools");
        assert_eq!(
            seen,
            design_6_env(&python_dir, &tools, &credential, &port),
            "{spec}: {out}"
        );
        assert_eq!(
            printed(&out, "argv0 "),
            Some(format!("/preview-home/uv-tools/{name}/bin/pcli").as_str()),
            "{spec}: {out}"
        );
    }
}

/// U-run-spawn (design 9), kills m-bin-name, a dropped, split or merged
/// argument, a swapped PATH and a proxy leaked into the run: the run execs
/// the console script the package's metadata names (a decoy named after the
/// package sits beside it) with the arguments as given, PATH is the
/// interpreter's directory then the env's `bin`, and no proxy or credential
/// reaches it.
#[cfg(tp4)]
#[tokio::test]
async fn u_run_spawn_the_console_script_runs_with_its_arguments_offline() {
    let shim = UvShim::new(&PROBE_CLI);
    let Some(ran) = shim
        .uvx("probe-cli", &["alpha", "b c", "--flag=d'e"], GUARD)
        .await
    else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(
        printed(&out, "argv0 "),
        Some("/preview-home/uv-tools/probe-cli/bin/pcli"),
        "{out}"
    );
    let python_dir = std::fs::canonicalize(&shim.python_dir).expect("python dir");
    assert_eq!(
        printed(&out, "PATH="),
        Some(
            format!(
                "{}:/preview-home/uv-tools/probe-cli/bin",
                path_of(&python_dir)
            )
            .as_str()
        ),
        "{out}"
    );
    assert_eq!(
        after_bin_ran(&out),
        ["argc 3", "alpha", "b c", "--flag=d'e"],
        "{out}"
    );
    let (credential, _) = credential_and_port(&record(&out, "uv.1.env"));
    let run_env: Vec<&str> = lines(&out)
        .into_iter()
        .filter_map(|l| l.strip_prefix("env "))
        .collect();
    assert!(
        !run_env.is_empty(),
        "the run printed its environment: {out}"
    );
    for line in &run_env {
        assert!(
            !line.starts_with("HTTPS_PROXY=")
                && !line.starts_with("HTTP_PROXY=")
                && !line.contains(&credential),
            "the run saw {line}: {out}"
        );
    }
}

const ESCAPEE: Scenario = Scenario {
    dist: "probe_cli",
    script: "pcli",
    decoy: false,
    hook: "setsid sh -c 'echo $$ > /preview-home/obs/escapee.pid; exec sleep 600' &\nsleep 1",
    run_tail: "pid=$(cat /preview-home/obs/escapee.pid)\n\
               test -d /proc/$pid && echo escapee-alive || echo escapee-gone\n\
               for d in /proc/[0-9]*; do p=${d#/proc/}; [ \"$p\" = \"$$\" ] || echo \"other $p\"; done",
    version: "uv 0.13.1 (x86_64-linux-gnu)",
};

/// U-sweep (design 5, as 2b-2's L5), kills m-sweep-skipped for uv: a
/// descendant uv leaves behind, holding both output pipes, is killed before
/// the run, the fetch still ends, and the run sees no process but PID 1 and
/// itself.
#[cfg(tp4)]
#[tokio::test]
async fn u_sweep_an_escapee_of_the_uv_install_is_swept() {
    let shim = UvShim::new(&ESCAPEE);
    let Some(ran) = shim.uvx("probe-cli", &[], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    let tail = after_bin_ran(&out);
    assert_eq!(
        tail.get(..2),
        Some(&["argc 0", "escapee-gone"][..]),
        "{out}"
    );
    assert!(tail[2..].iter().all(|l| *l == "other 1"), "{out}");
}

const OLD_UV: Scenario = Scenario {
    dist: "probe_cli",
    script: "pcli",
    decoy: false,
    hook: "",
    run_tail: "",
    version: "uv 0.13.0 (x86_64-linux-gnu)",
};

/// U-setup (design 8), kills m-late-setup for placement: a refusal found by
/// the launcher's probe is the start's own, returned before the helper
/// starts, its full text exactly the probe's (a refusal from inside the
/// fetch would read as a failed step instead). Needs no sandbox.
#[cfg(tp4)]
#[tokio::test]
async fn u_setup_a_probe_refusal_is_the_starts_own() {
    // The refusal comes before the helper is started, so no gateway binary
    // is needed: a late refusal would launch /bin/false and fail the row.
    let gateway = PathBuf::from("/bin/false");
    let shim = UvShim::new(&OLD_UV);
    let target = Target {
        program: PathBuf::from("uvx"),
        args: vec![OsString::from("probe-cli")],
    };
    let ca = crate::test_fixture_host::test_pki("pypi.org", "uv shim CA")
        .ca
        .pem();
    let refused = preview(&gateway, &target, &ca, 0, Some(shim.path()), GUARD).await;
    assert_eq!(
        refused,
        Err(Refusal::Step("uv 0.13.0 is older than 0.13.1".into()))
    );
}

/// U-dark (design 10): the production entry refuses a uv target before any
/// probe runs (the stand-in's version call would answer it); the rows reach
/// the staged code below that entry only.
#[cfg(tp4)]
#[tokio::test]
async fn u_dark_the_production_entry_refuses_uv() {
    // Refused at the entry, before any helper: no gateway binary needed.
    let gateway = PathBuf::from("/bin/false");
    let shim = UvShim::new(&PROBE_CLI);
    let marker = shim.tools.join("version-called");
    let target = Target {
        program: shim.tools.join("uvx"),
        args: vec![OsString::from("probe-cli")],
    };
    let refused = super::start_fetching(
        &gateway,
        &target,
        &[],
        tokio::time::Instant::now() + GUARD,
        None,
        None,
    )
    .await
    .map(|_| ());
    assert_eq!(
        refused,
        Err(Refusal::Command(
            "uvx previews are not enabled in this build".into()
        ))
    );
    assert!(!marker.exists(), "a probe ran before the refusal");
    // Positive control: the stand-in's version call does leave the marker.
    let status = std::process::Command::new(shim.tools.join("uv"))
        .arg("--version")
        .status()
        .expect("the stand-in runs");
    assert!(status.success() && marker.exists(), "the marker works");
}
