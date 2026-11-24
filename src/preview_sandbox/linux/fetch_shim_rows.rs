// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fetch step around a fake npm (L-env, L5, L-deadline2): a shell shim
//! in an NVM-shaped tree records what each npm step saw under
//! `/preview-home/obs` (`$SHIM_HOME/obs` outside the sandbox), and the bin
//! its `ci` step installs prints those records in the run phase, the only
//! way out of the root's tmpfs.

use std::ffi::OsString;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::fetch_rows::{GUARD, at_step, gateway_bin, lines, preview, sandbox_runs};
use crate::preview_sandbox::{Refusal, Target};

/// The lock the shim's first step writes: one registry tarball.
const LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"mcp-shim":"1.0.0"}},"node_modules/mcp-shim":{"version":"1.0.0","resolved":"https://registry.npmjs.org/mcp-shim/-/mcp-shim-1.0.0.tgz"}}}"#;

/// The installed bin: every record the npm steps left, then its arguments.
/// The run's PATH holds only node's and the install's bin directories, so it
/// names the system tools' directories itself.
const RUN_BIN: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
for f in install.argv install.env ci.argv ci.env report; do
  o="${SHIM_HOME:-/preview-home}/obs/$f"
  if [ -e "$o" ]; then echo "== $f"; cat "$o"; fi
done
echo "bin-ran $*"
"#;

/// npm as a shell script: `--version` answers on the host; `install` and
/// `ci` record their argv and exact environment, write `lock` or the bin,
/// then run `hook` with `$step` set. The fetch's PATH holds only node's and
/// npm's directories, so the shim names the system tools' directories after
/// reading its own environment (`/proc/$$/environ` keeps the exec'd one).
fn npm_shim(tree: &Path, lock: &str, hook: &str) -> String {
    let run_bin = run_bin_in(tree);
    format!(
        r#"#!/bin/sh
case "$1" in
--version) echo 10.2.0; exit 0;;
install|ci) step=$1;;
*) echo "shim: unexpected $1" >&2; exit 2;;
esac
PATH=/usr/bin:/bin
export PATH
home=${{SHIM_HOME:-/preview-home}}
obs=$home/obs
pkg=$home/pkg
mkdir -p "$obs"
printf '%s\n' "$@" > "$obs/$step.argv"
tr '\0' '\n' < /proc/$$/environ | LC_ALL=C sort > "$obs/$step.env"
if [ "$step" = install ]; then
  printf '%s' '{lock}' > "$pkg/package-lock.json"
else
  # As npm ci lays it out: the package with its manifest naming its bin, and
  # the .bin link; the run's entry point is read from the manifest.
  mkdir -p "$pkg/node_modules/mcp-shim" "$pkg/node_modules/.bin"
  printf '%s' '{{"name":"mcp-shim","version":"1.0.0","bin":{{"mcp-shim":"cli.sh"}}}}' \
    > "$pkg/node_modules/mcp-shim/package.json"
  cp "{run_bin}" "$pkg/node_modules/mcp-shim/cli.sh"
  chmod 755 "$pkg/node_modules/mcp-shim/cli.sh"
  ln -sf ../mcp-shim/cli.sh "$pkg/node_modules/.bin/mcp-shim"
fi
{hook}
exit 0
"#,
        run_bin = run_bin.display()
    )
}

/// Where the run bin lives: inside npm's package, the one directory of the
/// tree besides node's file that the root shows.
fn run_bin_in(tree: &Path) -> PathBuf {
    tree.join("lib/node_modules/npm/run-bin.sh")
}

fn script(path: &Path, body: &str) {
    crate::test_stub::write_executable(path, body);
}

/// A fake node install outside `/tmp` (the plan refuses to bind a program
/// there), shaped like an NVM version: the root shows its node file and
/// npm's package, nothing else of the tree.
struct Shim {
    _scratch: tempfile::TempDir,
    bin: PathBuf,
}

impl Shim {
    fn new(hook: &str) -> Self {
        Self::with_lock(LOCK, hook)
    }

    /// The shim, its first step writing `lock` (no single quote in it).
    fn with_lock(lock: &str, hook: &str) -> Self {
        let scratch = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("scratch");
        let tree = scratch.path().join(".nvm/versions/node/v20.0.0");
        let bin = tree.join("bin");
        let npm_pkg = tree.join("lib/node_modules/npm/bin");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(&npm_pkg).expect("npm package");
        script(&run_bin_in(&tree), RUN_BIN);
        script(&npm_pkg.join("npm-cli.js"), &npm_shim(&tree, lock, hook));
        script(&npm_pkg.join("npx-cli.js"), "#!/bin/sh\nexit 3\n");
        script(&bin.join("node"), "#!/bin/sh\nexit 3\n");
        symlink(npm_pkg.join("npm-cli.js"), bin.join("npm")).expect("npm link");
        symlink(npm_pkg.join("npx-cli.js"), bin.join("npx")).expect("npx link");
        Self {
            _scratch: scratch,
            bin,
        }
    }

    /// `npx mcp-shim args` with the shim's `bin` first on PATH and the
    /// preview's deadline `limit` away; `None` where the host cannot run it.
    async fn npx(&self, args: &[&str], limit: Duration) -> Option<Result<String, Refusal>> {
        self.npx_dialing(args, limit, 0).await
    }

    /// As [`Self::npx`], the proxy's dialer sending registry tunnels to
    /// `port` on the host's loopback.
    async fn npx_dialing(
        &self,
        args: &[&str],
        limit: Duration,
        port: u16,
    ) -> Option<Result<String, Refusal>> {
        let gateway = gateway_bin()?;
        if !sandbox_runs(&gateway).await {
            return None;
        }
        let target = Target {
            program: PathBuf::from("npx"),
            args: std::iter::once("mcp-shim")
                .chain(args.iter().copied())
                .map(OsString::from)
                .collect(),
        };
        let mut path = OsString::from(&self.bin);
        path.push(":/usr/bin:/bin");
        let ca = crate::test_fixture_host::test_pki("registry.npmjs.org", "shim CA")
            .ca
            .pem();
        Some(preview(&gateway, &target, &ca, port, Some(path), limit).await)
    }
}

/// The lines after `== name` up to the next record.
fn record<'a>(out: &'a str, name: &str) -> Vec<&'a str> {
    let head = format!("== {name}");
    lines(out)
        .into_iter()
        .skip_while(|l| *l != head)
        .skip(1)
        .take_while(|l| !l.starts_with("== ") && !l.starts_with("bin-ran"))
        .collect()
}

/// L-env, kills m-env-extra (the spawn keeps the host environment): each npm
/// step runs with exactly the fetch environment, every key and value, for
/// the proxy's credential and port it was given, and the step's own argv.
#[cfg(tp4)]
#[tokio::test]
async fn l_env_each_npm_step_sees_exactly_the_fetch_environment() {
    let shim = Shim::new("");
    let Some(ran) = shim.npx(&[], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    let prefix = super::plan::HOME.to_owned() + "/pkg";
    let install = [
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--prefix",
        prefix.as_str(),
        "mcp-shim",
    ];
    assert_eq!(record(&out, "install.argv"), install, "{out}");
    assert_eq!(
        record(&out, "ci.argv"),
        ["ci", "--ignore-scripts", "--prefix", prefix.as_str()],
        "{out}"
    );
    for step in ["install.env", "ci.env"] {
        let mut seen: Vec<(String, String)> = record(&out, step)
            .iter()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        seen.sort();
        let proxy = seen
            .iter()
            .find(|(k, _)| k == "npm_config_https_proxy")
            .map(|(_, v)| v.as_str())
            .expect("the step saw a proxy");
        let (credential, port) = proxy
            .strip_prefix("http://x:")
            .and_then(|rest| rest.split_once("@127.0.0.1:"))
            .expect("the proxy URL's form");
        // node's directory, then the directory npm's resolved CLI is in.
        let tree = shim.bin.parent().expect("tree");
        let path = format!(
            "{}:{}",
            shim.bin.display(),
            tree.join("lib/node_modules/npm/bin").display()
        );
        let mut want = super::fetch_step::npm_env(credential, port.parse().expect("port"), &path);
        want.sort();
        assert_eq!(seen, want, "{step}: {out}");
    }
}

/// L5, kills q9 (the sweep skipped): a descendant the first npm step leaves
/// behind, holding both output pipes, is killed before the run, the fetch
/// still ends, and the run phase sees no process but PID 1 and itself.
#[cfg(tp4)]
#[tokio::test]
async fn l5_an_escapee_holding_the_pipes_is_swept() {
    let hook = r#"if [ "$step" = install ]; then
  setsid sh -c 'echo $$ > /preview-home/obs/escapee.pid; exec sleep 600' &
  sleep 1
fi"#;
    let shim = Shim::new(hook);
    std::fs::write(
        run_bin_in(shim.bin.parent().expect("tree")),
        format!(
            "{RUN_BIN}pid=$(cat /preview-home/obs/escapee.pid)\ntest -d /proc/$pid && echo escapee-alive || echo escapee-gone\nfor d in /proc/[0-9]*; do p=${{d#/proc/}}; [ \"$p\" = \"$$\" ] || echo \"other $p\"; done\n"
        ),
    )
    .expect("run bin");
    let Some(ran) = shim.npx(&[], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    let tail: Vec<_> = lines(&out)
        .into_iter()
        .skip_while(|l| !l.starts_with("bin-ran"))
        .collect();
    // PID 1 may be hidden from the run; nothing else may be there.
    assert_eq!(
        tail.get(..2),
        Some(&["bin-ran", "escapee-gone"][..]),
        "{out}"
    );
    assert!(tail[2..].iter().all(|l| *l == "other 1"), "{out}");
}

/// L-deadline2: both npm steps take just under the preview's deadline, so
/// together they pass it; the preview refuses instead of running.
///
/// What the caller can see: the gateway's deadline ends the session at the
/// preview's deadline whatever the helper does, and after the credential the
/// helper's own words never reach the caller, so this row cannot tell the
/// helper's one shared deadline from a deadline per step. That sharing is
/// structural (`install` passes one `deadline` to both npm steps); this row
/// pins that a fetch running past the preview's deadline never runs.
#[cfg(tp4)]
#[tokio::test]
async fn l_deadline2_a_fetch_past_the_preview_deadline_never_runs() {
    // Each step takes most of the deadline, leaving room for a slow sandbox
    // start before fetch_start: two steps pass one deadline, but each fits
    // inside a deadline of its own.
    let limit = Duration::from_secs(30);
    let shim = Shim::new("sleep 18");
    let Some(ran) = shim.npx(&[], limit).await else {
        return;
    };
    let refusal = ran.expect_err("a fetch past the preview's deadline ran");
    // The gateway's own deadline ends the session first: its wait for
    // fetch_done times out at the deadline, either way a refusal.
    let text = refusal.to_string();
    assert!(
        text.contains("deadline") || text.contains("never came"),
        "{text}"
    );
}

/// The shim itself, outside the sandbox (runs where user namespaces are
/// refused): its lock passes the fetch's lock check, and its `ci` step
/// leaves a bin that prints the step records, so a failing L row above
/// points at the sandbox, not at the shim.
#[cfg(tp4)]
#[test]
fn the_shim_writes_a_checked_lock_and_a_bin_that_prints_its_records() {
    let shim = Shim::new("echo hook-ran > \"$obs/report\"");
    let home = tempfile::tempdir().expect("home");
    std::fs::create_dir_all(home.path().join("pkg")).expect("pkg");
    for args in [&["install", "--package-lock-only"][..], &["ci"]] {
        let status = std::process::Command::new(shim.bin.join("npm"))
            .args(args)
            .env("SHIM_HOME", home.path())
            .status()
            .expect("shim");
        assert!(status.success(), "{args:?}");
    }
    let lock = std::fs::read(home.path().join("pkg/package-lock.json")).expect("lock");
    let lock = serde_json::from_slice(&lock).expect("the lock is JSON");
    crate::preview_sandbox::install::check_lock(&lock).expect("the shim's lock passes the check");
    let out = std::process::Command::new(home.path().join("pkg/node_modules/.bin/mcp-shim"))
        .arg("--flag")
        .env("SHIM_HOME", home.path())
        .output()
        .expect("bin");
    let out = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(record(&out, "ci.argv"), ["ci"], "{out}");
    assert_eq!(record(&out, "report"), ["hook-ran"], "{out}");
    let env = record(&out, "install.env");
    assert!(env.iter().any(|l| l.starts_with("SHIM_HOME=")), "{out}");
    assert_eq!(lines(&out).last(), Some(&"bin-ran --flag"), "{out}");
}

/// L4b, kills q18 (the lock check skipped): a lock whose dependency resolves
/// to git refuses the fetch between the two npm steps, so `npm ci` never
/// installs it and the run never starts.
#[cfg(tp4)]
#[tokio::test]
async fn l4b_a_lock_entry_off_the_registry_refuses_before_npm_ci() {
    let lock = r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"mcp-shim":"1.0.0"}},"node_modules/mcp-shim":{"version":"1.0.0","resolved":"git+ssh://git@example.invalid/x.git#0123abcd"}}}"#;
    let Some(ran) = Shim::with_lock(lock, "").npx(&[], GUARD).await else {
        return;
    };
    let refusal = ran.expect_err("a git-resolved lock entry was installed");
    // Only the step crosses the control socket; the reason is check_lock's
    // own pure rows.
    assert!(at_step(&refusal, "the fetch's lock check"), "{refusal:?}");
}

/// L4b, kills q24 (the lock's edge check skipped): a dependency with no entry
/// in the lock, which could hide a pruned git edge, refuses the fetch.
#[cfg(tp4)]
#[tokio::test]
async fn l4b_a_dependency_missing_from_the_lock_refuses() {
    let lock = r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"mcp-shim":"1.0.0"}},"node_modules/mcp-shim":{"version":"1.0.0","resolved":"https://registry.npmjs.org/mcp-shim/-/mcp-shim-1.0.0.tgz","dependencies":{"hidden":"^1.0.0"}}}}"#;
    let Some(ran) = Shim::with_lock(lock, "").npx(&[], GUARD).await else {
        return;
    };
    let refusal = ran.expect_err("a lock missing an entry was installed");
    assert!(at_step(&refusal, "the fetch's lock check"), "{refusal:?}");
}

/// Connect probes in `bash` (`/dev/tcp`), bounded, each printing
/// `<label>-open` or `<label>-refused`.
const PROBE: &str = r#"probe() { if timeout 10 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then echo "$3-open"; else echo "$3-refused"; fi; }
"#;

/// L6 and L1, kill q12 (the relay left open after the fetch) and a run phase
/// with a route out: the relay port the fetch reached (positive control)
/// refuses in the run, and the run reaches neither a host listener on
/// loopback nor an outside address.
#[cfg(tp4)]
#[tokio::test]
async fn l6_l1_after_the_fetch_the_run_connects_nowhere() {
    let hook = format!(
        r#"{PROBE}if [ "$step" = install ]; then
  port=$(sed -n 's/^npm_config_https_proxy=.*@127\.0\.0\.1:\([0-9]*\)$/\1/p' "$obs/install.env")
  echo "$port" > "$obs/relay.port"
  probe 127.0.0.1 "$port" fetch-relay >> "$obs/report"
fi"#
    );
    let shim = Shim::new(&hook);
    std::fs::write(
        run_bin_in(shim.bin.parent().expect("tree")),
        format!(
            "{RUN_BIN}{PROBE}probe 127.0.0.1 \"$(cat /preview-home/obs/relay.port)\" run-relay\nprobe 127.0.0.1 \"$1\" run-host\nprobe 104.16.0.10 443 run-out\n"
        ),
    )
    .expect("run bin");
    let host = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener");
    let port = host.local_addr().expect("addr").port().to_string();
    let Some(ran) = shim.npx(&[&port], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(record(&out, "report"), ["fetch-relay-open"], "{out}");
    let tail: Vec<_> = lines(&out)
        .into_iter()
        .skip_while(|l| !l.starts_with("bin-ran"))
        .collect();
    let want = [
        format!("bin-ran {port}"),
        "run-relay-refused".into(),
        "run-host-refused".into(),
        "run-out-refused".into(),
    ];
    assert_eq!(tail, want, "{out}");
    drop(host);
}

/// F2-T2b, kills m-fd-leak (the control stream reaches the fetch child):
/// nothing the first npm step can list, its own descriptors or PID 1's, is a
/// socket, though PID 1 holds the control stream and the relay then.
/// `pidfd_getfd` is not probed: it passes the same ptrace check as reading
/// `/proc/1/fd`, as in the run phase's F2-T2.
#[cfg(tp4)]
#[tokio::test]
async fn f2_t2b_the_fetch_child_holds_no_control_connection() {
    let hook = r#"if [ "$step" = install ]; then
  ls -l /proc/$$/fd/ /proc/1/fd/ > "$obs/fds" 2>&1
  echo listed >> "$obs/report"
fi"#;
    let shim = Shim::new(hook);
    std::fs::write(
        run_bin_in(shim.bin.parent().expect("tree")),
        format!("{RUN_BIN}cat /preview-home/obs/fds\n"),
    )
    .expect("run bin");
    let Some(ran) = shim.npx(&[], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    assert_eq!(record(&out, "report"), ["listed"], "{out}");
    // Positive control: the listing rendered (the step's output pipes).
    assert!(out.contains("pipe:"), "{out}");
    assert!(!out.contains("socket:"), "{out}");
}

/// 2b-1's CA rows from the fetch child: `ca.pem` is there and cannot be
/// written, removed or renamed, the empty npmrc and certs directory are
/// there and empty, and nothing can be added beside them.
#[cfg(tp4)]
#[tokio::test]
async fn ca_files_are_read_only_from_the_fetch_child() {
    let hook = r#"if [ "$step" = install ]; then
  d=/etc/mcp-gateway-preview
  {
    test -f $d/ca.pem && echo ca-present
    (echo x > $d/ca.pem) 2>/dev/null && echo ca-writable
    (rm -f $d/ca.pem) 2>/dev/null; test -f $d/ca.pem && echo ca-kept
    (mv $d/ca.pem $d/moved) 2>/dev/null && echo ca-moved
    test -f $d/empty-user.npmrc && test -f $d/empty-global.npmrc && echo npmrc-present
    test -s $d/empty-user.npmrc || test -s $d/empty-global.npmrc || echo npmrc-empty
    test -d $d/empty-certs && [ -z "$(ls -A $d/empty-certs)" ] && echo certs-empty
    (touch $d/new) 2>/dev/null && echo dir-writable
  } >> "$obs/report"
fi"#;
    let Some(ran) = Shim::new(hook).npx(&[], GUARD).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    let want = [
        "ca-present",
        "ca-kept",
        "npmrc-present",
        "npmrc-empty",
        "certs-empty",
    ];
    assert_eq!(record(&out, "report"), want, "{out}");
}

/// L2, kills m-lo-skipped and a fetch child with a way out beside the
/// relay: through the relay, with the credential, a CONNECT to the registry
/// is established (positive control) and one to another name is refused,
/// and a direct connect to the registry's address fails. L-proxy's fetch
/// half: the proxy socket is there, a socket, during the fetch.
#[cfg(tp4)]
#[tokio::test]
async fn l2_the_fetch_child_reaches_only_the_registry_through_the_relay() {
    let hook = format!(
        r#"{PROBE}if [ "$step" = install ]; then
  port=$(sed -n 's/^npm_config_https_proxy=.*@127\.0\.0\.1:\([0-9]*\)$/\1/p' "$obs/install.env")
  cred=$(sed -n 's/^npm_config_https_proxy=http:\/\/x:\(.*\)@127\.0\.0\.1:[0-9]*$/\1/p' "$obs/install.env")
  auth=$(printf 'x:%s' "$cred" | base64 -w0)
  ask() {{ timeout 10 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$0"; printf "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n" "$1" "$1" "$2" >&3; head -c 12 <&3' "$port" "$1" "$auth"; }}
  echo "registry $(ask registry.npmjs.org:443)" >> "$obs/report"
  echo "other $(ask github.com:443)" >> "$obs/report"
  probe 104.16.0.10 443 direct-out >> "$obs/report"
  test -S /tmp/proxy.sock && echo proxy-sock-socket >> "$obs/report"
fi"#
    );
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").expect("upstream");
    let port = upstream.local_addr().expect("addr").port();
    let Some(ran) = Shim::new(&hook).npx_dialing(&[], GUARD, port).await else {
        return;
    };
    let out = ran.expect("the fetch and the run succeeded");
    let want = [
        "registry HTTP/1.1 200",
        "other HTTP/1.1 403",
        "direct-out-refused",
        "proxy-sock-socket",
    ];
    assert_eq!(record(&out, "report"), want, "{out}");
    drop(upstream);
}
