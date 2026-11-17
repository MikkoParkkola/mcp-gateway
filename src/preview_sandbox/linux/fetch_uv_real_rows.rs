// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The uv fetch with the real uv 0.13.1 against the fake PyPI (its test plan,
//! the real-uv rows). Each row looks for `uvx` on the test's PATH: absent,
//! it skips with a named line; present, it requires uv 0.13.1 and prints a
//! named `ran` line before its first assertion. The enabling PR deletes the
//! skip, so a missing uv then fails the row.

use super::fetch_uv_real_fixture::{Layout, Real, fixed, lines, ready, real_uvx, site_off, spawns};

/// U-spawn-S (design 3), kills m-no-wrapper and m-unquoted-wrapper: with
/// the recorder as the interpreter's real file, the fetch's one interpreter
/// spawn (uv 0.13.1 makes one: uvprobe2.out) carries -S; the run's own spawn
/// is the only other line; the tool env's python resolves to the recorder.
#[tokio::test]
async fn u_spawn_s_every_fetch_spawn_of_the_interpreter_has_site_off() {
    use super::fetch_rows::Bundle;
    let Some(ready) = ready("u_spawn_s").await else {
        return;
    };
    for under in ["plain", "it's"] {
        let layout = Layout::unlinked(under, Real::Recorder);
        let (out, _) = real_uvx(
            &ready,
            Some(&layout),
            "probe-hook",
            fixed(&[]),
            Bundle::Registry,
        )
        .await;
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
    let Some(ready) = ready("u_hostpth").await else {
        return;
    };
    let layout = Layout::unlinked("plain", Real::Recorder);
    // The host's stdlib may hold sitecustomize.py as a link to a host file
    // (Debian's points into /etc): the copy keeps the link, so it goes first
    // and the hook is created new, never written through it.
    let hook = layout.stdlib().join("sitecustomize.py");
    match std::fs::remove_file(&hook) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("removing the copied sitecustomize.py: {e}"),
    }
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&hook)
            .expect("the hook is created new"),
        HOOK.as_bytes(),
    )
    .expect("hook");
    let (out, _) = real_uvx(
        &ready,
        Some(&layout),
        "probe-hook",
        fixed(&[]),
        Bundle::Registry,
    )
    .await;
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
    let Some(ready) = ready("u_run_layout").await else {
        return;
    };
    for under in ["plain", "a b", "it's"] {
        let layout = Layout::pyenv(under);
        let reads: Vec<String> = layout
            .canaries
            .iter()
            .map(|c| format!("--read={}", c.display()))
            .collect();
        let args: Vec<&str> = reads.iter().map(String::as_str).collect();
        let (out, _) = real_uvx(
            &ready,
            Some(&layout),
            "probe-cli",
            fixed(&args),
            Bundle::Registry,
        )
        .await;
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
    let Some(ready) = ready("l7b").await else {
        return;
    };
    let sentinels = ["alpha", "b c", "--flag=d'e"];
    let args = |port: u16| {
        let mut args: Vec<String> = sentinels.iter().map(|a| (*a).to_owned()).collect();
        args.push(format!("--connect=127.0.0.1:{port}"));
        args
    };
    let (out, index) = real_uvx(&ready, None, "probe-cli", args, Bundle::Registry).await;
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
    let Some(ready) = ready("l7c_sdist").await else {
        return;
    };
    let (out, index) = real_uvx(&ready, None, "probe-sdist", fixed(&[]), Bundle::Registry).await;
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
    let Some(ready) = ready("l7c_url").await else {
        return;
    };
    let (out, index) = real_uvx(&ready, None, "probe-url", fixed(&[]), Bundle::Registry).await;
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
    let Some(ready) = ready("l7c_pth").await else {
        return;
    };
    let layout = Layout::unlinked("plain", Real::Recorder);
    let (out, _) = real_uvx(
        &ready,
        Some(&layout),
        "probe-pth",
        fixed(&[]),
        Bundle::Registry,
    )
    .await;
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
    let Some(ready) = ready("l_name").await else {
        return;
    };
    let (out, _) = real_uvx(&ready, None, "Foo.Bar_Baz", fixed(&[]), Bundle::Registry).await;
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
    let Some(ready) = ready("u_tls").await else {
        return;
    };
    let (out, index) = real_uvx(&ready, None, "probe-cli", fixed(&[]), Bundle::Registry).await;
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
    let (out, index) = real_uvx(&ready, None, "probe-cli", fixed(&[]), Bundle::Other).await;
    let refused = out.expect_err("an untrusted index refuses");
    assert!(at_step(&refused, "the fetch's uv install"), "{refused:?}");
    assert_eq!(index.requests(), Vec::<String>::new());
}
