#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/mingw-debs.sh: the restore-keys prefix, and a mirror
download bounded per attempt and retried once.

A mirror that trickles (43.5 kB/s for 43 min) never trips apt's own
timeouts, so each download attempt has a wall-clock bound and a second
attempt opens fresh connections. sudo, timeout and apt-get are stubbed on
PATH: timeout reports a timed-out attempt (exit 124) for the attempts named in
STUB_TIMEOUTS, and apt-get writes one .deb into the archive directory it is
given when an attempt is allowed to finish.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "mingw-debs.sh"

STUBS = {
    "sudo": '#!/usr/bin/env bash\nexec "$@"\n',
    # timeout <secs> cmd...: count attempts; a listed attempt "times out".
    "timeout": (
        '#!/usr/bin/env bash\n'
        'n=$(cat "$STUB_DIR/attempts" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$STUB_DIR/attempts"\n'
        'echo "timeout $1" >> "$STUB_DIR/calls"\n'
        'case " ${STUB_TIMEOUTS:-} " in *" $n "*) exit 124 ;; esac\n'
        'shift; exec "$@"\n'
    ),
    "apt-get": (
        '#!/usr/bin/env bash\n'
        'echo "apt-get $*" >> "$STUB_DIR/calls"\n'
        'for a in "$@"; do case "$a" in Dir::Cache::Archives=*) d=${a#Dir::Cache::Archives=} ;; esac; done\n'
        'case " $* " in *" --download-only "*) [ -z "${STUB_APT_FAIL:-}" ] || exit 100; touch "$d/gcc-mingw-w64-x86-64_1.0_amd64.deb" ;; esac\n'
        'case " $* " in *" --no-download "*) [ -z "${STUB_NODL_FAIL:-}" ] || exit 100 ;; esac\n'
        'exit 0\n'
    ),
    "dpkg-deb": '#!/usr/bin/env bash\nexit 0\n',
    "x86_64-w64-mingw32-gcc": '#!/usr/bin/env bash\necho "x86_64-w64-mingw32-gcc 13"\n',
}


def run(args, **env_extra):
    with tempfile.TemporaryDirectory() as t:
        stub = pathlib.Path(t) / "bin"
        stub.mkdir()
        for name, body in STUBS.items():
            p = stub / name
            p.write_text(body)
            p.chmod(0o755)
        env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}", STUB_DIR=t,
                   RUNNER_TEMP=t, ImageOS="ubuntu24", ImageVersion="20261101.1")
        env.update(env_extra)
        out_dir = pathlib.Path(t) / "debs"
        argv = [a.replace("<OUT>", str(out_dir)) for a in args]
        r = subprocess.run(["bash", str(SCRIPT), *argv], env=env, capture_output=True, text=True)
        calls = (pathlib.Path(t) / "calls").read_text() if (pathlib.Path(t) / "calls").exists() else ""
        debs = sorted(p.name for p in out_dir.glob("*.deb")) if out_dir.exists() else []
        return r.returncode, r.stdout + r.stderr, calls, debs


ROWS = []


def row(fn):
    ROWS.append(fn)
    return fn


@row
def prefix_names_the_os_only():
    rc, out, _, _ = run(["prefix"])
    assert rc == 0 and out.strip() == "mingw-debs-ubuntu24-", (rc, out)
    rc, out, _, _ = run(["key"])
    assert out.strip().startswith("mingw-debs-ubuntu24-20261101.1-"), out


@row
def a_download_that_finishes_takes_one_bounded_attempt():
    rc, out, calls, debs = run(["download", "<OUT>"])
    assert rc == 0, out
    assert calls.count("timeout 600") == 1, calls
    assert "did not finish" not in out, out
    assert debs == ["gcc-mingw-w64-x86-64_1.0_amd64.deb"], debs


@row
def a_timed_out_attempt_is_retried_once():
    # Each attempt is two bounded calls (index refresh, then download): call 2 is attempt 1's download.
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_TIMEOUTS="2")
    assert rc == 0, out
    assert calls.count("timeout 600") == 2, calls
    assert "mingw attempt 1: the download (600s) did not finish in time" in out, out
    assert debs == ["gcc-mingw-w64-x86-64_1.0_amd64.deb"], debs


@row
def two_timed_out_attempts_fail_with_a_clear_error():
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_TIMEOUTS="2 4")
    assert rc == 1, (rc, out)
    assert calls.count("timeout 600") == 2, calls
    assert "::error::mingw packages: the Ubuntu mirror did not deliver them in 2 attempts" in out, out
    assert debs == [], debs


@row
def the_bound_is_configurable():
    rc, out, calls, _ = run(["download", "<OUT>"], MINGW_DOWNLOAD_SECONDS="5", MINGW_UPDATE_SECONDS="3", STUB_TIMEOUTS="2 4")
    assert rc == 1 and calls.count("timeout 5") == 2 and calls.count("timeout 3") == 2, (rc, calls)


@row
def a_stalled_index_refresh_is_bounded_and_named():
    rc, out, calls, _ = run(["download", "<OUT>"], STUB_TIMEOUTS="1 3")
    assert rc == 1, (rc, out)
    assert "mingw attempt 1: the index refresh (180s) did not finish in time" in out, out
    assert "--download-only" not in calls, calls


# Review 2026-11-06: the index refresh is bounded too; an apt error is not reported as a time-out; the
# fallback set installs through apt with downloads off, so a set that needs anything else fails before
# unpacking and leaves no half-installed state behind for the mirror install.
@row
def the_index_refresh_is_bounded_too():
    rc, out, calls, _ = run(["download", "<OUT>"])
    assert rc == 0, out
    lines = calls.splitlines()
    i = next(k for k, l in enumerate(lines) if l.startswith("apt-get") and " update" in l)
    assert i > 0 and lines[i - 1].startswith("timeout "), calls


@row
def an_apt_error_is_named_as_such_not_as_a_timeout():
    rc, out, _, _ = run(["download", "<OUT>"], STUB_APT_FAIL="1")
    assert rc == 1, (rc, out)
    assert "apt-get exited 100 during the download" in out and "did not finish in time" not in out, out


@row
def the_fallback_set_installs_through_apt_with_downloads_off():
    with tempfile.TemporaryDirectory() as t:
        pathlib.Path(t, "a.deb").touch()
        rc, out, calls, _ = run(["install-local", t])
    assert rc == 0, out
    assert "--no-download" in calls and "install" in calls, calls


@row
def a_fallback_set_that_needs_a_download_fails_cleanly():
    with tempfile.TemporaryDirectory() as t:
        pathlib.Path(t, "a.deb").touch()
        rc, out, calls, _ = run(["install-local", t], STUB_NODL_FAIL="1")
    assert rc != 0, (rc, out)
    assert "dpkg -i" not in calls, calls


def main():
    failed = 0
    for fn in ROWS:
        try:
            fn()
            print(f"ok    {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"WRONG {fn.__name__}: {e}")
    print(f"mingw-debs rows: {len(ROWS) - failed} ok, {failed} wrong")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
