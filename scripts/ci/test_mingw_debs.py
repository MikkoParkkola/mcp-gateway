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
        # The index refreshes listed in STUB_UPDATE_503 hit a 503. As measured on noble's apt 2.8.4, a failed index
        # fetch is a warning and exit 0 (the old index is kept), unless --error-on=any makes it an error and exit 100.
        'case " $* " in *" update "*)\n'
        '  u=$(cat "$STUB_DIR/updates" 2>/dev/null || echo 0); u=$((u+1)); echo $u > "$STUB_DIR/updates"\n'
        '  case " ${STUB_UPDATE_503:-} " in *" $u "*)\n'
        '    case " $* " in *" --error-on=any "*)\n'
        '      echo "E: Failed to fetch http://mirror/ubuntu/dists/noble/InRelease  503  Service Unavailable" >&2; exit 100 ;;\n'
        '    esac\n'
        '    echo "W: Failed to fetch http://mirror/ubuntu/dists/noble/InRelease  503  Service Unavailable" >&2\n'
        '    echo "W: Some index files failed to download. They have been ignored, or old ones used instead." >&2 ;;\n'
        '  esac\n'
        # The source files this call reads: its Dir::Etc::SourceParts, else the apt directory apt-config names. A
        # planted outage of the third-party source (STUB_THIRDPARTY_503) fails a strict refresh that reads it.
        '  parts="$STUB_DIR/etc/apt/sources.list.d"\n'
        '  for a in "$@"; do case "$a" in Dir::Etc::SourceParts=*) parts=${a#Dir::Etc::SourceParts=} ;; esac; done\n'
        '  echo "parts: $(ls "$parts" | tr "\\n" " ")" >> "$STUB_DIR/calls"\n'
        '  if [ -n "${STUB_THIRDPARTY_503:-}" ] && [ -e "$parts/microsoft-prod.list" ]; then\n'
        '    case " $* " in *" --error-on=any "*)\n'
        '      echo "E: Failed to fetch https://packages.microsoft.com/ubuntu/24.04/prod/dists/noble/InRelease  503" >&2; exit 100 ;;\n'
        '    esac\n'
        '  fi ;;\n'
        'esac\n'
        'exit 0\n'
    ),
    "apt-config": '#!/usr/bin/env bash\necho "ETC=\'$STUB_DIR/etc/apt/\'"\n',
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
        # A runner image's apt sources: Ubuntu's in ubuntu.sources (24.04 on), a third-party repository beside it.
        apt_etc = pathlib.Path(t) / "etc" / "apt"
        (apt_etc / "sources.list.d").mkdir(parents=True)
        (apt_etc / "sources.list").write_text(env.get("STUB_SOURCES_LIST", ""))
        if not env.get("STUB_NO_UBUNTU_SOURCES"):
            (apt_etc / "sources.list.d" / "ubuntu.sources").write_text("URIs: mirror+file:/etc/apt/apt-mirrors.txt\n")
        (apt_etc / "sources.list.d" / "microsoft-prod.list").write_text("deb https://packages.microsoft.com/ubuntu/24.04/prod noble main\n")
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


def apt_steps(calls):
    """The apt-get calls in order, each as update, download or other."""
    return ["update" if " update" in line else "download" if "--download-only" in line else "other"
            for line in calls.splitlines() if line.startswith("apt-get")]


# A failed index refresh fails its attempt: apt-get update keeps the image's old index when a fetch fails, and that
# index can name versions the archive no longer carries (a run downloaded every package from it and got 503s).
@row
def a_failed_index_refresh_fails_the_attempt_and_retries():
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_UPDATE_503="1")
    assert rc == 0, out
    assert apt_steps(calls) == ["update", "update", "download"], calls
    assert "mingw attempt 1: apt-get exited 100 during the index refresh" in out, out
    assert debs == ["gcc-mingw-w64-x86-64_1.0_amd64.deb"], debs


@row
def two_failed_index_refreshes_never_download_from_a_stale_index():
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_UPDATE_503="1 2")
    assert rc == 1, (rc, out)
    assert apt_steps(calls) == ["update", "update"], calls
    assert "::error::mingw packages: the Ubuntu mirror did not deliver them in 2 attempts" in out, out
    assert debs == [], debs


# The strict refresh judges only the Ubuntu archive's sources, where the mingw packages come from: an outage of a
# third-party source the runner image adds must not fail the attempt (noble apt 2.8.4 with a dead third-party
# source: a strict refresh over every source exits 100, over ubuntu.sources alone 0).
@row
def only_the_ubuntu_sources_are_refreshed_and_read():
    rc, out, calls, _ = run(["download", "<OUT>"])
    assert rc == 0, out
    apt_calls = [line for line in calls.splitlines() if line.startswith("apt-get")]
    assert len(apt_calls) == 2, calls
    for line in apt_calls:
        assert "Dir::Etc::SourceList=/dev/null" in line and "/sources.list.d" in line, line
    assert "parts: ubuntu.sources \n" in calls, calls


@row
def an_unrelated_source_failing_does_not_fail_the_attempt():
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_THIRDPARTY_503="1")
    assert rc == 0, out
    assert apt_steps(calls) == ["update", "download"], calls
    assert "mingw attempt" not in out, out
    assert debs == ["gcc-mingw-w64-x86-64_1.0_amd64.deb"], debs


@row
def before_24_04_the_sources_list_is_read():
    rc, out, calls, _ = run(["download", "<OUT>"], STUB_NO_UBUNTU_SOURCES="1",
                            STUB_SOURCES_LIST="deb mirror+file:/etc/apt/apt-mirrors.txt jammy main universe\n")
    assert rc == 0, out
    update = next(line for line in calls.splitlines() if line.startswith("apt-get") and " update" in line)
    assert "/etc/apt/sources.list " in update and "Dir::Etc::SourceList=/dev/null" not in update, update
    assert "parts: \n" in calls, calls


@row
def no_ubuntu_source_fails_fast():
    # Neither ubuntu.sources nor a deb line in sources.list: two attempts would read only the image's old index.
    rc, out, calls, debs = run(["download", "<OUT>"], STUB_NO_UBUNTU_SOURCES="1", STUB_SOURCES_LIST="# none\n")
    assert rc == 1, (rc, out)
    assert "::error::mingw packages: no Ubuntu apt source in" in out, out
    assert apt_steps(calls) == [], calls
    assert debs == [], debs


@row
def the_refresh_keeps_the_other_sources_indexes():
    # apt's List-Cleanup (on by default) erases the cached indexes of sources a refresh does not read.
    rc, out, calls, _ = run(["download", "<OUT>"])
    assert rc == 0, out
    update = next(line for line in calls.splitlines() if line.startswith("apt-get") and " update" in line)
    assert "-o APT::Get::List-Cleanup=0" in update, update


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
