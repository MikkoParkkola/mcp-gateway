# ADR-019: Restarting the gateway from the UI

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.3); unblocks U14 (MIK-8867, restart with progress, version and uptime) and UI10 (MIK-8884)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

Gateway › Actions (frame 26) offers Restart for settings that wait for one (a new TLS certificate, a changed `auth` section), and the result frame (26t) shows "Restarted at 14:30 · 3 s down".

| # | Fact | Where |
|---|---|---|
| F1 | The gateway has no restart mechanism. | api-gaps.md F19, Risk 3 |
| F2 | It runs under launchd, systemd, Docker, Homebrew services or a bare shell, and cannot tell which; 4.0 also ships a Windows binary. | api-gaps.md Risk 3; ADR-016 |
| F3 | Host, port and TLS are read once at start; a reload does not change the listener. | `src/gateway/ui/session.rs:154-156` |
| F4 | `main` runs the whole gateway inside `runtime::block_on` and returns an exit code when it ends. | `src/main.rs:55-59` |
| F5 | State is saved on shutdown, but a periodic cost save can be skipped while the previous write is still running, and save failures are logged, not raised. | `src/gateway/server/persistence.rs:145-160`, `:284` |
| F6 | The crate denies `unsafe`. | `src/lib.rs:12` |

## Options

1. **Exit with a reserved code** and rely on the supervisor's restart policy. Works under systemd with `Restart=on-failure` and Docker with a restart policy; under a bare shell or a launchd job without KeepAlive the gateway just stops.
2. **Re-execute itself.** Shut down cleanly, then replace the process image with the same binary and arguments (`std::os::unix::process::CommandExt::exec`, safe Rust, so F6 holds). The PID stays the same, so every supervisor still sees its own process, and a bare shell keeps its foreground job. Not available on Windows.
3. **Guidance only.** The UI says "restart required" and shows the command.

## Decision

Option 2 on Unix, Option 3 where 2 cannot run.

- **Path.** At startup the gateway records the path it was invoked by, and its arguments: argv[0] if it contains a slash (resolved against the start directory), otherwise the first executable match for that name in the startup `PATH`. It keeps that path, not its target, so a symlink an upgrade repoints (as Homebrew does) leads to the new binary. It does not use `current_exe`, which resolves to the running file and would re-run the old version.
- **Refuse first.** Before anything stops, Restart is refused when the platform is Windows or the recorded path is missing or not executable; the UI then shows "Restart required" with the platform's command. Nothing is half-stopped.
- **Sequence.** Stop accepting new calls; let calls in flight finish for up to 10 s, then fail the rest (frame 26 already says a write cut off may have happened); save state and check that every save succeeded (F5). A failed save cancels the restart and reopens for calls, and the UI says why.
- **Exec after the runtime is gone.** The restart request ends `run` with a restart outcome; `main` (F4) drops the runtime, so no worker thread or open listener is left, then calls `exec` from the one remaining thread. Listener sockets are close-on-exec, so the new process binds afresh.
- **If exec returns.** It failed (the file changed between the check and the call). The gateway logs why and exits with code 75 (temporary failure), so a supervisor with a restart policy brings it back. Under a bare shell it stays down; that is the residual risk, and the log line names the command to start it.
- **Progress.** The UI keeps reconnecting and shows the down time when the gateway answers again (26t); the restart and its duration go to the restart log U13 (MIK-8866) keeps for the uptime strip.

## Consequences

- One-click restart under every Unix supervisor and a bare shell, with no supervisor detection.
- An upgrade followed by Restart runs the new binary.
- Windows operators get guidance, not a button, in 4.0.0.
- A few seconds of refused connections during the restart, the "3 s down" in the frames.
- Runtime shutdown is bounded: blocking work still running when the timeout ends is abandoned with the process image, which is why every save is checked before exec rather than after.
- Two cases leave a bare-shell gateway down: an exec that fails after its own check passed, and a new process that execs fine but then fails to start (a config error, a port taken). Both are logged with the command to recover; under a supervisor the second is handled by its restart policy.
