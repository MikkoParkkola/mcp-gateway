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
| F3 | Host, port and TLS are read once at start; a reload does not change the listener. | `src/gateway/ui/session.rs:154-156` (restart-only listener values) |
| F4 | State that must survive a restart is already saved on shutdown. | `src/gateway/server/persistence.rs:284` (`save_state_on_shutdown`) |
| F5 | The crate denies `unsafe`. | `src/lib.rs:12` (`#![deny(unsafe_code)]`) |

## Options

1. **Exit with a reserved code** and rely on the supervisor's restart policy. Works under systemd with `Restart=on-failure` and Docker with a restart policy; under a bare shell or a launchd job without KeepAlive the gateway just stops, and the button lied.
2. **Re-execute itself.** Drain, save state (F4), then replace the process image with the same binary and arguments (`std::os::unix::process::CommandExt::exec`, safe Rust, so F5 holds). The PID stays the same, so every supervisor still sees its own process; a bare shell keeps its foreground job. Not available on Windows.
3. **Guidance only.** The UI says "restart required" and shows the command. Always honest; never a one-click restart.

## Decision

Option 2 on Unix, Option 3 where 2 cannot run.

- **Sequence.** Stop accepting new calls; let calls in flight finish for up to 10 s, then fail the rest (frame 26's copy already says writes cut off may have happened); save state (F4); `exec` the binary at the path the process started from, with the same arguments and environment.
- **Upgrade.** If the binary on disk was replaced by an upgrade, the re-exec runs the new version; Gateway › Status reports the version that comes back.
- **Refusal.** On Windows, or when the starting binary path no longer exists or is not executable, Restart is refused before anything stops, and the UI shows "Restart required" with the service command for that platform. Nothing is half-stopped.
- **Progress.** The UI keeps its connection attempts going and shows the down time when the gateway answers again (26t); the restart and its duration go to the restart log U13 (MIK-8866) keeps for the uptime strip.

## Consequences

- One-click restart under every Unix supervisor and a bare shell, with no supervisor detection.
- Windows operators get guidance, not a button, in 4.0.0.
- The listener is closed for the re-exec: a few seconds of refused connections (the "3 s down" in the frames), which is what an operator restart costs today.
- A crash during the drain falls back to the supervisor's own policy, as any crash does.
