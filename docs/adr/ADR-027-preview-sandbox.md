# ADR-027: The command-server preview runs in a per-OS sandbox, or not at all

- **Status**: Accepted, 2026-10-25.
- **Criterion**: SBX.1 (the web UI's start-once server preview waits on it for command servers)
- **Requirements**: a sandbox that works on a default install in 4.0.0, and never an unsandboxed run; macOS
  keeps escapees sandboxed and lists them by pid, never saying "gone"; Ubuntu 24.04+, Docker and hardened RHEL
  refuse with the fix named, documented in SECURITY and UPGRADING; npm and PyPI only, GitHub release hosts in
  a later release
- **Scope**: how `POST /ui/api/previews` starts a typed command once. Out of scope: backends that are
  added and run normally, URL and OpenAPI previews (no code runs here), Windows (refused).

## Context

A preview runs an unverified package (`npx -y …`, `uvx …`, or any typed command) to list its tools before the
operator saves it. Today's stdio launch gives a child a minimal environment and its own process group
(`transport/stdio.rs`, `stdio_tree.rs`), but the child can read anything the gateway's user can, including
`~/.mcp-gateway`, and a descendant that calls `setsid` leaves the group that cleanup kills.

Constraints, each checked:

- `#![deny(unsafe_code)]` (`src/lib.rs:12`), and `#[allow]` is not used to silence lints. `CommandExt::pre_exec`
  is `unsafe fn`. rustix 1.1.5's safe `thread::unshare` is `#[deprecated]` and documented in its own source as
  "not actually safe" (the r1 draft wrongly called it safe); `unshare_unsafe` is the supported call. So the
  gateway makes no namespace syscall itself.
- rustix's `mount::mount`, `fsmount`, `move_mount` and `unmount` are safe functions (registry source).
- Landlock restricts only the calling thread, and its network rules are port-only (allowing 443 allows
  `127.0.0.1:443`); pathname Unix sockets are covered only from ABI 9. It is not used.
- `sandbox-exec` works on macOS 27.0.1 (checked on macOS 27.0.1: a read under `~/.mcp-gateway` is "Operation not
  permitted" inside a profile and succeeds outside), and a `setsid` + double-fork descendant survives it,
  reparented to launchd (also checked on macOS 27.0.1).
- Sources for every other OS fact: References, at the end.

## Decision: fetch, then run offline

A preview has two phases, both sandboxed, launched only by `preview_sandbox::start`:

1. **Fetch** (only for `npx` and `uvx` commands): the trusted package manager downloads the package and its
   dependencies into the preview's disposable home and **executes nothing from them**: `npm install
   --ignore-scripts --prefix <home>/pkg <spec>` for npx (bins are linked, never run; it also fills `$HOME/.npm`
   for the offline run), and `uv tool install --no-build <spec>` for uvx, with `UV_TOOL_DIR` and the uv cache in
   the preview home (wheels only, so no build script runs). No command name is looked up on a PATH the install
   has changed: the r2 form `npm exec … -- true` / `uvx --from <pkg> true` ran a package-provided `true` and is
   gone. Its only network route is the gateway's allowlist proxy (below).
2. **Run**: the package itself starts with **no network at all** (`npm_config_offline=true`, `UV_OFFLINE=1`, and
   per OS below no route anywhere), lists its tools over stdio, and is torn down. Any other typed command has no
   fetch phase and only this one.

Because the package's own code never has a network route, it cannot exfiltrate (not even by publishing to the
registry with a token it carries), and a macOS descendant that escapes the process group inherits a profile with
no network permission. Packages that need install scripts or source builds fail their preview with the step
named; they can still be added without one.

**The fetch step stays outside the package's control**. The gateway builds the fetch
command itself; nothing from the typed command reaches it except a validated package spec:

- The typed command is parsed strictly: `npx [-y|--yes] <spec> [server args]` or `uvx <spec> [server args]`.
  Any npx or uvx option before the spec (`--registry`, `--node-options`, `--index-url`, `--with`, `--python`, …)
  refuses the preview, as do anything else that is not one of these two shapes and still needs a fetch.
- The spec must be a registry package name with an optional version: no `file:`, `git:`, `github:`, `http(s):`,
  tarball, alias or local-path form, so the trusted manager fetches only from the allowlisted registries and runs
  no local code.
- No configuration can come from outside: `HOME` and the working directory are the fresh preview home, so no
  user or project `.npmrc`, `pip.conf` or `uv.toml` exists; the environment sets `npm_config_ignore_scripts=true`
  and the registry URLs explicitly, and `UV_NO_BUILD=1`, `UV_NO_CONFIG=1`.
- Server args after the spec go only to the run phase, never to the fetch.

Every phase, on every OS, also gets:

- **No secrets**: the resolved backend's env, headers and OAuth are dropped (U6 design r3); the environment is
  minimal plus `HOME` and `TMPDIR` set to the preview home and the phase's package-manager variables.
- **A disposable home**: an empty temporary directory as `HOME`, working directory and package caches, deleted
  after the preview. No persistent cache.
- **Bounds**: 30 s for both phases together, then teardown; output read through the launcher's raw reader with a
  4 MiB frame cap and an 8 MiB total budget, enforced before parsing. The preview home is a tmpfs of at most
  1 GiB (on macOS a 1 GiB sparse APFS disk image the gateway's user creates and attaches with `hdiutil`, which needs no privileges, detached at teardown; if `hdiutil` fails, command previews refuse); every process gets `RLIMIT_AS` 4 GiB, `RLIMIT_FSIZE`
  512 MiB and `RLIMIT_NOFILE` 1024 (safe `rustix::process::setrlimit`), and `RLIMIT_NPROC` is the user's current
  process count plus 256. `RLIMIT_NPROC` counts the uid host-wide, which is a known limit: a pids cgroup would
  be exact but needs privileges the gateway does not have.
- **Its own environment**: the launcher builds it; it never calls the stdio path's
  `configure_child_environment` or `assigned_package_cache_dir`, which set the real `HOME` and a persistent
  per-backend cache.
- **One table** of readable paths, writable paths and network reach per OS drives the Linux bind list, the
  macOS profile and the reported `Isolation`, so the report cannot drift from what was enforced.

**The allowlist proxy** (fetch phase only): an HTTP CONNECT proxy in the gateway, listening on IPv4 and IPv6
loopback on one port reserved for the gateway's lifetime (outside a fetch it refuses every connection, so the
port is never released for something else to take), requiring a fresh random credential per fetch in `Proxy-Authorization` (passed only in that fetch's proxy URL, so an escapee from an earlier fetch holds an expired one), admitting only `registry.npmjs.org`, `pypi.org` and
`files.pythonhosted.org` on 443 by exact hostname equality. Names are resolved once through the existing
`PinningResolver`, refused when any address is loopback, link-local, private or cloud metadata (the SSRF deny
list) or is assigned to one of the host's own interfaces (read at each CONNECT, since the deny list does not
hold the host's global addresses), and only the pinned addresses are dialled. A fetch reaches the proxy
through `HTTPS_PROXY`, `HTTP_PROXY`, `npm_config_https_proxy` and `npm_config_proxy`, each
`http://<credential>@127.0.0.1:<port>` with an IPv4 literal (no name lookup), and `NO_PROXY` empty.
IPv4-mapped and IPv4-compatible IPv6 addresses are unwrapped before every address check, as `is_private_ipv6`
already does. When a credential expires, the proxy also closes every tunnel already open under it, not only
new ones. The fetch sets `npm_config_git` to a path that does not exist, so a git dependency anywhere in the
tree fails before anything is cloned (a git dependency's own `.npmrc` can select a program to run even under
`--ignore-scripts`), and such a fetch is refused; the proxy refuses git hosts as well.
Only the trusted package manager talks to it, and only for downloads; dependency URLs that point anywhere else
are refused by it.

### Linux: util-linux `unshare`, a private read-only root, no network in the run phase

The gateway starts the whole preview, both phases, as one namespace set:

```
/usr/bin/unshare --user --map-root-user --mount --propagation private --pid --fork --kill-child --mount-proc \
    --net --ipc --uts <gateway binary> __preview-sandbox <table and paths, as arguments>
```

It starts `unshare` with `env_clear` and the same environment allowlist as the child, so neither `unshare` nor
the helper ever holds a gateway secret. util-linux makes the namespace calls (in every mainstream distro's base
system), so the gateway itself makes none. `--map-root-user` maps namespace root to the gateway's uid, which
gives the helper `CAP_SYS_ADMIN` inside the namespace for its mounts. `--fork --pid --mount-proc` makes the
helper the first process of a new PID namespace with its own `/proc`; `--kill-child` kills it when `unshare`
dies. `--net` gives an empty network namespace whose only interface is its own `lo`. `--ipc` and `--uts` cut
host System V IPC and the host name. The gateway invokes `unshare`, `ip`, `npm` and `uv` by the absolute paths
its probe resolved.

The helper subcommand is dispatched on the main thread before `on_main_stack` and before any runtime starts,
and then, inside the namespaces, in this order:

1. Refuses unless it is really in fresh namespaces: the gateway passes its own user, mount, PID and network
   namespace inodes, and the helper compares `/proc/self/ns/*` against them. Refuses too if any descriptor other
   than 0 to 2 is open (it lists `/proc/self/fd`, leaving out the directory descriptor that listing itself
   holds): closing a raw descriptor would need `unsafe`, so a descriptor the gateway inherited without
   close-on-exec fails the preview closed instead of leaking. Every descriptor the helper opens later (the
   control socket, the relay, mount handles) is close-on-exec, which std does by default, so no child inherits
   one. Makes
   itself non-dumpable (`set_dumpable_behavior`), so a capability-less process in the namespace cannot read its
   `/proc/1/environ`, `/proc/1/fd` or `/proc/1/mem`.
2. Stages a fresh root on a tmpfs (`size=16M`). Every tmpfs it mounts, this one included, carries `MS_NOSUID |
   MS_NODEV`. Each runtime path is bind-mounted recursively (`MS_BIND | MS_REC`), and then it and every submount
   under it is remounted `MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV` (an initial bind ignores
   those flags, and a remount reaches only one mount). Runtime paths: `/usr`, `/bin`, `/lib*`, `/etc/ssl`, `/etc/ca-certificates`, `/etc/pki/tls`. The
   command's program binds on an allowlist, by where its real file is: under those roots, nothing more; under
   `/usr/local`, its directory and a sibling `lib`, bound back; inside a known runtime tree (an NVM node version, a
   pyenv version, a Homebrew keg), that tree alone; anywhere else, the file alone, never the directory around it,
   so a home or any other private directory is excluded without having to be found. The drop execs the program under the name
   it was asked for (`argv[0]`): by the path asked for (its directory links resolved) when that path and every link after it
   lie where the root shows them and no later link's target passes through a directory link (a kernel-started script
   sees the exec path as its `$0`), and by its real file otherwise; so on Debian a program reached through
   `/etc/alternatives` runs as its real file. The run phase's `PATH`
   names the exec path's directory, so an alias outside the binds never puts its own directory there. Every masking mount is a tmpfs with `size=4k`, mounted writable only long enough to create the
   mountpoints of any bind-back under it, then remounted `MS_RDONLY`: one over `/usr/local` (with that
   interpreter directory bound back if it lies there), one each over `/etc/ssl/private` and
   `/etc/pki/tls/private`, and one over every resolved gateway state, config and data path that falls under any
   bind. Plus the preview home (tmpfs `size=1G`, read-write), a `/tmp` (tmpfs `size=256M`), `/dev/null`,
   `/dev/zero`, `/dev/urandom`, and the PID namespace's `/proc` mounted at the new root's `/proc` with `hidepid=2,gid=1` (then remounted, as
   kernels before 5.8 keep the options per superblock), so the helper (PID 1), which the target cannot ptrace, is
   not listed there, whatever host groups the gateway's user holds. The remount for kernels before 5.8 is untested on a real
   5.4-5.7 kernel; CI covers 6.x (a pre-release run on such a kernel is tracked as SBX.8). The gateway
   proxy's Unix socket is bound in now, while its host path is still reachable, onto a file under the writable
   `/tmp`, so the helper alone can unmount and remove it after the fetch (step 6); nothing in the new root is from `/run`, `/var` or any home; no
   `/etc/resolv.conf` (the fetch reaches only the proxy on `127.0.0.1`, which resolves names on the gateway
   side). Then it reads back the final attributes of every mount in the new root and refuses on any mismatch.
3. `pivot_root`s into it, `chdir("/")` at once (a working directory left outside the new root would survive a
   lazy unmount), then `umount2(put_old, MNT_DETACH)`, removes `put_old`, and remounts the new root itself
   read-only. No host Unix socket path (system D-Bus, `docker.sock`, agent sockets) and no gateway state, config
   or data path exists inside, wherever those paths live.
4. Brings `lo` up with iproute2's `ip link set lo up` (present wherever util-linux is; rustix's only interface
   call is an unsafe ioctl), for the fetch.
5. Starts every phase child as `<gateway binary> __preview-drop <limits> <program> -- <target argv>` (by `/proc/self/exe`,
   which the private root keeps reachable as the helper's own image), so the helper itself keeps its namespace
   capabilities for the step-6 unmount and never runs untrusted code. `__preview-drop` drops every privilege, in
   the order the kernel needs (clearing `CAP_SETPCAP` first would make the later calls fail): the secure bits
   `NOROOT`, `NOROOT_LOCKED`, `NO_SETUID_FIXUP` and their locks (`set_capabilities_secure_bits`), then every
   capability out of the bounding set (`remove_capability_from_bounding_set`), then the ambient set, then the
   effective, permitted and inheritable sets last (`set_capabilities`); then no-new-privileges and the resource
   limits. All safe rustix calls, checked in its source; each result is checked, and any failure refuses. Then
   it applies a seccomp filter and `exec`s the target (`CommandExt::exec`, safe). The filter begins with the
   helper's own six-instruction preamble, prepended to the program seccompiler compiles (a `BpfProgram` is a
   plain vector of filter instructions, built without `unsafe`), because seccompiler's rules are keyed by
   syscall number and cannot say "any number with a bit set". Each test is followed by its own return: load
   the architecture; if it is the host's, jump over the next instruction; return `SECCOMP_RET_KILL_PROCESS`;
   load the syscall number; on x86_64, if the x32 bit (`0x40000000`) is clear (`JSET`), jump over the next
   instruction; return `SECCOMP_RET_KILL_PROCESS`. Every jump is one instruction forward, well inside BPF's
   255-instruction jump range, and only a number that passes both tests reaches seccompiler's program (which
   checks the architecture again, harmlessly). An architecture check alone passes x32 numbers. Killing, not an
   errno, so a test can tell this rule from any other refusal. The instructions, as `(code, jt, jf, k)`:

   | # | x86_64 | aarch64 | Meaning |
   |---|---|---|---|
   | 1 | `(0x20, 0, 0, 4)` | `(0x20, 0, 0, 4)` | load `seccomp_data.arch` |
   | 2 | `(0x15, 1, 0, 0xC000003E)` | `(0x15, 1, 0, 0xC00000B7)` | host arch: skip the kill |
   | 3 | `(0x06, 0, 0, 0x80000000)` | `(0x06, 0, 0, 0x80000000)` | `SECCOMP_RET_KILL_PROCESS` |
   | 4 | `(0x20, 0, 0, 0)` | none | load `seccomp_data.nr` |
   | 5 | `(0x45, 0, 1, 0x40000000)` | none | x32 bit set: fall to the kill; clear: skip it |
   | 6 | `(0x06, 0, 0, 0x80000000)` | none | `SECCOMP_RET_KILL_PROCESS` |

   aarch64 has no x32 ABI, so its preamble is the first three. Then seccompiler's own rules deny the keyring calls (`keyctl`, `add_key`, `request_key`, so an inherited
   session keyring cannot be read) and `ptrace`, `process_vm_readv`/`writev`, `unshare`, `setns`, `mount`,
   `umount2`, `pivot_root`, `clone` with namespace flags, `clone3` (answered `ENOSYS`, not `EPERM`, so libc
   falls back to plain `clone` when spawning), `io_uring_*` and `bpf`, as Codex and sandbox-runtime do. A
   default-deny allowlist was considered and not taken: it must cover every syscall of any Node, Python or
   native MCP server and breaks unfamiliar runtimes, while the namespaces and the private root are the boundary
   and the filter only narrows the kernel surface. The helper is non-dumpable and the children cannot `ptrace`,
   so its capabilities are not reachable from them.
6. **Fetch** (npx and uvx only): asks the gateway for a fresh proxy credential over the control socket
   (`fetch-start`; never passed as an argument, since `/proc/1/cmdline` stays readable when non-dumpable),
   starts the relay (one loopback TCP port inside the namespace to the proxy's Unix socket, because npm and uv
   take a TCP proxy URL), and spawns the fetch command with `std::process::Command` (`env_clear` and an
   explicit allowlist: `PATH`, `HOME`, `TMPDIR`, the proxy URL with the credential, named npm and uv variables
   and `UV_PYTHON_DOWNLOADS=never`; the host's `HTTP(S)_PROXY`, `ALL_PROXY` and `NODE_OPTIONS` never reach it).
   The credential exists only in the helper's memory and that child's environment. When the fetch exits the
   helper, in this order: SIGKILLs every other pid in the namespace (it is PID 1 and lists `/proc`) and reaps
   them, repeating until `/proc` lists only PID 1 and `waitpid` answers `ECHILD`, so a fork in flight during one
   sweep is caught by the next; any pid still present after 2 s refuses the preview. Then it closes the
   relay listener and every relayed stream, sends `fetch-done` on the control socket and waits, bounded, for
   the gateway's ack that the credential is expired, then unmounts the socket's bind and removes the path. Any
   step that fails refuses the preview before the run phase: the helper exits, which kills the namespace and
   everything left in it. The gateway expires a fetch's credential on `fetch-done`, on the helper's exit, or at the
   fetch's deadline on the gateway's own timer, whichever comes first, so expiry never depends on the helper
   reaching its success path, nor on a namespace's first process finishing its exit.
7. **Run**: spawns the run command the same way, in the same namespaces, so it sees the fetch's install in the
   preview home. The argv for an npx server is `<node> <the bin's target file>`; for a uvx server it is the
   installed entry-point script itself, whose shebang names the tool environment's Python, so the installed
   dependencies are on its path (never the host Python running the script). The bin is the package's only one,
   or the one named after the package; anything else refuses. The server args follow. `PATH` holds the
   interpreter directory and the install's bin directory, so shebang scripts start. Its environment has no proxy URL and no
   credential, and no socket, relay or loopback listener of the gateway exists in the namespace, so nothing
   inside has a route anywhere. The helper stays as PID 1, forwards the child's stdio, reaps orphans, and exits
   when the child does. Cleanup kills it, and with it the whole namespace.

**Cleanup.** Killing the helper, which is PID 1 of the namespace, makes the kernel SIGKILL every process in it
(`pid_namespaces(7)`), `setsid` and double-forked descendants included. The launcher records the target's host
pid before teardown and checks it is gone.

**Teardown reachability.** A teardown that runs only when an async path is driven to its end leaves the
sandbox running when that path is dropped, or when its runtime is never driven again; a teardown wait with no
deadline can hold shutdown. So each teardown below has a synchronous backstop that needs no driven runtime, a
deadline on every wait, and a named test for each of three cases: the owning future dropped, the runtime idle,
and the teardown's own I/O stalled.

| Teardown | Dropped future | Idle runtime | Stalled I/O |
|---|---|---|---|
| Linux helper kill (`preview_sandbox::Started`) | `a_dropped_preview_kills_its_namespace` | `a_preview_dropped_after_its_runtime_still_ends` | N/A: one `SIGKILL` sent in `Drop` with no wait to bound; `--kill-child` then kills the namespace's first process, and the kernel every process in it |
| macOS marker scan | named with the macOS sandbox | named with the macOS sandbox | its 2 s deadline |
| macOS `hdiutil detach` | named with the macOS sandbox | named with the macOS sandbox | a deadline on the detach |

**Probe and refusal (SBX.5).** Run once at gateway start with `/bin/true` as the target, through the real setup
(namespaces, mounts, pivot, seccomp), then once more with `<interpreter> --version` for each interpreter the
fetch phases use, cached for the process lifetime. Any failing step refuses every command
preview, naming the step, the errno and the fix:

| Host | Fails at | Message names |
|---|---|---|
| Ubuntu 24.04+ | mounts inside the namespace (AppArmor denies capabilities in it) | the one-time root step: an AppArmor profile granting `userns` to the gateway binary's path, whose text SECURITY.md gives, then `apparmor_parser -r` (not shipped in packages) |
| Docker, Podman default | `unshare` (seccomp denies it) | that a container cannot nest this sandbox; preview from a host install, or add the server without a preview |
| `user.max_user_namespaces = 0` (STIG RHEL) | `unshare` | the sysctl, and that the host's hardening forbids it |
| no util-linux `unshare` | before start | the missing tool |
| no iproute2 `ip` | before a fetch | the missing tool (command previews with no fetch still run) |

The server can always be added without a preview.

### macOS: Seatbelt, two profiles, escapees inherit no network

Each phase runs as `/usr/bin/sandbox-exec -p <profile> <command>` (no FFI), started through the same
`__preview-sandbox` helper as on Linux: it lists `/dev/fd` (leaving out its own listing descriptor) and refuses
on any descriptor other than 0 to 2, because Seatbelt keeps access through descriptors opened before the
profile applies, sets the resource limits, then `exec`s `sandbox-exec` (`CommandExt::exec`, safe). Every path
interpolated into a profile goes through one quoting function (it escapes `"` and `\` and refuses a newline),
with a test for each. `sandbox-exec` is marked deprecated
since about 10.12 but works on macOS 27.0.1 and is used by Codex, Anthropic's sandbox-runtime and
Chromium; if Apple removes it, command previews fall back to the refusal.

Both profiles: `(deny default)`; process-fork and process-exec allowed (npx and uvx fork workers); signals only
`(target same-sandbox)`; file reads of the table's system paths (`/usr`, `/System`, `/Library/Frameworks`);
reads and writes of `/dev/null` and `/dev/zero` and reads of `/dev/urandom`, the same three devices Linux
binds (so `subprocess.DEVNULL` and the like work); no `mach-lookup` of the keychain and security services
(`com.apple.securityd*`, `com.apple.SecurityServer`). Then, in this order, because the last matching rule wins
(checked on macOS 27.0.1: a deny after an allow denies, the same deny before the allow does not): `deny file-read*` and
`deny file-write*` on `/usr/local`, as Linux masks it, on all of `/Users`, and on all of `/System/Volumes`
(the data volume's own spelling of `/Users` and `/usr/local`, which the `/System` allow would otherwise
reopen; nothing a preview needs lives only there); then allow reads of the command
interpreter's binary directory plus the library directories it needs (never a whole Homebrew prefix, and an
NVM `node` under the user's own home is allowed back here, after the home deny), and reads and writes of the
preview home, whose disk image is attached outside every denied path; then, **last**, `deny file-read*` and
`deny file-write*` on the resolved gateway state, config and data paths, so a state directory placed under an
allowed prefix (for example by `MCP_GATEWAY_CONFIG_DIR` under `/usr/local/etc`) stays unreadable.

- Fetch profile: network outbound only to the proxy, written `(remote tcp "localhost:<proxy port>")` (Seatbelt host filters accept only
  `localhost` and `*`, so "only the proxy" is the expressible rule; the proxy enforces the allowlist). The fetch
  phase runs no package code: npm runs with `--ignore-scripts`, and uv with `--no-build` and `UV_NO_BUILD=1`, so
  it installs wheels only and refuses a package that needs a source build rather than building it. Any process
  holding this profile is therefore npm, uv or one of their own workers, all of which keep the marker. The
  post-fetch scan (below) must leave no marked process alive: a survivor it cannot kill refuses the preview
  before the run phase starts, and is listed by pid.
- Run profile: **no network rule at all**, so everything is denied. A descendant that escapes the process group
  keeps this profile (children inherit their parent's sandbox and cannot drop it), so it has no network and no
  access to the gateway's paths or any home, whatever later listens on any port.

**Cleanup.** The launcher kills the run phase's process group. macOS has no unprivileged way to kill a
descendant that calls `setsid` or double-forks (no PID namespace, no subreaper, no cgroups; kqueue `NOTE_TRACK`
returns `ENOTSUP`); measured here, one survives and is reparented to launchd. Every process inherits
`MCP_PREVIEW_MARK=<preview id>`. After the group kill the launcher reads each candidate's environment as whole
entries through `KERN_PROCARGS2` (via a safe crate, `sysinfo`'s process environment reader the candidate,
confirmed by the source-read gate below; never by parsing `ps` text, which a process can shape), matches the
exact entry, considers only pids that started after the preview began, never the gateway's own pid, SIGKILLs
each match, and repeats the scan until one finds no marked pid, with a 2 s deadline. It fails closed: a
process of the gateway's user, started after the preview began, whose environment cannot be read counts as a
survivor, never as clean; a pid left at the
deadline is listed, and after a fetch it refuses the run phase. Immediately before each signal it re-reads that
pid's start time and marker; if either changed (the pid was reused), it does not signal and reports the pid
instead. macOS has no pidfd, so a race remains between that check and the signal: a reuse inside it needs the PID counter to wrap past every other process in the instant between two system calls. That residual is named here and the report says "killed or reported", never more. The scan runs after the fetch phase as well as after the run phase. The report lists by pid every
match it found and whether it was killed. A process that `exec`s itself with an empty environment is not found; it is still
sandboxed with no network. No text on macOS says the processes are "gone" or "stopped"; it reports the group
kill and the scan.

**Probe and refusal (SBX.5).** At gateway start the launcher creates a canary file under the gateway's data
dir, runs the run profile against `/bin/cat <canary>` and requires `EPERM`, then runs `<interpreter> --version` under the same profile with the real preview home and requires success ("Operation not permitted"); any
other result, `sandbox-exec` missing included, refuses every command preview with the reason. ENOENT never
counts as a working sandbox.

### Windows

Command previews are refused (SBX.5): "command previews need a sandbox this platform does not have in 4.0.0".
Job Objects and AppContainer are the route for a later release.

## What the UI may say (SBX.6)

The launcher returns `Isolation`, built from the same table that drove the binds and the profile: `{os,
readable: [paths], writable: [paths], network: {fetch: "npm and PyPI through the gateway's proxy" | null, run:
"none"}, cleanup: "process namespace killed" | "process group killed; N escapees found and killed, M found and not
killed (pids); a run-phase escapee that cleared its environment is not found and stays sandboxed with no
network"}`. Only the run phase can leave an unlisted escapee: the fetch phase runs no package code, only npm
or uv, which keep the marker, so the scan finds every fetch-phase process, and one it cannot kill refuses the
run phase. No unlisted process holds the fetch profile's network rule unless npm or uv itself is compromised,
which is outside this ADR's threat model as for any trusted tool. The
202 confirmation and the preview response render only from it; nothing is filled in from a constant, and a
refused host has no `Isolation`, only the refusal.

## Explicitly out of scope

- Sandboxing backends that are added and run normally.
- Install scripts and source builds in the fetch phase (packages that need them fail their preview).
- GitHub release hosts (v4.1.0).
- Any setting to widen the allowlist or turn the sandbox off (simple-UX rule; there is no unsandboxed preview).

## Consequences

- Command previews work on Debian 11+, Fedora, Arch, Ubuntu 22.04, unhardened RHEL 8/9 and macOS; they are
  refused on Ubuntu 24.04+ until the one-time AppArmor step, in containers, on STIG-hardened RHEL and on Windows.
- Every command preview downloads its package cold (no persistent cache).
- New code on the preview path only: two hidden helper subcommands (`__preview-sandbox`, `__preview-drop`), a
  CONNECT proxy with its control socket, a relay and a seccomp filter; the invoke path is unchanged (SBX.7
  benchmark).
- Two crates to confirm, each a hard gate on the sandbox's first implementation commit: that
  commit adds the pinned dependency, its source is read from the crate cache before any code calls it, and
  cargo-deny and the repo's supply-chain checks run on it. For the seccomp filter (`seccompiler`) the read
  confirms `apply_filter` and the `BpfProgram` type have no `unsafe` in their public API (a reviewer read them
  as safe; not yet re-read here); for the macOS process-environment reader (`sysinfo`, the candidate), the same. If either needs `unsafe`,
  work stops and it becomes an ADR-016-style maintainer decision, not one taken in the PR.

## Acceptance (the sandbox's tests prove these; each denial has its positive control)

| AC | Linux CI | macOS CI |
|---|---|---|
| SBX.2 | canaries in a fake `~/.mcp-gateway`, the config dir, another home, `/run` and `/var/lib` are unreadable inside, and readable outside; an inherited session-keyring key cannot be read inside; a permitted runtime file is readable | canaries in `~/.mcp-gateway`, the config dir (including one placed under an allowed prefix) and another home are unreadable inside and readable outside; a keychain lookup fails |
| SBX.3 | the run phase cannot connect anywhere, the gateway's listener included; in the fetch phase a CONNECT to a non-registry name, and to a registry name resolving to loopback, is refused; a cold `npx` fetch through the proxy succeeds | the run phase cannot connect anywhere; the fetch phase reaches only the proxy; a cold fetch succeeds |
| SBX.4 | a descendant that calls `setsid` and double-forks: its host pid is gone after teardown | the same descendant is killed by the scan or listed by pid, and the response never says "gone" |
| SBX.5 | the 24.04 refusal text through a probe seam; CI runs `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0` before the sandbox job (ubuntu-latest is 24.04) | refusal when `sandbox-exec` is absent and when the canary read is not EPERM (seams) |
| SBX.6 | U6 route tests render only from `Isolation` | same |
| fetch stays trusted | an npm package whose `preinstall`, `postinstall` and `prepare` scripts write a marker file and open a socket, and which also ships a bin named `true`: after the fetch, no marker exists and the proxy saw only the registry; a wheel carrying a `.pth` file and a console script named `true` leaves no marker; a PyPI package with only an sdist is refused by the fetch, not built; `npx --registry=… pkg`, a `file:`/`git:`/URL spec and an unknown option are each refused before anything runs; a package with a transitive `git+https` dependency is refused by the fetch and leaves no marker | same, on macOS CI |
| host root gone (Linux) | after `pivot_root`, the old root's path does not exist inside, `/proc/self/cwd` is inside the new root, and no host file is reachable through `/proc/1/root`; `/proc/self/status` is readable (positive control); `/proc/self/fd` lists only 0, 1 and 2; writing past 256 MiB in `/tmp` or past 1 GiB in the home fails | n/a |
| helper refusals (Linux) | a descriptor inherited without close-on-exec makes the preview refuse; a helper started outside fresh namespaces refuses before any mount; from inside, reading `/proc/1/environ` and `/proc/1/fd` of the helper fails and `/proc/1/cmdline` holds no credential; the run phase finds the fetch's install in the home, the proxy socket path does not exist, and a process the fetch left behind is gone before the run starts (including one forked during the first sweep); the applied filter's first instructions equal the published preamble tuples for the host's architecture, value for value, and `keyctl` and `ptrace` called by their x32 numbers each end the child with `SIGSYS`; a refusal at the 2 s sweep deadline leaves the fetch's credential refused by the proxy; an interpreter under `/usr/local` starts (the bind-back mountpoint exists) while another `/usr/local` file stays unreadable; a canary under `/etc/ssl/private` is unreadable inside | a descriptor inherited without close-on-exec makes the preview refuse |
| macOS limits | n/a | writing past 1 GiB in the preview home fails; an escapee from one fetch cannot use the proxy during the next (its credential is refused); a fetch-phase connect to a second localhost port is refused; a canary under `/usr/local` outside the interpreter directory is unreadable; a canary in the gateway user's own home outside the interpreter directory is unreadable while an NVM `node` in that home starts; a child writes to `/dev/null` and reads `/dev/urandom`; a canary read through `/System/Volumes/Data/Users/<user>/` fails; a scan seam returning an unreadable environment refuses the run; open tunnels close when the credential expires; a profile path holding `"` or `\` is quoted and one holding a newline refuses; a fetch survivor the scan cannot kill refuses the run phase |
| tool versions | the probe records `npm --version` and `uv --version`; npm older than 9 or uv older than 0.4 refuses the fetch; CI runs the fetch fixtures against the pinned versions | same |
| positive controls | a cold fetch and an offline start succeed for an `npx` and a `uvx` server, with `node` from a Homebrew and an NVM prefix and Python from the system and Homebrew | same |
| Ubuntu AppArmor step | a CI job loads the documented profile with `apparmor_restrict_unprivileged_userns` still on, and the sandbox tests pass | n/a |

## References

- Cross-cutting constraint: "no unsafe" + thread-scoped kernel APIs:
  - <https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html>
  - <https://man7.org/linux/man-pages/man2/landlock_restrict_self.2.html>
  - <https://docs.kernel.org/userspace-api/landlock.html>
  - <https://man7.org/linux/man-pages/man2/unshare.2.html>
  - <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md>
- Landlock:
  - <https://man7.org/linux/man-pages/man7/landlock.7.html>
  - <https://docs.kernel.org/userspace-api/landlock.html>
  - <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md>
  - <https://man7.org/linux/man-pages/man2/landlock_restrict_self.2.html>
  - <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=999551>
  - <https://landlock.io/talks/2022-10-24_landlock-netdevconf.pdf>
  - <https://nono.sh/docs/cli/internals/landlock>
  - <https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json>
  - <https://docs.rs/landlock/latest/landlock/>
- Unprivileged user namespaces:
  - <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
  - <https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces>
  - <https://documentation.ubuntu.com/release-notes/24.04/>
  - <https://seclists.org/oss-sec/2025/q1/253>
  - <https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt>
  - <https://www.debian.org/releases/bullseye/amd64/release-notes/ch-information.en.html#linux-user-namespaces>
  - <https://lists.debian.org/debian-user/2025/10/msg00220.html>
  - <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/7.4_release_notes/new_features_kernel>
  - <https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2026-02-05/finding/V-230548>
  - <https://github.com/nix-community/nix-user-chroot/issues/91>
  - <https://docs.docker.com/engine/security/seccomp/>
- Reliable descendant cleanup without root:
  - <https://man7.org/linux/man-pages/man7/pid_namespaces.7.html>
  - <https://docs.kernel.org/admin-guide/cgroup-v2.html>
  - <https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html>
  - <https://man7.org/linux/man-pages/man2/pidfd_open.2.html>
  - <https://kernelnewbies.org/Linux_5.14>
  - <https://lwn.net/Articles/855049/>
  - <https://raw.githubusercontent.com/systemd/systemd/main/units/user%40.service.in>
  - <https://systemd.io/CGROUP_DELEGATION/>
- Network restricted to "registries only":
  - <https://github.com/anthropic-experimental/sandbox-runtime>
  - <https://docs.npmjs.com/cli/v11/using-npm/config>
  - <https://docs.astral.sh/uv/reference/environment/>
  - <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md>
- Existing unprivileged tools:
  - <https://github.com/containers/bubblewrap>
  - <https://bugs.launchpad.net/ubuntu/+source/bubblewrap/+bug/1709164>
  - <https://launchpad.net/ubuntu/+source/bubblewrap>
  - <https://learn.chatgpt.com/docs/sandboxing.md>
  - <https://github.com/netblue30/firejail>
  - <https://github.com/google/nsjail>
  - <https://github.com/anthropic-experimental/sandbox-runtime>
  - <https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md>
- sandbox-exec / Seatbelt (SBPL):
  - <https://keith.github.io/xcode-man-pages/sandbox-exec.1.html>
  - <https://github.com/anthropics/claude-code/issues/55849>
  - <https://news.ycombinator.com/item?id=47101200>
  - <https://learn.chatgpt.com/docs/sandboxing.md>
  - <https://github.com/openai/codex/blob/main/codex-rs/core/src/seatbelt_base_policy.sbpl>
  - <https://github.com/anthropic-experimental/sandbox-runtime>
  - <https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md>
  - <https://chromium.googlesource.com/chromium/src/+/master/sandbox/mac/seatbelt.cc>
  - <https://github.com/k3sm-io/runtimed/pull/149>
  - <https://github.com/alcimerio/ai-config-selector/pull/222>
  - <https://github.com/kainkalju/analysis/blob/main/macos-seatbelt.md>
  - <https://developer.apple.com/forums/thread/749725>
- Descendant cleanup on macOS without root:
  - <https://github.com/daintreehq/daintree/issues/12203>
  - <https://github.com/oven-sh/bun/pull/33965>
  - <https://github.com/Okerew/osxiec/releases>
  - <https://keith.github.io/xcode-man-pages/launchd.plist.5.html>
  - <https://github.com/chrismo/sheepdog/pull/205>
  - <https://github.com/jhlee0409/proc-janitor>
  - <https://github.com/openai/codex/blob/main/codex-rs/core/src/seatbelt_base_policy.sbpl>
  - <https://trailofbits-skills.mintlify.app/plugins/seatbelt-sandboxer>
- AppContainer + Job Objects:
  - <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>
  - <https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation>
  - <https://learn.chatgpt.com/docs/sandboxing.md>
  - <https://github.com/anthropic-experimental/sandbox-runtime>
- Points raised in review of this ADR:
  - <https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/README.md> (Seatbelt keeps access through open descriptors)
  - <https://man7.org/linux/man-pages/man2/seccomp.2.html> (x32 syscall numbers and the architecture check)
  - <https://github.com/rust-vmm/seccompiler/blob/main/src/backend/bpf.rs> and <https://github.com/rust-vmm/seccompiler/blob/main/src/lib.rs> (filter construction and `apply_filter`)
  - <https://github.com/torvalds/linux/blob/master/kernel/pid_namespace.c> (a namespace's first process waits for its descendants on exit)
  - <https://github.com/astral-sh/uv/security> (source builds run package code)
  - <https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/> (git dependencies and `.npmrc`)
  - <https://docs.python.org/3/library/subprocess.html#subprocess.DEVNULL> (why `/dev/null` must stay open)
