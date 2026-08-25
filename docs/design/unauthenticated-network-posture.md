# Design: protect credentials from callers that are not browsers

Status: draft for review, 2026-08-25. Follows the origin-gate change, which
closed the browser path and explicitly did not close these.

## SCOPE

FOR: an unauthenticated gateway must not hand its backend credentials to the
network, and must not leave them in a file other local users can read.

OUT, tracked separately: authentication on by default and credential
provisioning (MIK-7243), the destructive-confirmation gate (MIK-7246),
capabilities taking a caller-supplied URL (MIK-7247).

## Which adversaries

From the threat model in `origin-validation-anon-admin.md`. The origin gate
addresses adversary 2 only. This addresses the two it named and left open.

| # | Adversary | Today |
|---|-----------|-------|
| 1 | Remote network attacker | Reaches a non-loopback bind with no credential. The gateway warns and serves anyway |
| 4 | Another OS user on the machine | Reaches loopback, and can read a config file written at the process umask |

Adversary 3, a process running as the same user, stays out of reach at this
layer and is not claimed.

## Decision A — refuse to serve HTTP on a non-loopback bind with auth disabled

Exit non-zero before binding the listener. A warning is not a control: the
current one has been emitted on every such start and has not prevented one.

Placement is **before** `TcpListener::bind`, so a refused configuration never
opens a port at all. `log_startup_banner` is reached only from `Gateway::run`
(`src/gateway/server/mod.rs:1230`), so stdio mode is untouched — verified, not
assumed.

The message names both remedies: enable authentication, or bind loopback.

### The override

`server.allow_unauthenticated_network_bind: bool`, default false, deliberately
long. It is logged at WARN on every start when set, not once at startup, so it
cannot fade into the background.

Rejected: an environment variable. A config field travels with the deployment
that made the choice and is visible to anyone reading the config; an env var is
invisible in the artifact and easy to set globally by accident.

### What breaks

Any deployment binding non-loopback with authentication off. That is a real
break and needs a release note.

It is not, however, a deployment this project documents: `docs/DEPLOYMENT.md`
pairs `host: "0.0.0.0"` with `auth.enabled: true` in the one example that binds
wide, and states "never run without auth on a network-accessible port".
Checked, rather than assumed, before choosing refusal over a warning.

## Decision B — config files are created `0600`

The mode is set **at creation of the scratch file**, in
`create_scratch_exclusive` (`src/config_persistence.rs:115-120`), not applied
to the final file afterwards. The scratch file is a real file next to the
config for the duration of the write; creating it at the default umask and
tightening later leaves exactly the window this is meant to close. `rename`
preserves the mode, so the final file inherits it.

Windows has no equivalent and the call is a no-op there. Stated rather than
silently skipped.

### Existing files are reported, not changed

A config already written wide is reported at startup with the command to fix
it. Silently changing the permissions of a file the operator owns is a
surprise, and a surprise in a security change is how the next report starts.

## Why both, and why not more

A is the larger exposure: it needs no browser and no local access. B is small
and is a precondition for MIK-7243, which will persist a credential.

Neither addresses adversary 3. Nothing at this layer can.

## Unknowns, closed before this froze

| Question | How | Answer | What it changed |
|----------|-----|--------|-----------------|
| Does a refusal break stdio mode? | Read `server/mod.rs:1230` and its caller | No. Only `Gateway::run` reaches it | Allowed refusal instead of a warning-only compromise |
| Do our own docs recommend non-loopback with auth off? | `rg '0\.0\.0\.0' docs/ README.md` | No. The one wide-bind example enables auth | Removed the main argument against refusing |
| Does the final file inherit the scratch file's mode? | `rename(2)` preserves the inode | Yes | Let the fix sit at creation, closing the window |
