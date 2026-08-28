# Design: protect credentials from callers that are not browsers

Status: draft for review, 2026-08-25. Follows the origin-gate change, which
closed the browser path and explicitly did not close these.

## SCOPE

FOR: an unauthenticated gateway must not hand its backend credentials to the
network, and must not leave them in a file other local users can read.

OUT, tracked separately: authentication on by default and credential
provisioning (MIK-7243), the destructive-confirmation gate (MIK-7246),
capabilities taking a caller-supplied URL (MIK-7247).

This scope moved twice, both on 2026-08-28: to take in two more members of the
same class found by the final review (Decision D), and to close the two ways
this change's own gates refuse the caller they were built to admit
(Decision E).

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

Placement is **before every listener**, so a refused configuration never opens a
port at all. That means ahead of the optional WebSocket spawn as well as the
HTTP bind: the check first sat between the two, which spawned a WebSocket
listener on the same host for a configuration the next line refused. The
guarantee was written before that listener existed and was not re-checked when
it did — found in review, 2026-08-27. `log_startup_banner` is reached only from `Gateway::run`
(`src/gateway/server/mod.rs:1230`), so stdio mode is untouched — verified, not
assumed.

A once-at-startup check is sufficient only if neither half of the forbidden
state can be reached later. Both halves were checked:

- `server.host` is restart-required. A host or port edit sets `server_changed`
  and is reported as needing a restart (`src/config_reload/mod.rs:75`).
- `auth` is snapshotted into the router at construction
  (`src/gateway/router/mod.rs:134`), and `src/config_reload/` contains zero
  references to `auth_config` or `ResolvedAuthConfig`. A reload does not replace
  the running auth state.

A review raised the opposite as a critical finding, reasoning from the sibling
design's live `public_url` read. It does not hold here, and the citations above
are why. Recorded so the question is not re-opened from the same premise.

The message names both remedies: enable authentication, or bind loopback.

### The override

`server.allow_unauthenticated_network_bind: bool`, default false, deliberately
long. It is logged at WARN on **every** start while it remains set, rather than
only on the start that first set it, so it cannot fade into the background.

Its intended use is a deployment where authentication terminates in front of
the gateway: a sidecar, a service mesh, or a reverse proxy that authenticates
before forwarding. Naming the use makes the setting reviewable — someone
reading the config can ask whether that fronting layer actually exists. A
generic escape hatch invites setting it to silence a message.

Rejected: an environment variable. A config field travels with the deployment
that made the choice and is visible to anyone reading the config; an env var is
invisible in the artifact and easy to set globally by accident.

### What breaks

Any deployment binding non-loopback with authentication off. That is a real
break and needs a release note.

Three shapes were raised in review as possibly legitimate. Two are:

| Shape | Verdict |
|-------|---------|
| systemd socket activation, where no in-process bind happens so a pre-bind check never runs | Does not apply. Zero hits for `LISTEN_FDS` in `src/`; the `runtime.systemd` flag concerns a service manager being available to the runtime provider, not inherited sockets |
| An orchestrator probing the pod, which cannot reach a server that refuses to start | Applies, and the failure is loud rather than silent: the pod fails to start and the reason is in its logs. That is the intended behaviour of a refusal, not a defect in it |
| Authentication terminating at a sidecar, mesh or reverse proxy, so the gateway itself needs none | Applies, is legitimate, and is the strongest case against a blanket refusal |

The third is what the override is **for**, and the design says so below rather
than offering the override as a generic escape hatch.

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

### Existing files are reported, then tightened by the next write

A config already written wide is reported at startup with the command to fix
it. Detection alone changes nothing: silently re-permissioning a file the
operator owns is a surprise, and a surprise in a security change is how the
next report starts.

It does not stay wide forever, though, and an earlier draft of this section
implied it would. The write path replaces the file by rename from a scratch
file created `0600`, so **the next config write tightens it**. Both facts are
true and only the pair is honest: nothing changes on detection, and the first
write after that fixes it.

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

## Decision C — a reload that would open the tools is refused, not applied

Tracked as MIK-7254. Added 2026-08-27, after Decision A shipped. It closes the gap Decision A left
open and that `support.rs` recorded rather than guessed at. Revised once, after
a design review found the first draft's condition unsound; that round is kept
below because the unsound version is the obvious one to reach for.

### SCOPE

FOR: the forbidden state Decision A refuses at startup cannot be entered by a
reload of a running gateway.

OUT: making `auth` apply live; pre-write rejection in the admin UI; anything
about a local process running as the operator.

### What Decision A's sufficiency argument missed

That argument checked two halves — `server.host` is restart-required, and `auth`
is snapshotted at construction — and concluded a once-at-startup check suffices.
It was true when written. `network_bind_refusal` then grew a third input:
`server.public_url`, keyed on declared reachability because a tunnel or reverse
proxy is not where the bind address says the request arrives from.

`server.public_url` is the one `server` field deliberately excluded from
restart-required, because the origin gate re-reads it per request
(`config_reload/mod.rs`, `pending_restart_fields`). So adding a non-loopback
`public_url` to a RUNNING gateway whose tool paths are public reaches exactly
the state startup refuses, without passing through the check.

### The condition — the config that will be IN FORCE, not the file

The refusal is evaluated against an **effective** config: what the process is
running, with only the live-applied fields overlaid from the new file. Today
that overlay is `server.public_url` and nothing else.

    effective = running.clone()
    effective.server.public_url = new.server.public_url

The overlay is built **beside `network_bind_refusal`**, in the same module, and
is what `config_reload` calls — the raw refusal is not exported. Two functions
that must agree about which fields are live do not stay in agreement across a
module boundary, and the failure is silent: the overlay would simply judge the
wrong config. Co-locating them makes the next person to add a refusal input read
the overlay in the same screen.

The overlay list is not derived from `pending_restart_fields`, which returns
field names and offers no way to apply them. A test pins that allow-list to its
exact contents instead, so making a new field live fails a test whose message
sends the reader here. That is a tripwire rather than a derivation, and it is
named as one: it catches the addition, not a wrong overlay.

It runs **after the file is loaded and before `apply_patch`**. Before, and there
is no file to judge; after, and backends in the same file have already been
stopped and started, so "nothing was applied" would be false.

Every other input to `network_bind_refusal` therefore comes from `running`, and
that is the point rather than an accident:

| Input | Taken from | Why |
|---|---|---|
| `server.public_url` | the new file | the origin gate re-reads it per request |
| `auth.enabled`, `auth.public_paths` | `running` | the router snapshots `auth_config` at construction; `src/config_reload/` never touches it |
| `server.allow_unauthenticated_network_bind` | `running` | restart-only, like the rest of `server` |
| `server.host` | `running` | the listener is bound; a host edit is restart-required |

Testing the new file as a whole is the version this design first proposed, and
two reviewers independently killed it as CRITICAL. The hole: an operator who
adds a `public_url` **and** enables authentication in the same edit — which is
the remediation this project recommends everywhere — produces a file that reads
as safe. The refusal sees `auth.enabled = true`, declines to fire, the reload
publishes, the origin gate admits the new host on the next request, and the
running auth state is still the old permissive one. The masking works with
`allow_unauthenticated_network_bind` too, and with any restart-only input the
function grows later.

Overlaying the live fields onto the running config removes the class rather than
the instance: a field that is not applied cannot influence a decision about what
is in force, because it never enters the config being judged.

### Refuse only what this reload would cause

Keyed on `refusal(running).is_none() && refusal(effective).is_some()`.

An unconditional test of `effective` would refuse every reload for a gateway
already running in a refusable state. That is unreachable on the HTTP path,
since startup refused it. It is reachable off that path: `run_stdio` has no
listener, never runs the check, and wires no reload context today — verified,
not assumed. Keying on the transition stays correct if a stdio reload path is
ever added, and costs one comparison.

### The reload fails, and says why

The reload returns an **error**, not a successful outcome carrying a flag.

The first draft reported `restart_required: true` on the theory that the change
was unapplied rather than lost. Three reviewers rejected it for the same reason,
and they are right: `restart_required` is the signal that says *bounce me*, and
an operator or a supervisor that acts on it restarts a working gateway into
Decision A's startup refusal. A control against opening the tools must not have
a path to taking the gateway down instead.

An error is also what actually happened. `reload_outcome` already returns `Err`
for the one other case where a reload did not happen —
`SHUTDOWN_ABORTED_ERROR` — and this follows that shape rather than inventing a
second one:

- one shared constant as a stable **prefix**, matched through a single
  predicate, with the refusal's own text riding behind it. The file watcher is
  the only consumer that classifies today; the meta-tool and the admin API
  forward the message whole, so it reaches an operator either way. `SHUTDOWN_ABORTED_ERROR`
  is compared whole because it carries nothing dynamic; this one cannot be, and
  saying "the same shape" without saying which produces an arm that never
  matches;
- its own arm in the file-watcher match, so it is logged as a refusal and not
  as the broken-config-file alert that a parse failure raises.

A typed error variant would be better than a string literal four consumers must
agree on, and would let the admin API narrow its status. It is the same
next-major job `reload_outcome`'s own comment already records for
`Result<_, String>`, and doing it here would change that signature for every
caller outside the crate. Following the existing constant is the smaller change;
the typed version is a reason to do that job, not a reason to do it now.

The message says three things, because each is something the operator would
otherwise get wrong:

1. the whole patch was skipped, backends in the same file included, so nobody
   assumes a bundled backend registered;
2. the gateway keeps serving the configuration that was in force before this
   reload — not necessarily the one it started with, since an earlier reload may
   have applied backends;
3. what a **restart** does with this same file, which is not one answer. A file
   that also enables authentication is ACCEPTED by a restart, so that operator
   is told to restart rather than to revert. A file that only declares the name
   REFUSES at the next start, planned or not, so that operator is told to revert
   it or close the tool paths. Taken from `network_bind_refusal(wanted)` — the
   startup question, asked of the file — rather than assumed.

Point 3 was a single unconditional sentence in the first draft, saying the next
start would refuse. Two reviewers caught it: that is false for the file the
deployment guide tells an operator to write, so the refusal was contradicting
our own advice and telling them to undo the fix. Worded around what a restart
DOES rather than around what changed, because the two entry points differ — the
file watcher fires because the operator edited the file, the admin UI writes the
file itself before reloading — and the restart outcome is true on both.

It carries the `network_bind_refusal` text as well, which already names the
condition and the remedy.

### Why not just report it

Adding `public_url` to `pending_restart_fields` reports and does not refuse:
`live_config.set(new_config)` still runs, the origin gate re-reads the new host
on the next request, and the tools are open with an accurate warning next to
them. The refusal has to happen before the publish, which is also before
`apply_patch` and its side effects.

### The refusal asks about the tool surface, not about a list of exceptions

Two spellings of "are the tools public" were wrong in opposite directions, and
the final review found the second within a day of the first being fixed.

| spelling | what it got wrong |
|---|---|
| any entry that is not `/health` | refused a gateway listing `/metrics` — documented, legitimate, and granting nothing, since the scrape route is merged outside the auth layer |
| ...and is not empty | skipped the one entry that opens everything |

Both come from framing the question as a list of exceptions. Asked directly —
does any public prefix cover `/mcp`, using the same `starts_with` semantics
authentication itself uses — it answers both: `""`, `"/"` and `"/m"` all
prefix-match the tool route, while `/health` and `/metrics` do not. A
table-driven case pins both directions, because an over-refusal stops a
legitimate gateway starting and is not the safer error it looks like.

Scope, stated rather than missed: a public path over the ADMIN surface is a
different exposure with a different control — the anonymous identity holds no
admin — and this refusal is about a caller invoking every configured backend.

The rule went through three spellings, and the third is the one that asks the
question in the operator's terms rather than in the string's:

| spelling | wrong how |
|---|---|
| any entry that is not `/health` | refused a legitimate `/metrics` |
| ...and is not empty | skipped the entry that opens everything |
| any entry beginning `/mcp` | refused `/mcp-status`, `/mcpx`, `/mcp.json` — an operator's own endpoints, none of which axum routes to a tool |

The slash is the correction: a configured prefix opens the tools when it is a
prefix of `/mcp`, or when it begins `/mcp/` and so names a path SEGMENT. The
test derives its expected column from `real_path.starts_with(entry)` over the
real routes rather than asserting it by hand, because a hand-written column is
how two of those three spellings stayed green while being wrong.

### A blank public path was the most public path of all

Found by the final code review, and pre-dating this decision: `network_bind_refusal`
skipped empty `auth.public_paths` entries when deciding whether tools were
reachable without a credential. Public paths are matched by **prefix**
(`ResolvedAuthConfig::is_public_path`, `path.starts_with(p)`), so a blank entry
— a stray dash in a YAML list — is a prefix of every path and opens the whole
gateway. The single entry that opens everything was the single entry that did
not count, so such a config read as secured and served every backend.

Fixed at the shared root rather than on the reload path, because the refusal is
what both callers ask, and the startup half was the more exposed of the two: it
serves, where the reload half only publishes. Covered on both.

The reload case has to be staged in the RUNNING config to mean anything, and
mis-staging it is instructive: a blank entry in the FILE is harmless at reload
time, because `auth` is not applied and the request path keeps the closed paths
it started with. What makes it the live half of the forbidden state is being
already in force.

### Telling an operator to revert a file a restart would accept

The refusal first said, always, that the configuration on disk would refuse at
the next start. That is true for a file declaring only a `public_url`, and false
for one that also enables authentication — which a reload cannot apply, and a
restart applies correctly. The deployment guide tells that operator to write
exactly that file and restart, so the refusal was contradicting our own advice
and telling them to undo the fix.

The refusal therefore reports two facts: why this reload cannot be applied, and
whether a restart on the same file would refuse as well. The second is
`network_bind_refusal(wanted)` — the startup question, asked of the file — and
the message ends differently on each answer.

### An exemption is only as good as the thing it recognises

The gate list grew to include `agent_auth`, and the first version counted
`enabled`. Review caught what that admits: `DecodingKey::from_secret(b"")` is a
valid key anyone can sign for, so an agent whose `hs256_secret` is an empty
string authenticates the world. A gateway in that state would have been exempted
from the refusal and served every backend on a network address — reached
through the exemption meant to recognise security.

The gate now requires key material somebody could fail to produce: an RSA public
key, an `env:` reference, or an HS256 secret of at least 32 bytes. Empty, short,
and no-agents-at-all are each pinned as NOT gating, because that is the direction
that costs something.

The forgeable agent itself is a separate defect and is filed as **MIK-7258**:
nothing rejects an empty secret at the auth layer either. This decision only
stops the posture check from mistaking it for protection.

**The general lesson, recorded because it will recur**: every exemption added
here asks "is something else already demanding a credential?", and each one is
an opportunity to accept a mechanism that is enabled but toothless. Adding a
gate means checking that it can actually turn somebody away, not that its flag
is on.

### Stated limits of the test set

Two coverage gaps are known and left, rather than closed badly.

The watcher case asserts the CLASSIFICATION of a real refusal string, not the
`ConfigWatcher` match arms themselves. It catches the realistic mistake — an arm
written `==` against a prefix, which never matches — and does not catch an arm
deleted or ordered after the generic one. Running the arms means capturing log
output, and no such harness exists here; a shared subscriber across parallel
tests is a flake source. Revisit if a log-capture harness lands for other
reasons.

The live-field tripwire mutates `public_url`, `role_mapping` and `auth`, so it
fails when one of those changes status. It cannot fail for a field in a section
nothing has made live yet. `every_tracked_section_is_covered` already holds the
exhaustive half — every section reaches the classifier — so what is uncovered is
narrow: a field moved to live-applied in a section this case does not touch.

### What a refusal does NOT undo

`Config::load` applies the config's `env_files` to the process environment
before it returns, so by the time this check runs, that much has happened. It is
true of every failed reload — a parse error, a validation error, the shutdown
abort — and pre-dates this decision; found in review of it, filed as **MIK-7256**.

It is not inert, either: `capability::executor` resolves an `env:` credential
with `std::env::var` inside `dispatch_protocol`, per call, so a later capability
call can use a value the refused file supplied.

The fail-fast ran, and the answer is that undoing it is not expressible here.
Three consumers read those variables — `expand_string` (`src/config/mod.rs:331`)
and figment's `Env` provider (`:286`) at load time, and `capability::executor`
per call — so an undo would have to unset or restore process variables, and
`#![deny(unsafe_code)]` (`src/lib.rs:25`) forbids the `set_var`/`remove_var`
that edition 2024 made unsafe. `dotenvy` can set them because it is a
dependency; we cannot unset them. The alternative — resolving every consumer
from a candidate map instead of the process environment — is a four-consumer
refactor with its own design and review, not a fix to this decision.

**MIK-7256 is therefore closed as a known residual, not repaired.** The narrower
patch that suggested itself, refusing when the `env_files` LIST changes, was
rejected: it misses a same-path file whose CONTENTS changed, which is the
ordinary case. Nothing in the refusal message claims otherwise today, which is
what keeps the residual honest rather than hidden.

So the message states two bounded facts — no backend was started or stopped, no
configuration was published — and offers **no summary of what remains in
force**. That summary is the thing that kept being wrong: three review rounds
each narrowed it ("nothing was applied" → "still serving what it started with" →
"still serving what was in force") and each left it false. A claim that survives
three patches is one to delete rather than patch again, and a test now asserts
its ABSENCE so a later edit cannot reintroduce the reassurance.

The prefix went the same way, one round later. It read "config reload refused,
the running gateway is unchanged:" — the identical claim, three words shorter,
sitting in the one part of the message the test was not reading, because that
test listed the phrasings the body had just been corrected of. It is now a bare
label, and the test asserts the PROPERTY over every phrasing this claim has ever
taken rather than the two most recent.

That is the lesson worth keeping: a test written against the last wording
catches the last mistake. The claim had four spellings across four rounds, and
the one that survived was the one nobody thought to read.

The operator loses nothing they can act on. Overclaiming in a security message
is how the next report starts.

### Accepted residual

The admin UI writes the file before it reloads, so a config that would refuse at
startup can be persisted and then reported as refused. The write is the
operator's stated intent and the error tells them immediately, including point 3
above. Rejecting the write pre-emptively is a separate change and is out of
scope here.

A restart-only edit could still invite a bounce into the startup refusal by a
different route: disabling `auth` in the file is reported as restart-required
and applied to disk, and the restart then refuses to serve. The running gateway
never enters the forbidden state, so the risk is availability rather than
exposure — but the advice was still "restart", and following it took the
gateway away.

**MIK-7255 is fixed, in the place the analysis named**: `with_pending_restart`
asks the STARTUP check about the published config whenever it reports pending
fields, and appends the consequence to the outcome. The startup check is the
right question there precisely because the file is already published — what a
restart boots is `live.get()`, not the reload overlay. `network_bind_refusal`
stays private; it is re-exported as `next_start_refusal` so the call site names
the question it asks, which is what the module's one-way-to-ask rule was
protecting. Decision C itself is **MIK-7254**.

`reload_outcome`'s error reaches the admin API as a 500. It is a policy refusal
rather than an internal fault, so the status is generous; the text is what the
operator reads, and narrowing the status means giving `Err(String)` a shape it
does not have. Stated rather than fixed.

### Test plan

| AC | Case | Level | Type |
|----|------|-------|------|
| A reload adding a published `public_url` over public tool paths is refused | `Err` whose text is the shared constant, and which carries the refusal remedy and the next-start warning | unit | security |
| Enabling `auth` in the same edit does not mask it | same file, plus `auth.enabled = true` and tightened `public_paths` — still refused, because the running auth is what is in force | unit | security |
| Setting the override in the same edit does not mask it either | same file, plus `allow_unauthenticated_network_bind = true` — still refused | unit | security |
| Refused means nothing was applied | a backend added in the same file is absent from the registry, and the live snapshot still has no `public_url` | unit | security |
| A reload that does not enter the state is unaffected | a RUNNING config whose tool paths are already not public, plus the same new `public_url` — applies normally | unit | regression |
| A restart-only edit whose restart would refuse says so | `with_pending_restart` on a `0.0.0.0` gateway losing `auth` carries the warning; the same edit on loopback does not | unit | security |
| The refusal is logged as a refusal | the file watcher takes its own arm, not the broken-config-file arm a parse failure raises | unit | regression |
| Every refusal input comes from the side it should | `auth`, the override and `host` read from `running`; `public_url` from the file | unit | security |
| `auth` is not applied by a reload | a reload toggling `auth.enabled` in a file that does not refuse leaves request-time authentication governed by the startup snapshot | integration | security |
| A published-but-not-running value cannot mask it either | two reloads: the first publishes `auth.enabled` with no `public_url`, the second adds one — still refused | unit | security |
| The live-field allow-list has not grown | `pending_restart_fields`' allow-list is exactly `server.public_url` and `control_plane.role_mapping` | unit | regression |

The second and third cases are the ones that fail against the first draft; they
are the design review's finding turned into a test. The first case asserts the
message content and not merely the error's identity, so reducing the message to
a bare label fails it.

The regression case takes its non-public tool paths from the RUNNING config
rather than the file, because taking them from the file is the very mistake the
overlay exists to prevent — a test written the other way would pass by treating
a restart-only auth edit as live.

The two-reload row is what separates `running()` from `get()`. Every other case
starts on a fresh `LiveConfig`, where the two are equal, so an implementation
that overlays onto the **published** snapshot passes all of them — and reopens
the masking hole one reload later, in the exact sequence this project's own
advice produces: enable authentication, be told it is restart-required, add the
public URL. That second reload would read the published `auth.enabled = true`,
decline to refuse, and open the origin gate over a request path still running
the old auth.

The `auth`-is-not-live row is the other load-bearing one, and it is not obvious. The overlay is only
safe while a reload does not apply `auth`; that is verified at source today and
nothing enforces it. If it ever changes, the inverse hole opens — disabling auth
and setting a `public_url` in one edit would slip through — and every other row
here stays green, because they all read `auth` from `running` and would keep
agreeing with themselves. This row is what fails on that day.

## Decision D — an agent may hold one key type, and a token file is replaced, never written into

Receipt update, 2026-08-28. The scope declared at the top of this document moves
to include two credential paths that the final review found, and that belong to
the class this change is about: a secret an unauthenticated caller can reach, or
a secret left where another local user can read it. Both were pre-existing code.
They are fixed here rather than filed, because filing them would ship a release
whose stated purpose is this class while leaving two members of it open.

### An agent configured with both key types is refused at startup

`validate_agent_token` reads the algorithm from the **token header**, which the
caller controls, and then picks the verifying key from that algorithm. An agent
carrying both `hs256_secret` and `rs256_public_key` therefore verifies against
whichever the caller names — the deployment is only as strong as its weaker key,
and a shared HMAC secret sitting beside an RSA public key is exactly the pairing
an operator adds while migrating. `AgentDefinition` already documented "exactly
one of" as a rule. Nothing enforced it.

Validation now refuses the configuration and names both keys. This eliminates
the finding rather than patching it: with the pairing unrepresentable, no
algorithm-confusion path exists to defend. A both-keys deployment that starts
today will refuse to start after upgrading, and the error says which agent and
what to remove — the intended outcome, since such a deployment is already
verifying tokens against its weaker key.

### The OAuth token file is created owner-only, not chmodded afterwards

`save` wrote the token with `fs::write` and then narrowed the mode. Between those
two calls the file holds a backend refresh token at whatever the process umask
allowed, and a pre-existing world-readable file is written *into*, keeping its
mode and its inode. The same module already had the safe shape for the far less
sensitive client-id file: create exclusively at `0600`, write, then link into
place. Token writes now use those same helpers, renamed to say "secret" rather
than "client", and land with `fs::rename` because a refresh legitimately
replaces the previous token, where a client id must not.

The non-Unix arm now emits the inherited-ACL warning the config path already
emits, so a Windows operator hears about the token file for the same reason and
in the same words as the config file.

### The mTLS private key is replaced, never written into

The generated mTLS key had the same shape as the token write and the same
defect. `OpenOptions::mode` sets a mode on a file it *creates*; over a key file
an earlier run already left behind, `create(true).truncate(true)` reuses that
file, mode and all, and the `set_permissions` that followed only narrowed it
after the key was already on disk. On a shared host the window is enough to read
a CA key and mint client certificates the gateway trusts.

Same repair, for the same reason: create a fresh `0600` scratch file next to the
destination, write and `fsync` it, then `rename` it over the old key. The key
exists only at owner-only mode, and the rename is atomic for anything reading
the path. The non-Unix arm keeps the inherited-ACL warning it already had.

This is the third member of the class, found by the final review after the first
two were fixed. Searching for the construct rather than the report is what
turned one finding into three: `OpenOptions` with `create` and a `mode` is the
grep, not "token" or "config".

### Test plan (Decision D)

| AC | Case | Level | Type |
|----|------|-------|------|
| An agent cannot hold both key types | validation returns `Err` naming the agent and both keys | unit | security |
| A token never lands in a pre-existing readable file | pre-create the path `0644`, save, assert the inode changed and the mode is `0600` | unit | security |
| A private key never lands in a pre-existing readable file | pre-create the key path `0644`, write, assert the inode changed and the mode is `0600` | unit | security |
| The Windows warning covers tokens | the `cfg(not(unix))` arm compiles and calls the shared warning helper | compile | security |

The inode assertion is the load-bearing one. A test asserting only the final
mode passes against the old code, which did reach `0600` — one syscall late, and
without ever detaching from the file it inherited.

## Decision E — a gate that refuses the legitimate caller is a defect, not a posture

Both gates this work added deny by default, which is right, and both had a
configuration in which nothing could ever satisfy them. Neither is reachable by
an adversary; both make the product unusable for an operator who did everything
the documentation says. They are listed here because a closed gate looks
correct from the inside — the refusal is logged, the tests pass, and only the
person locked out knows.

### An install administered by an API key could not open its own dashboard

The bootstrap link is printed at startup and redeemed once. Redemption required
`auth.bearer_token`, so an install whose only admin credential is an admin API
key was refused every time, with a message that did not say why.

The credential is never exchanged in this exchange — the link is an opaque
single-use handle, and the session it issues carries admin rights. So the
question the gate must ask is whether the install has an admin credential at
all, not which kind. An admin API key answers yes. A restricted key does not,
and is still refused: the session it would issue is more powerful than the key.

Nothing configured admits nobody, and now says so, naming `auth.bearer_token`,
an admin API key, and `mcp-gateway init`.

### The shipped deployments declared no name, so the Host gate refused every client

On a non-loopback bind the Host gate admits a numeric address unconditionally
and a NAME only when `server.public_url` declares it. Every shipped deployment
binds `0.0.0.0` because a container or pod must, and none of them declared a
name.

The failure is quiet in the worst way: kubelet probes an address, so readiness
stays green, while every client dialling the Service by name gets 403. The
single-node compose file has the same shape — the client on the host and the
container's own healthcheck both dial `localhost`.

Each shipped config now declares the one name its callers use, and the chart
derives it from the release's own Service and namespace rather than asking the
operator to repeat what the chart already knows.

### Test plan (Decision E)

| AC | Case | Level | Type |
|----|------|-------|------|
| An admin API key opens the dashboard | redeem a bootstrap link on an install with no bearer token and one admin key, assert `303` | unit | functional |
| A restricted API key does not | same install, key without admin, assert `401` | unit | security |
| An install with no admin credential is told so | redemption returns `401` naming the settings that would fix it | unit | functional |
| A 0.0.0.0 Kubernetes config declares its name | parse the shipped ConfigMap, require a `.svc.cluster.local` `public_url`; require the chart template to render one | unit | functional |
| The compose service declares its name | parse the shipped compose file, require `MCP_GATEWAY_SERVER__PUBLIC_URL` to name the published port | unit | functional |

The restricted-key row is the one that keeps the repair honest. Widening the
gate to "any API key is configured" passes every other row here.
