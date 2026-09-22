<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Live identity-grant reload — design

Design for a production trigger that re-reads the local identity-grant file into a running
gateway, so `mcp-gateway identity revoke` takes effect without a restart. Today the CLI
edits a file and nothing signals the process.

**Read the scope claim before the design.** This closes revocation on the **authorization**
path and strands pre-revocation **response**-cache entries. It does **not** evict the
slot-keyed **catalogue** cache. A reviewer who closes `MIK-7334.CATALOGUE.1` on this
document alone would be closing it wrong — see §0, which exists because the briefing for
this work asserted the opposite and the source does not support it.

Evidence markers: **V** verified at the cited line, **I** inferred, **A** assumption.

**Branch caveat.** Every line number below was verified on `docs/pkg1-runtime-evidence`
(worktree `/Users/mikko/github/.worktrees/relcheck`, `git branch --show-current`). The
briefing for this work named `docs/ranking-1-release-line`. If those differ, the citations
need re-checking on the release line before this design is graded against it — the reasoning
is branch-independent, the line numbers are not.

---

## 0. The premise that does not hold: the policy epoch is not the catalogue's invalidation

The briefing stated that `CATALOGUE.1`'s revocation half needs no new eviction primitive,
because `set_identity_grants` advances the policy epoch and *that is* the invalidation — so
the only missing piece is a production caller. The first half is true of one cache and
false of the one the criterion names.

**V** `policy_epoch` keys the **response** cache and nothing else. It reaches the key
through `KeyContext.policy_epoch` (`src/cache.rs:108`), whose `digest()` feeds
`response_cache_key_for`. The test that proves the discipline says so in its own header:
*"the epoch that keys the response cache"* (`src/gateway/meta_mcp/policy_epoch_tests.rs:1-6`),
and its honest-limit note concedes the full `invoke` path is not driven (`:13-16`).

**V (absence)** `rg -n "policy_epoch" src/backend/ src/gateway/meta_mcp/discovery_fetch.rs`
returns **zero matches** (exit 1). The catalogue cache is `tools_cache` on `PooledEntry`
(`src/backend/pool.rs:90`), reached per slot through `tools_slot(binding)`
(`src/backend/metadata.rs:112,128`). No epoch is in that path.

**V** The source states the intended mechanism, and states that it is deliberately *not*
this one — `src/backend/metadata.rs:56-59`:

> NOT the revocation hook, and deliberately not reachable as one: it discards an empty list
> only, so routing revocation through it would be a silent no-op on every populated cache.
> Revocation evicts the identity's slot, which drops its transport and its caches together.

**V, and nothing does it today.** The only per-user slot eviction that exists is
`evict_idle_per_user_entries` (`src/backend/pool.rs:326`), which filters on `idle_ttl` and
`in_flight`, skips `PoolKey::Shared`, and takes **no identity or grant input at all**. So
identity-keyed eviction is not merely un-triggered — it is unimplemented.

**I** So catalogue revocation is **slot eviction keyed on `PoolKey::PerUser { binding }`**,
and the `CATALOGUE.1` re-grade note records why that does not yet hold on the shipped
default: PATH A's `identity_propagation::cache_binding(subject_key, audience)` takes no
grant input, so a grant rotation does not move the binding.

**Consequence for ticket scope.** MIK-7530 is not dead; it is **re-scoped**. It is not
"a cache-eviction primitive for the response cache" (that exists, and is the epoch). It is
slot eviction on the catalogue path, which is the in-flight `MIK-7334` catalogue design's
own work (`docs/internal/design/2026-09-22-catalogue-1-design-review-round2.md`, §3.1 —
co-locate the metadata caches with the pool slot). **This design supplies the trigger that
work needs; it is not a substitute for it.**

| Cache | Keyed on | Revocation reaches it? |
|---|---|---|
| Response cache (`src/cache.rs:108`) | `policy_epoch` | **Yes**, once a reload calls `set_identity_grants` — this design |
| Authorization decision (`invoke.rs:2663`) | read live, per request | **Yes**, this design; no cache to evict |
| Catalogue `tools_cache` (`pool.rs:90`) | `PoolKey::PerUser { binding }` | **No** — needs slot eviction, MIK-7334 |

---

## 1. What exists today

**V** The store is plain data: `pub struct LocalIdentityGrantStore { grants: BTreeMap<String, IdentityGrant> }`
(`src/identity_grants.rs:503-505`). **V (absence)**
`rg "Mutex|RwLock|RefCell|Cell<|AtomicBool" src/identity_grants.rs` → zero matches (exit 1).
No interior mutability.

**V** `MetaMcp` holds it as `pub(super) identity_grants: RwLock<LocalIdentityGrantStore>`
(`src/gateway/meta_mcp/mod.rs:569`) beside `policy_epoch: Arc<AtomicU64>` (`:579`).

**V The live-replacement mechanism already exists and is race-safe.**
`pub fn set_identity_grants(&self, grants: LocalIdentityGrantStore)`
(`src/gateway/meta_mcp/mod.rs:1300`) takes `&self`, takes the write lock, publishes, then
bumps the epoch with `Ordering::Release` **while the lock is still held**. Its doc comment
names the discipline: *"Bump-then-write is the 4.g race on the writer side."*
`policy_epoch_tests.rs:51` drives the production key builder against the production mutation
site and proves a pre-change entry cannot be served after it.

**V The only production caller is boot.** `src/gateway/server/mod.rs:1234` calls
`load_configured_identity_grants` inside `build_meta_mcp`, then publishes at `:1237-1239`.
`rg "load_configured_identity_grants"` shows one other non-test hit: the definition at `:163`.

**V The `Arc::get_mut` at the boot site is incidental, not a structural bar.**
`Arc::get_mut(&mut meta_mcp).expect("no other Arc references at this point")` (`:1237-1238`)
reflects the boot path holding the only reference. `set_identity_grants` takes `&self`, so
live replacement needs no `get_mut` at all.

**V (absence)** `rg "identity_grant|IdentityGrant" src/config_reload/` → zero matches
(exit 1). An applied config reload does not reload grants today.

**V** Per-request liveness is `is_active_at` (`src/identity_grants.rs:217-218`):
`self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)`, reached via `covers`
(`:230`) and `evaluate` (`invoke.rs:2663`). **Expiry therefore already works live** — time
advances against in-memory data. **Revocation does not** — it only edits the file.

**V** The CLI writes and prints: `revoke_local_grant` (`src/commands/identity.rs:179`) reads
the file, sets `revoked_at`, writes, and `print_grant_result("revoked", ...)` (`:90`).

**V, and load-bearing for §D3** The write is **not atomic**: `tokio::fs::write(path, content)`
(`src/commands/identity.rs:234`). Every `identity grant add` / `revoke` opens a window in
which the file on disk is truncated or partial.

### 1.1 What `config_reload` already provides

This matters because it is the reuse candidate, and it is richer than the briefing assumed.

- **V** `LiveConfig` already shares the gateway's epoch: `policy_epoch: Option<Arc<AtomicU64>>`
  (`src/config_reload/mod.rs:255`), wired at `src/gateway/server/mod.rs:1570-1571`, and
  `LiveConfig::set` bumps it on **every** published reload (`config_reload/mod.rs:312-320`).
- **V** `ReloadContext` (`:1423-1441`) holds `config_path`, `live_config`, `registry`,
  `failsafe_config`, `cache_ttl`, `env`. It holds **no** `MetaMcp` reference.
- **V** `MetaMcp` holds `reload_context: RwLock<Option<Arc<ReloadContext>>>`
  (`meta_mcp/mod.rs:387`), set at `server/mod.rs:1597`. The dependency runs MetaMcp → ReloadContext.
- **V** Triggers already exist: the `gateway_reload_config` meta-tool
  (`src/gateway/meta_mcp_tool_defs.rs:504-507`, served only when a reload context exists,
  `:590`), the admin UI reload, and a debounced `notify` file watcher on `config.yaml` plus
  env files (`ConfigWatcher::start`, `config_reload/mod.rs:1064`; started at
  `server/mod.rs:1996-2017`).
- **V** Its failure posture is **refuse and mutate nothing**: `reload_outcome_locked`
  (`:1645`) returns `Err` with `POSTURE_REFUSED_PREFIX` and the words *"No backend was
  started or stopped, and no configuration was published"* on a message-signing restart
  field, an account-binding change, or a bind-posture refusal; and `Err(SHUTDOWN_ABORTED_ERROR)`
  when `apply_patch` reports partial application. Publication happens only on the success path.
- **V** It serializes: `reload_outcome_locked` is reached through `lock_reload_within`
  (`:1634`), and `apply_patch`'s comment (`:902-910`) explains why — two reloads that each
  compute a patch against the live config can register two instances under one name.

**V** The grants file is **not** in the watch set. Its path comes from
`config.security.identity_grants.path` (`src/config/features/security.rs:400-404`), a
different file from `config.yaml`; `create_notify_watcher` (`config_reload/mod.rs:1112`)
registers only the config path and env-file paths.

**V** `fail_on_error` (`src/config/features/security.rs:405-407`) — *"Fail startup if the
configured file cannot be read or parsed. Default: `true` so operators do not silently run
with an empty grant store."* Cited again in §D3; its stated worry is exactly the failure
mode a fail-closed reload would manufacture.

---

## 2. The four triggers

| | Cost | Attack surface | Failure mode | Platforms |
|---|---|---|---|---|
| **(a) reuse `config_reload`** | One sink field, one call, one outcome line. Watcher, debounce, lock, refusal vocabulary and admin gating already exist. | **None new.** `gateway_reload_config` is already admin-gated (`ADMIN_META_TOOLS`, `router/authorization.rs:73-77`); no new route, port, signal or file handle. | Inherits the module's refuse-and-publish-nothing posture. Risk is *coupling* — §D1. | All. Pure Rust + `notify`, already shipped. |
| **(b) SIGHUP** | New signal task, new shutdown interaction. | Low, but any process that can signal the gateway can force a re-read. | Signals are edge-triggered and coalesce; two revokes during one handler run read the file once — fine here (the file is the whole state), but it has no outcome channel: the operator gets a log line, not a result. | **Unix only.** **V** the repo handles exactly one signal today, `SignalKind::terminate()` at `src/gateway/server/support.rs:330`; **V (absence)** `rg "SIGHUP\|signal_hook\|unix::signal\|SignalKind" src/` finds no other. Windows is not a shipped target, but a signal-only design must say so, and it cannot be triggered from inside a container by an MCP client at all. |
| **(c) filesystem watcher on the grants file** | Moderate. Needs directory-watch treatment (editors and `tokio::fs::write` replace rather than mutate) plus debounce. | Low. | **Torn reads.** **V** `tokio::fs::write` (`commands/identity.rs:234`) is truncate-then-write, so the watcher fires reliably *inside* the partial-file window. Every `grant add` becomes a reload attempt against a corrupt file. | All. |
| **(d) admin/control-plane route** | New route, new request shape, new RBAC wiring — **or none at all, because it exists**. | **V** `mutate_grant` (`src/gateway/ui/control_plane.rs:175`) already does admin-gated, mandatory-audit grant mutation via `apply_mutation` + `commit_grant_audited`. But it writes `ControlPlaneGrant` rows to the **control-plane store**, a different object from `LocalIdentityGrantStore`; **V** the identity-grant surface there is read-only projection (`control_plane_grant_from_identity`, `:685`). | Wiring the two grant worlds together is a merge-semantics design, not a reload design. | All. |

### D1 — Trigger: reuse `config_reload`, on a **separate grant path** under the same lock

**Decision: (a), with grants on their own reload step rather than folded into the config patch.**

Three reasons, from the source.

**1. Every part except the read already exists, and (c) and (d) each buy one part at the
price of a new failure class.** (b) is Unix-only and has no outcome channel. (c) buys
zero-touch liveness and pays with a torn-read race that (a) does not have, because (a) is
triggered by an operator act rather than by the write itself. (d) is not a reload trigger;
it is a second grant store.

**2. Grants are not part of `Config`, so they must not be sequenced behind the config patch.**
This is the real design tension and the reason for "separate path". `reload_outcome_locked`
returns `Err` **before** any publication on a `security.message_signing` restart field
(`:1652-1664`), an account-binding change (`:1758-1765`), a bind-posture refusal, or a
partially applied patch. **I** If grants published only on that success path, an unrelated
config edit — an operator mid-way through enabling message signing — would hold a
**revocation** hostage indefinitely. A revocation's validity has nothing to do with config
hygiene. So: `ReloadContext::reload_identity_grants()` is its own function with its own
outcome, called by the same triggers, and neither step's refusal refuses the other.

**3. It must still take the module's lock.** **V** `apply_patch`'s comment (`:902-910`)
documents the shape of the race a lock-free reload path inherits: two triggers interleave
read-file and publish, the older file wins, and a revocation is **silently lost** — the exact
bug this design exists to kill. `reload_identity_grants` therefore runs inside
`lock_reload_within` (`:1634`) — which wraps `BackendRegistry::lock_reload`
(`src/backend/registry.rs:197`) — the same serializing lock, so a grants reload and a config
reload cannot interleave either.

**The two strongest arguments against this choice**, recorded because a reviewer should be
able to overturn it:

- **It is not zero-touch.** A revoke is live only when someone triggers a reload. An
  operator who revokes and walks away has not revoked on the running process. (c) would close
  that; this does not. The mitigation is honesty, not mechanism — §D4 — and the second slice
  in §5 is exactly (c).
- **It puts a security-critical publish behind a lock shared with backend restarts.**
  `apply_patch` awaits `backend.stop()` per modified backend (`:947,958`). A config reload
  stopping a slow stdio backend holds the lock, and a concurrent revocation waits behind it.
  Bounded, not unbounded — but a revocation waiting on a child-process shutdown is a real
  property, and the honest alternative (a second lock for grants only) trades it for the
  interleaving in reason 3. I take the wait over the lost write.

### D2 — Sink shape: share the store behind an `Arc`, do not hold a `Weak<MetaMcp>`

**Decision: `MetaMcp.identity_grants` becomes `Arc<RwLock<LocalIdentityGrantStore>>`;
`ReloadContext` holds a clone of that `Arc` and of `policy_epoch`.**

`ReloadContext` must reach the store, and `MetaMcp` already holds `Arc<ReloadContext>`
(`meta_mcp/mod.rs:387`), so a strong back-reference is a cycle. The two candidates:

| | Silent-failure mode |
|---|---|
| `Weak<MetaMcp>` | **Upgrade fails → no-op → revocation silently lost.** That is the defect class this design exists to remove, reintroduced at the sink. |
| `Arc<RwLock<LocalIdentityGrantStore>>` + `Arc<AtomicU64>` | None. The publisher cannot fail to find its target. |

**V, verified cheap — and counted, because this is where a reviewer can cheapest falsify the
MVP sizing in §4.** `rg -n "identity_grants" src/gateway/meta_mcp/mod.rs` plus a
field-position sweep `rg -n "identity_grants\s*:" src/` gives the complete set:

| Site | Change |
|---|---|
| `invoke.rs:2663` — `self.identity_grants.read().evaluate(&request)` | **none**; `Arc<RwLock<T>>` derefs |
| `mod.rs:1314` — `self.identity_grants.read().values()` | **none**; same |
| `mod.rs:672` — `identity_grants: RwLock::new(LocalIdentityGrantStore::new())` in `new()` | wrap: `Arc::new(RwLock::new(…))` |
| `mod.rs:864` — `self.identity_grants = RwLock::new(grants)` in `with_identity_grants` (`:863`) | wrap: same |
| `mod.rs:1300` — `set_identity_grants` | becomes a thin call into the shared publisher |

So **two** readers compile unchanged and **two** construction sites gain an `Arc::new` — not
one, as a first pass suggested. A struct-literal initializer does **not** coerce, which is why
the field-position sweep was run separately from the `.read()` search.

**V** `with_identity_grants` (`:863`) is a **consuming** builder taking `mut self`, so it
predates any shared reader and needs no epoch bump or ordering discipline. It is named here
only so nobody later "fixes" it into the shared publisher and bumps an epoch nothing is
reading yet.

**One publisher, one ordering discipline.** The write-then-bump-under-the-lock sequence and
its doc comment stay in a single function that both `MetaMcp::set_identity_grants` and the
reload path call. Duplicating those four lines at a second site is how the `Release`
ordering gets dropped in a later edit.

**A** This also makes the second slice cheap: `ConfigWatcher::start` has no `MetaMcp` at all
(`config_reload/mod.rs:1064-1071`), and two `Arc`s pass to it without touching its signature
shape.

### D3 — Corrupt or unreadable file: **fail open** (keep the live store), refuse the reload, report it loudly

This is the decision the briefing correctly called the most important one, and the one where
both defaults are a hole. The ruling splits three cases, because they are not the same event.

| Case | Ruling | Why |
|---|---|---|
| **Corrupt** — unparseable, or wrong `schema_version` | Keep the live store. Return `Err`. | Below. |
| **Absent / unreadable** — deleted, unmounted, permissions | Keep the live store. Return `Err`. | Below. |
| **Valid and empty** — `schema_version` present, `grants: []` | **Apply it.** Store becomes empty. | This is the escape hatch, and it is the supported way to revoke everything. |

That third row is what stops fail-open from being a hole. "Revoke everything" is expressible,
it parses, and it applies — so fail-open never means "there is no way to drop all grants".

**Five reasons for fail-open on the first two rows.**

**1. Fail-closed is an outage caused by the safe-looking choice, and it is high-probability,
not theoretical.** **V** `tokio::fs::write` (`commands/identity.rs:234`) truncates before it
writes. Every `identity grant add` and every `identity grant revoke` opens a window where the
file parses as garbage. **I** Under fail-closed, a reload landing in that window drops **every**
grant on the gateway — so an operator *adding* a grant takes down every personal capability.
The failure is triggered by the routine safe operation, which is the worst possible trigger.

**2. The file is the whole store, so a parse error cannot be read as a revocation.** A
corrupt file does not say "revoke grant X"; it says "I cannot tell you anything". **I** Treating
"I cannot tell you anything" as "revoke everything" turns a one-grant edit — or a bad disk —
into an all-grant revocation. Fail-closed here is not a conservative reading of the operator's
intent; it is a fabricated one.

**3. Fail-closed for grants means *denied*, not *granted*, so this is an availability call,
not an authorization one.** **V** The field doc is explicit (`meta_mcp/mod.rs:566-568`):
*"Empty by default. Public and shared tools still evaluate as allowed, but capabilities marked
`personal` fail closed without matching caller, owner, and live grant evidence."* So dropping
the store denies access. Nobody gains anything by a fail-open reload refusal; the cost is
bounded to "the revocation has not landed yet", which is **the status quo before the reload**.
Fail-open cannot be worse than not having built this.

**4. The codebase already ruled this way, in the module being reused.** **V**
`reload_outcome_locked` refuses and mutates nothing on every bad candidate, with the standing
sentence *"No backend was started or stopped, and no configuration was published"*
(`config_reload/mod.rs:1745, 1763`). A grants path that dropped live state on a
parse error would be the only place in `config_reload` where a bad file changes the running
process. That is a surprise a reviewer should not have to find.

**5. The config knob that governs the boot version of this question says so in its own doc.**
**V** `fail_on_error` (`src/config/features/security.rs:405-407`): *"Fail startup if the
configured file cannot be read or parsed. Default: `true` **so operators do not silently run
with an empty grant store**."* The codebase's stated worry is running with an empty store —
precisely what fail-closed-on-reload manufactures.

**Why the reload deliberately ignores `fail_on_error`.** **V** At boot, that flag chooses
between aborting startup (`Err(Error::Config(e))`, `server/mod.rs:173`) and continuing with
**no** grants plus a warning (`:174-181`). Neither branch transfers. "Refuse to start" has no
analogue in a running process — there is no "refuse to keep running" — and the continue branch
is only safe at boot because nothing is in force yet. **A** Honouring the flag at reload time
would therefore mean inventing a third meaning for it; the design does not, and this paragraph
exists so nobody adds it later thinking it was an oversight.

**A refusal must not touch the epoch, and fail-open is what makes that free.** The epoch is
global, not per-caller: **V** it is mixed into every response-cache key through
`KeyContext.digest()` (`src/cache.rs:115-120`), so one bump strands **every** caller's entries,
not just the subject whose grant changed. A reload that fails to parse a file and bumps anyway
would therefore throw away the whole gateway's result cache in exchange for nothing — no
grant changed, no authorization decision differs, and the refusal repeats on every retry, so a
grants file left corrupt turns each reload into a full cache flush.

Fail-open makes this structural rather than a rule to remember: the refusal returns **before**
the publisher is reached, and the publisher is the only thing that bumps. There is no code path
where a refused grants reload advances the epoch, because publish-and-bump is one function
(§D2) and a refusal never calls it. **The same reasoning is why the no-op comparison (T8) is
MVP rather than polish** — an unchanged file that published anyway would flush every caller's
cache on every reload, which is the identical waste arriving through the success path instead
of the failure path.

**What fail-open is NOT.** It is not "keep serving a revoked grant and say nothing." The
refusal is an `Err` on the trigger's own channel (§D4) plus an `error!` tracing event plus an
audit entry where one is available (§D5). The operator's revoke is not lost — it is on disk,
the CLI already told them disk is all it did, and the reload says out loud that it did not land.

### D4 — What the operator sees

**V** The gap today: `print_grant_result("revoked", ...)` (`commands/identity.rs:90`) prints
the same word whether a gateway is running, not running, or running on another host.

**The CLI cannot honestly say "applied", and cannot say "queued" either.** It is a separate
process; **A** under the shipped container image it is very often a different container and a
different mount from the gateway, and nothing guarantees any gateway reads that path. There is
also no queue — nothing persists an intent to apply. Claiming either is how a security message
starts the next incident report.

So the CLI states only what it did and where the live answer lives:

```
revoked  grant-id=alice-heygen  file=/etc/mcp-gateway/grants.yaml
  Written to disk only. Running gateways apply this on their next config reload.
  Live state: gateway_reload_config, or the control-plane grant view.
```

**Distinguishing applied from not-applied uses two surfaces that already exist**, so this adds
no new reporting mechanism:

- **The trigger's own return.** `reload_identity_grants` returns a result the caller renders:
  applied (with a count and the path), no-change, or refused (with the parse error). The
  `gateway_reload_config` meta-tool and the admin UI reload already render a `ReloadOutcome`
  (`config_reload/mod.rs:131-229`); grants add one line to it.
- **The authoritative live view.** **V** `identity_grant_rows()` (`meta_mcp/mod.rs:1313`)
  snapshots the **in-memory** store, and `control_plane_grant_from_identity`
  (`ui/control_plane.rs:685`) already projects each row to `Approved` / `Revoked`. That view
  reads live state, not the file, so it answers "did it land" by construction. **I** No change
  is needed to it; it simply becomes the documented answer.

### D5 — Audit: yes, on the governance log, and say where that log is absent

**Decision: append to the control-plane governance audit log when it exists; always emit a
tracing event; do not add a third log.**

**V** The pattern exists and is the right one. `apply_mutation` routes grant and policy
mutations through `validate_for_actor` + `commit_grant_audited`
(`ui/control_plane.rs:175-196`), and the tests pin both directions —
`admin_grant_mutation_persists_and_audits` (`:1161`) and
`auditor_grant_mutation_is_denied_with_no_side_effects` (`:1184`). **V** The governance log is
deliberately separate from the invocation transparency log and shares its signing identity:
*"a governance-scoped audit log, separate from the invocation transparency log (ADR-005,
MIK-6685) … Governance audit entries reuse the transparency log's signing identity, so they
are signed iff the invocation log is"* (`server/mod.rs:185-199`). A grant reload is a
governance event by that definition, so it belongs there and not in the invocation log.

**The hole, stated rather than papered over.** **V** `build_control_plane_store` returns
`None` — disabling the governance routes, which then answer 503 — **when auth is disabled**,
and also *"if the data directory or the audit log cannot be opened; never fatal to startup"*
(`server/mod.rs:189-193`). **I** Therefore *"a grant reload is audited"* is **false on an
auth-disabled gateway** and false when the data dir is unavailable. In those configurations
the only record is the tracing event.

**Ruling:** audit to the governance log when the store is present; always emit `info!` on an
applied reload (path, grant count, changed / unchanged) and `error!` on a refusal (path,
parse error); and state the auth-disabled gap in the operator docs rather than adding a
fallback log. **I** A gateway with auth disabled treats every caller as an anonymous admin
(`server/mod.rs:189-191`) — a private audit trail on that deployment would assert an
accountability it does not have.

---

## 3. Test plan — cells by failure mode

Tests first. Each row names the **failure it goes red on**, not the code path it touches.

**On the harness.** Every cell below is expressible today with `MetaMcp` + `tempfile` +
assertions on `evaluate` / `identity_grant_rows()` / `policy_epoch()`, in the style of
`policy_epoch_tests.rs`. None needs a live MCP transport. This is said explicitly because
`policy_epoch_tests.rs:13-16` concedes the full `invoke` path is undrivable here, and because
the catalogue review's §6.3 records this house rejecting greps and green-before controls
presented as tests. Proposed module: `src/gateway/meta_mcp/grant_reload_tests.rs`.

| # | Goes red when | Setup → observable |
|---|---|---|
| **T1** | **A revocation never reaches the running process** — the bug. | Store with an active grant; `evaluate` allows. Write the file with `revoked_at` set. Trigger reload. → `evaluate` now denies for that subject/capability. |
| **T2** | **A corrupt file drops live grants** (the fail-closed hole, §D3). | Populated live store. Overwrite the file with unparseable bytes. Trigger reload. → reload returns `Err`, **and** `identity_grant_rows()` is byte-identical to before, **and** `evaluate` still allows, **and** `policy_epoch()` is unchanged. |
| **T2b** | **A refused reload flushes every caller's result cache** (§D3). Separate cell because T2's first three assertions can all pass while the epoch still moves — and the epoch is global, so the blast radius is every caller, not the one whose grant was edited. | The T2 setup, repeated three times against the still-corrupt file. → `policy_epoch()` is unchanged after each, and a key minted before the first attempt still hits the cache after the third. |
| **T3** | **A torn read drops live grants.** Pins the `tokio::fs::write` hazard (`commands/identity.rs:234`) that makes T2's case routine rather than exotic. | Populated live store. Truncate the file mid-record (valid prefix, no closing structure). Trigger reload. → same four assertions as T2. |
| **T4** | **A missing or unreadable file drops live grants.** Distinct from T2: a vanished mount is not a corrupt one. | Populated live store. Delete the file. Trigger reload. → same four assertions as T2. |
| **T5** | **"Revoke everything" is not expressible** — the escape hatch that keeps §D3 honest. | Populated live store. Write a valid file with `grants: []` and a correct `schema_version`. Trigger reload. → reload reports **applied**, store is empty, `evaluate` denies. Mirror-image of T2 on the same input shape; T2 and T5 fail in opposite directions, so neither passes vacuously. |
| **T6** | **A refusal is indistinguishable from a success** (§D4). | The T2 setup. → the returned error text names the path and the parse failure; it is **not** an `Ok` reporting "no changes". |
| **T7** | **The publisher forgets the epoch** — a stale response-cache entry outlives the grant change. | Read `policy_epoch()`. Apply a reload that genuinely changes the grants (T1's file). → epoch is strictly greater. Reuse `policy_epoch_tests.rs`'s key-builder assertion so the observable is a real cache miss, not just an integer. |
| **T8** | **A no-op reload churns every caller's response cache.** **Red today**: `set_identity_grants` (`meta_mcp/mod.rs:1300-1307`) bumps unconditionally. This cell is what forces the `PartialEq` comparison, and why that comparison is MVP. | Read `policy_epoch()`. Trigger a reload against a file byte-identical to the live store. → epoch **unchanged**, and the outcome reads "no change". |
| **T9** | **A config refusal holds a revocation hostage** (§D1 reason 2) — but only if the observable is the *ordering*, not the outcomes. | Config file edited so `reload_outcome_locked` refuses at its early `return Err` (`:1663`, the `security.message_signing` restart field), plus a grants file carrying a revocation. Trigger both through the one operator-facing entry point, under the shared lock. → the config reload returns `Err` **and** `evaluate` denies, **and** the grant publish is reached rather than skipped by that early return. **The third assertion is the test.** Asserting only the first two passes trivially the moment the two paths are separate functions, which proves nothing about sequencing; the catalogue review's §6.3 is this house rejecting exactly that. |
| **T10** | **Two concurrent triggers lose a write** (§D1 reason 3). | Two reload triggers racing a two-revocation file sequence. → the final store matches the last file written, never an earlier one. **A** Deterministic only under the lock; without it this is the interleaving `apply_patch:902-910` describes. |
| **T11** | **Expiry regressed** — the one liveness property that already works, and the cheapest thing for this change to break. | Grant with `expires_at` in the near future. Advance the clock input past it with **no reload at all**. → `evaluate` denies. Green before and after; it is a guard, and is labelled as one rather than counted as new coverage. |

**Not tests, and not counted as any.** That the catalogue cache is untouched by this change
(§0) is a scope statement resting on a cited absence (`rg -n "policy_epoch" src/backend/` →
exit 1), not a cell. It goes red only when `MIK-7334`'s slot-eviction tests land.

### 3.1 On the briefing's "the epoch advances exactly once per applied reload"

**Recorded as over-specified, and replaced by T7 + T8.** "Exactly once" is not an invariant
this codebase holds. **V** `LiveConfig::set` bumps the **same** `Arc<AtomicU64>` on every
published config reload (`config_reload/mod.rs:312-320`, wired at `server/mod.rs:1570-1571`),
and **V** `CapabilityExecutor::bump_policy_epoch` bumps it from two further sites
(`src/capability/backend.rs:229,388`). A test asserting a delta of exactly one would encode a
property that is already false and would go red on unrelated work.

Monotonicity is the real invariant — and it has no reachable red state, since the only
mutation is `fetch_add`, already guarded by a `debug_assert!` at the write site
(`meta_mcp/mod.rs:1303-1307`). A test for it would pass by construction. The two cells that
**can** fail are T7 (a change that fails to advance the epoch) and T8 (a non-change that
advances it), which is why they replace it.

---

## 4. Scope: minimum viable versus gold-plating

**This is a new mechanism in a release candidate.** The MVP is deliberately the smallest thing
that makes a revocation reachable on a running process, and it is sized so a reviewer can cut
it further without leaving a half-built mechanism behind.

**What this design closes, stated so it cannot be read wider.** It closes the revocation
**trigger** and the **result-cache** half — a reload publishes the new store and advances the
epoch, stranding every result-cache key minted under the superseded grant. It **does not**
close the per-caller **catalogue** half, which needs identity-keyed eviction of the pool slot
and is unimplemented today (§0, `pool.rs:326`). That second construct is **out of scope here
by decision, not by oversight**, and this design must not be widened to cover it.
**`MIK-7334.CATALOGUE.1` does not close on this document.**

### MVP — five pieces

| Piece | Size |
|---|---|
| 1. `MetaMcp.identity_grants` → `Arc<RwLock<…>>`; one shared publisher holding the write-then-bump-under-lock discipline (§D2). | Field type + `Arc::new` at **two** construction sites (`mod.rs:672,864`). Two readers compile unchanged (**V**, §D2). |
| 2. `ReloadContext` gains the two `Arc`s and `reload_identity_grants()`, inside `lock_reload_within` (§D1). | One field pair, one function: read file → compare → publish or refuse. |
| 3. The existing triggers call it — `gateway_reload_config` and the admin UI reload. | Call site each; both already hold a `ReloadContext`. |
| 4. The no-op comparison (T8). **V** `IdentityGrant` and `IdentityGrantFile` both derive `PartialEq, Eq` (`identity_grants.rs:115,147`) and the store is a `BTreeMap`, so this compares the loaded rows against `identity_grant_rows()` — no new trait, no new helper. | One comparison. |
| 5. The CLI message and the grants line in `ReloadOutcome` (§D4). | Two strings. |
| T1–T11. | — |

Cutting piece 4 is the one cut that costs something real and invisible: every reload then
invalidates every caller's response cache. Cutting piece 5 leaves the mechanism working and
the operator unable to tell whether it worked, which is the state this design was written to
end.

### Gold-plating — explicitly out

| Out | Why |
|---|---|
| **Filesystem watcher on the grants file** (option c) | The zero-touch slice, and the honest second one. It needs directory-watch treatment plus a torn-read guard against the non-atomic write at `commands/identity.rs:234` — **V** which is a second decision (retry-on-parse-failure, or make the CLI write atomically via tmp+rename), not a line of wiring. Shipping it in the same slice means shipping that decision unreviewed. |
| **SIGHUP handler** (option b) | Unix-only (§2), no outcome channel, and unreachable from an MCP client inside a container. Redundant once (a) exists. |
| **A dedicated grant-reload route** (option d) | `gateway_reload_config` already exists and is already admin-gated. **V** A new meta-tool also costs the compact-surface budget the project protects by decision. |
| **Auto-reload on CLI revoke** | The CLI is a different process, often a different container (§D4). It would need to discover and authenticate to running gateways — a client, not a trigger. |
| **Merging `LocalIdentityGrantStore` with the control-plane store** | Two grant worlds with different shapes and lifecycles (§2 row d). A merge-semantics design of its own. |
| **Slot eviction for the catalogue cache** | `MIK-7334`'s work, not this one (§0). |

---

## 5. Where I think this design is weak

Recorded because a design that survives its own author unchanged is a finding.

**5.1 It is operator-triggered, and the threat model for revocation usually is not.** A
revocation that lands only when someone runs a reload is weaker than one that lands on write.
Every argument in §D1 for (a) over (c) is about *torn reads and review surface*, not about
(c) being the wrong end state. **(c) is the right end state**; this slice is the part of it
that can ship reviewed. If a reviewer decides the gap between `revoke` and the next reload is
unacceptable for the release, the answer is to pull the watcher forward and pay the atomicity
decision now — not to argue this slice is sufficient.

**5.2 The lock decision trades a rare stall for a rare lost write, and I have not measured
either.** §D1 reason 3 takes the serializing lock, so a revocation can wait behind a config
reload awaiting `backend.stop()` on a slow stdio child (`apply_patch:947,958`). **A** I assume
that wait is short and bounded; I did not measure it, and no test in §3 bounds it. T10 pins
the correctness half only. **V** There is also a third outcome I have not given a cell:
`lock_reload_within` times out to `ConfigWriteError::Busy` (`config_reload/mod.rs:1634-1641`).
Under §D3 that is simply another refusal — nothing published, operator told — but it means a
revocation can come back "busy, retry", and the CLI message in §D4 does not mention that.

**5.3 The criterion needs two constructs and this supplies one.** This design makes revocation
live on the authorization path and strands the result cache. The other construct —
identity-keyed pool-slot eviction — is unimplemented (`pool.rs:326` is idle-keyed) and belongs
to `MIK-7334`. Whether the criterion's revocation conjunct is satisfied by the two together,
or needs something neither supplies, is a grading question this document does not answer and
must not be read as answering.

**5.4 The audit gap is stated but not closed.** §D5 leaves auth-disabled deployments with a
tracing line and no signed record. That is defensible (an auth-disabled gateway has no actor
to attribute to) but it means "grant reloads are auditable" carries a configuration caveat,
and any compliance claim built on it has to carry the same caveat.
