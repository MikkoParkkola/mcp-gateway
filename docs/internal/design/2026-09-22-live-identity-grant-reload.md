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

**Branch caveat — raised, and discharged.** Every line number below was verified on
`docs/pkg1-runtime-evidence` (worktree `/Users/mikko/github/.worktrees/relcheck`), while the
briefing named `docs/ranking-1-release-line`. That skew has since been checked: the two
branches have **zero `src/` difference**, so every `file:line` anchor here holds on the release
line as written. Recorded rather than deleted, so a later reader knows the question was asked
and answered rather than never raised.

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

**3. It needs a lock, but its OWN lock — not `lock_reload_within`.** Grants do need
serializing: two triggers can interleave read-file and publish, the older file wins, and a
revocation is **silently lost** — the exact bug this design exists to kill.

But the *shared* lock is the wrong one, and re-reading the comment that justifies it says why.
**V** `apply_patch` (`config_reload/mod.rs:898-910`) warns about **backend registration**: two
reloads each compute a `ConfigPatch` against the live config, both add the same backend, and
*"register two instances under one name… if traffic started that first instance in the gap its
child process is orphaned."* **I** That hazard is entirely `Config`/`ConfigPatch`/registry
shaped. Grants are not in `Config`, are not diffed as a patch, and register no backends, so a
grants reload cannot cause it and cannot suffer it.

**Decision: a grants-only `tokio::sync::Mutex`.** It gives the same mutual exclusion between
grant reloads, and gives up nothing, because the only state the two paths genuinely share is
the epoch — **V** an `AtomicU64` mutated solely by `fetch_add` (`meta_mcp/mod.rs:1303`;
`config_reload/mod.rs:315`), so concurrent bumps are monotone and over-invalidate at worst.

**This deletes a worst case rather than documenting one.** Under the shared lock a revocation
could wait behind `backend.stop()` on a slow stdio child (`apply_patch:947,958`) or return
`Busy` from `lock_reload_within` (`:1634-1641`) because of an entirely unrelated config edit.
Under a grants-only lock neither can happen.

**The publish-then-bump invariant is unaffected**, and this is worth stating because it looks
like the kind of thing a narrower lock would weaken. It does not: the invariant is that the
epoch advances *while the grants write lock is held* (`meta_mcp/mod.rs:1300-1307`). That is a
property of the grants lock and the ordering inside one function. Which **other** writers touch
the epoch is irrelevant to it — they were never excluded by `lock_reload_within` either, since
**V** `capability/backend.rs:229,388` bump it without taking that lock at all.

**The two strongest arguments against this choice**, recorded because a reviewer should be
able to overturn it:

- **It is not zero-touch.** A revoke is live only when someone triggers a reload. An
  operator who revokes and walks away has not revoked on the running process. (c) would close
  that; this does not. The mitigation is honesty, not mechanism — §D4 — and the second slice
  in §5 is exactly (c).
- **It reuses a module whose reason for existing is `Config`, for something that is not
  `Config`.** Once grants have their own function, their own lock and their own outcome
  (reason 3), what remains shared is the *trigger* and the file-reading idiom — and a reader
  may reasonably ask whether that is reuse or coincidence. The answer I'd defend: the trigger
  is the valuable part (admin-gated, already surfaced, already understood by operators), and
  rebuilding it elsewhere would duplicate `gateway_reload_config` for no gain. But if a
  reviewer decides grants deserve their own trigger too, reason 3 has already done most of the
  separation work, and the cut is cheap.

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
| **Valid and empty** — `schema_version` present, `grants: []` | **Apply it.** Store becomes empty. | The escape hatch, and the supported way to revoke everything — **but only safe once MVP piece 6 lands.** See §D3.1. |

That third row is what stops fail-open from being a hole. "Revoke everything" is expressible,
it parses, and it applies — so fail-open never means "there is no way to drop all grants".
It is also, without piece 6, the most dangerous row in this design. §D3.1.

### D3.1 — The hole fail-open does not cover: a torn file that is *valid and short*

**The refusal never fires, because there is nothing to refuse.** Fail-open defends against a
file that fails to parse. A truncated grants file need not fail to parse — it can be valid
YAML describing **fewer grants**, and the design publishes it as authoritative.

**V, and it reduces exactly to the escape hatch.** `IdentityGrantFile`
(`src/identity_grants.rs:147-154`) declares **both** fields with defaults:

```rust
#[serde(default = "default_identity_grants_file_schema_version")]
pub schema_version: String,
#[serde(default)]
pub grants: Vec<IdentityGrant>,
```

**V** So a write interrupted after the header — before any row lands — deserializes to
`grants: []`, and the schema check at `read_identity_grants_file` (`:193-200`) passes, because
the defaulted version **is** `IDENTITY_GRANTS_FILE_SCHEMA_VERSION`. The result is bit-for-bit
the deliberate revoke-everything file. A prefix ending after any complete row parses the same
way with a partial list.

**Three decisions, each sound alone, combining into the outage the ruling exists to prevent:**

| # | Decision | Alone |
|---|---|---|
| 1 | Fail open on a corrupt file (§D3) | Sound |
| 2 | A valid empty list **applies**, so revoke-all stays expressible | Sound |
| 3 | The CLI writes non-atomically — `tokio::fs::write` truncates first (`commands/identity.rs:234`) | The known hazard |

**(2) + (3) = an interrupted `identity grant add` revokes everything on the next reload.** The
all-user outage arrives through the **success** path, where no refusal, no log and no error
text stands in its way. T3 as first written assumed a torn file is invalid; **it need not be**.

**Ruling: MVP piece 6 (atomic tmp+rename) is a REQUIREMENT of this design, not an improvement
to it. Do not ship decision (2) without it.** With atomicity a partial file never exists,
(3) disappears, and (2) goes back to being safe rather than load-bearing.

**And the fix belongs at the writer, not the parser.** Rejecting a short-but-valid file would
mean rejecting valid YAML — which would also reject the legitimate revoke-all file, the one
case decision (2) exists to serve. The parser cannot distinguish "operator meant zero grants"
from "the writer died after the header", because **they are the same bytes**. Only the writer
knows, so only the writer can fix it.

**Five reasons for fail-open on the first two rows.**

**1. Fail-closed turns a partial file into a total outage — and the argument survives this
slice fixing the main cause of partial files.** **V** `tokio::fs::write`
(`commands/identity.rs:234`) truncates before it writes, so today every `identity grant add`
and `revoke` opens a window where the file parses as garbage. **I** Under fail-closed, a reload
landing in that window drops **every** grant on the gateway — an operator *adding* a grant
takes down every personal capability.

**MVP piece 6 removes that cause** (atomic tmp+rename, below), so the honest version of this
reason is narrower and still sufficient: torn and partial files do not only come from our
writer. An editor saving in place, a half-finished `scp`, a truncated mount, a
config-management tool mid-render, a container image with a partially materialised layer — all
produce the same bytes, and none are ours to fix. **I** Fail-open costs nothing to keep after
piece 6; fail-closed would convert every one of those into a gateway-wide denial of personal
capabilities. Reasons 2–5 below do not depend on the writer at all.

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

**V, and it is not only `revoke`.** `identity grant add` has the identical liveness gap — a
new grant is equally not-in-force until a reload — and **V** both verbs already route through
the one `print_grant_result` (`commands/identity.rs:285`), called at `:80` (`"granted"`) and
`:90` (`"revoked"`). So the notice goes in that shared function and both verbs get it from a
single edit. The ticket names only the revocation verb; fixing it at the caller would leave
`add` silently wrong, which is the sibling-caller mistake this repo's own guidance warns about.

**The CLI cannot honestly say "applied", and cannot say "queued" either.** It is a separate
process; **A** under the shipped container image it is very often a different container and a
different mount from the gateway, and nothing guarantees any gateway reads that path. There is
also no queue — nothing persists an intent to apply. Claiming either is how a security message
starts the next incident report.

So the CLI states only what it did and where the live answer lives:

```
revoked  grant-id=alice-heygen  file=/etc/mcp-gateway/grants.yaml
  Written to disk only. Running gateways apply this on their next reload.
  Live state: gateway_reload_config, or the control-plane grant view.
```

**And three refusals, which must not read alike.** Under §D3 nothing is published in any of
them, but they ask the operator for different things, so the trigger's error text distinguishes:

| Refusal | Operator text | What it asks for |
|---|---|---|
| Parse / schema | `grants reload refused: <path>: <parse error>` | Fix the file. |
| Absent / unreadable | `grants reload refused: <path>: <io error>` | Fix the path or the mount. |
| **Busy** | `grants reload busy: another grant reload is in progress; retry` | **Retry, unchanged.** |

**V** The busy case is real and survives the grants-only lock: §D1 reason 3 narrowed it to
contention between two *grant* reloads, but did not remove it. Rendering it as a parse failure
would send an operator to inspect a file that is perfectly fine.

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

**Ruling, and it is a scope ruling as much as an audit one: the tracing event is the MVP
record; the governance-log append is deferred.** The mechanism cited above does not fit a
file-driven reload without inventing something. **V** `apply_mutation`
(`ui/control_plane.rs:175-196`) is built around an **actor** (`actor_from_client` + role
mapping), an RBAC decision (`validate_for_actor`), and a `ControlPlaneGrant` payload. A reload
triggered by a file change has **no actor** — the operator who edited the file is not the
caller who triggered the reload, and may not be a gateway principal at all — and its payload is
a `LocalIdentityGrantStore`, not a `ControlPlaneGrant`. Appending to that log would mean
fabricating an actor, which is worse than not appending: a governance log whose actor column
is sometimes synthetic is a log nobody can reason about.

So, priced explicitly:

- **MVP:** `info!` on an applied reload (path, grant counts **and the §4 delta**, changed /
  unchanged) and `error!` on a refusal (path, parse error, or busy). This is the record.
- **Deferred, and listed in the gold-plating table:** a governance-log append, which first
  needs an event type that fits a no-actor file reload. That is an ADR-005 question, not a
  wiring question, and it should be answered once for every file-driven event rather than
  invented here for one.

State the auth-disabled gap in the operator docs rather than adding a fallback log. **I** A gateway with auth disabled treats every caller as an anonymous admin
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
| **T3** | **A torn read that is INVALID drops live grants.** Half the torn-file space; T3b is the other and more dangerous half. | Populated live store. Truncate mid-token so the result does not parse. Trigger reload. → same four assertions as T2. |
| **T3b** | **A torn read that is VALID silently revokes everything** (§D3.1). **Red today**, and not via the refusal path — via the success path. | Populated live store. Truncate the file after the header, before any row — **V** which parses as `grants: []` (`identity_grants.rs:147-154`). → **The assertion is that this state is unreachable, not that the parser rejects it.** Drive the real CLI write path (`write_identity_grant_file`) and assert no observer can ever read a partial file: after piece 6 the path is either the old content or the complete new content, never a prefix. Asserting a parse rejection instead would pin the wrong layer and would break the legitimate revoke-all file. |
| **T4** | **A missing or unreadable file drops live grants.** Distinct from T2: a vanished mount is not a corrupt one. | Populated live store. Delete the file. Trigger reload. → same four assertions as T2. |
| **T5** | **"Revoke everything" is not expressible** — the escape hatch that keeps §D3 honest. | Populated live store. Write a valid file with `grants: []` and a correct `schema_version`. Trigger reload. → reload reports **applied**, store is empty, `evaluate` denies. Mirror-image of T2 on the same input shape; T2 and T5 fail in opposite directions, so neither passes vacuously. |
| **T6** | **A refusal is indistinguishable from a success, or one refusal from another** (§D4). | The T2 setup → the error names the path and the parse failure, and is **not** an `Ok` reporting "no changes". Then, holding the grants lock, trigger a second reload → it returns the **busy** refusal, distinguishable from the parse refusal, and still publishes nothing. Both halves matter: the first stops a refusal reading as success, the second stops a retryable refusal reading as a broken file. |
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

**The file is authoritative on reload, and that can resurrect a revoked grant.** A reload
replaces the live store with whatever the file says — there is no comparison against what was
previously in force. **I** So a config-management rollback, a restored backup, or a redeployed
container image carrying an older grants file **un-revokes** every grant revoked since that
file was written, on the next reload. Every cell in §3 assumes the file is newer than the
store; none of them would catch this.

**Deliberately not solved here.** Detecting it needs a monotonic generation or revocation
tombstones that survive file replacement — a durable-state design, and a much larger one than
this. Three cheap things instead, all already in the MVP:

1. **Say it.** Operator docs state that the grants file is authoritative on reload, so
   restoring an old one re-grants. It belongs beside the backup procedure, not in a footnote.
2. **Make it visible.** §D5's `info!` on an applied reload logs the **delta** — grants added,
   removed, and newly-revoked-vs-previously — not just a total. A rollback then shows up as a
   negative revocation count in the log, which is the cheapest possible tripwire.
3. **Scope it.** This is recorded as a known limitation of file-backed grants, not a defect of
   the reload trigger. The same hazard exists today at **boot** (`server/mod.rs:1234`); reload
   widens *when* it can fire, not *whether* it can.

**A** No generation counter, no tombstones, no file-mtime check — an mtime comparison would
also refuse legitimate edits from a clock-skewed host, which trades a rare resurrection for a
routine refusal.

**What this design closes, stated so it cannot be read wider.** It closes the revocation
**trigger** and the **result-cache** half — a reload publishes the new store and advances the
epoch, stranding every result-cache key minted under the superseded grant. It **does not**
close the per-caller **catalogue** half, which needs identity-keyed eviction of the pool slot
and is unimplemented today (§0, `pool.rs:326`). That second construct is **out of scope here
by decision, not by oversight**, and this design must not be widened to cover it.
**`MIK-7334.CATALOGUE.1` does not close on this document.**

### MVP — six pieces

| Piece | Size |
|---|---|
| 1. `MetaMcp.identity_grants` → `Arc<RwLock<…>>`; one shared publisher holding the write-then-bump-under-lock discipline (§D2). | Field type + `Arc::new` at **two** construction sites (`mod.rs:672,864`). Two readers compile unchanged (**V**, §D2). |
| 2. `ReloadContext` gains the two `Arc`s and `reload_identity_grants()`, inside `lock_reload_within` (§D1). | One field pair, one function: read file → compare → publish or refuse. |
| 3. The existing triggers call it — `gateway_reload_config` and the admin UI reload. | Call site each; both already hold a `ReloadContext`. |
| 4. The no-op comparison (T8). **V** `IdentityGrant` and `IdentityGrantFile` both derive `PartialEq, Eq` (`identity_grants.rs:115,147`) and the store is a `BTreeMap`, so this compares the loaded rows against `identity_grant_rows()` — no new trait, no new helper. | One comparison. |
| 5. The CLI message and the grants line in `ReloadOutcome` (§D4). | Two strings, one shared print site (**V** both verbs route through `print_grant_result`, `commands/identity.rs:285`). |
| 6. **Atomic grant-file write.** Replace `tokio::fs::write` (`commands/identity.rs:234`) with tmp+rename. | **V** Already implemented and `pub`: `write_config_text` (`src/config_persistence.rs:125`) → `write_yaml` (`:129`) does exclusive-scratch create, `write_all` + `sync_all`, `rename_with_retry` (`:147`), and removes the scratch file on any failure. Reuse it. Two notes: it is **sync** `std::fs` while `write_identity_grant_file` is `async`, so it wants `spawn_blocking` or a deliberate blocking call on the one-shot CLI path; and the grants file may be JSON **or** YAML (`is_json_path`), so the shared helper wants a neutral name — `write_yaml` is already a private one-liner under `write_config_text`, so exposing it as `write_text_atomic` is the whole change. |
| T1–T12. | — |

Cutting piece 4 is the one cut that costs something real and invisible: every reload then
invalidates every caller's response cache. Cutting piece 5 leaves the mechanism working and
the operator unable to tell whether it worked, which is the state this design was written to
end.

### Gold-plating — explicitly out

| Out | Why |
|---|---|
| **Filesystem watcher on the grants file** (option c) | The zero-touch slice, and the honest second one. It needs directory-watch treatment (editors and renames replace rather than mutate) plus a debounce. MVP piece 6 removes the torn-write hazard that used to be the larger half of this slice's cost, so what remains is watcher mechanics — genuinely a slice, but a smaller one than when this design was first drafted. |
| **SIGHUP handler** (option b) | Unix-only (§2), no outcome channel, and unreachable from an MCP client inside a container. Redundant once (a) exists. |
| **A dedicated grant-reload route** (option d) | `gateway_reload_config` already exists and is already admin-gated. **V** A new meta-tool also costs the compact-surface budget the project protects by decision. |
| **Auto-reload on CLI revoke** | The CLI is a different process, often a different container (§D4). It would need to discover and authenticate to running gateways — a client, not a trigger. |
| **Merging `LocalIdentityGrantStore` with the control-plane store** | Two grant worlds with different shapes and lifecycles (§2 row d). A merge-semantics design of its own. |
| **Governance-log append for reloads** | Deferred by §D5. Needs an audit event type that fits a no-actor, file-driven mutation; fabricating an actor to reuse `apply_mutation` would corrupt the one property that log has. ADR-005 question, answered once for all such events. |
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

**5.2 The grants-only lock removes the stall but not contention, and I have not measured what
remains.** §D1 reason 3 takes a grants-only mutex, so a revocation no longer waits on
`backend.stop()` or on an unrelated config reload. What remains is contention between two
*grant* reloads, which is exactly what the lock is for and is bounded by one file read.
**A** I assume that is short; I did not measure it, and no test in §3 bounds it — T10 pins the
correctness half only. A grants reload can still return busy if a concurrent grants reload
holds the lock, which §D4 must say and T6 must assert.

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
