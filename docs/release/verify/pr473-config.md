# PR #473 shard — `src/config/`, `src/config_reload/`, `src/commands/`

Pinned revision: `BASE=c3626cf8`, `HEAD=60b138bb10a869703254eae2fe500f055d96f8d7`.
Payload built from the pinned SHAs, never the worktree.

## Payloads — split, and why

The shard diff is 212,860 bytes over 10 files (4,000 insertions, 262
deletions), sha256
`3c12f814f46fa6172243c87c1b0e3ac53352fb838f019834d823ebe10daddb36`. That
exceeds the ~150KB single-payload limit in the shared brief, so it was split by
kind and each half reviewed by both vendors.

| half | sha256 | bytes | contents |
|---|---|---|---|
| source | `1e025a3a949d1d6ac66a9f8fd9880e9f4c71211faf73f5802f563f8e9366e7c1` | 123,691 | `config/mod.rs`, `config/env_overlay.rs`, `config/features/`, `config_reload/mod.rs`, `commands/{add_remove,setup,upgrade}.rs` |
| tests | `f7ae5f3bf8efc21440f050d09a77f2b24d3084f7597e4522c99f037126644cbc` | 89,169 | `config/tests.rs`, `config_reload/tests.rs` |

Per-file insertions: `add_remove` 67, `setup` 19, `upgrade` 247,
`env_overlay` 507 (new), `features/error_budget` 167 (new), `features/mod` 2,
`config/mod` 858, `config/tests` 901, `config_reload/mod` 313,
`config_reload/tests` 1,181.

## Ledger rows — four, because the payload was split

The ledger records `material_sha256` as `sha256(0x00 || payload)`; that identity
was recomputed locally for both payloads and matches the rows below, which is
what binds each verdict to the exact bytes reviewed.

| half | vendor | ts (UTC) | verdict | material_sha256 | process_status |
|---|---|---|---|---|---|
| source | gpt | 2026-09-08T16:27:37Z | SHIP-WITH-FIXES | `bc5d7b085266115627626fd40d3a683d0901f72dd5053988bd39dfc99a6d8593` | ok |
| source | grok | 2026-09-08T16:34:11Z | SHIP | `bc5d7b085266115627626fd40d3a683d0901f72dd5053988bd39dfc99a6d8593` | ok |
| tests | gpt | 2026-09-08T16:27:56Z | SHIP-WITH-FIXES | `11ae36c4cd3a4ddbb7d84b0e6bf4eb87995bf93cefc7a7a393e2bd1f0c6b1077` | ok |
| tests | grok | 2026-09-08T16:38:10Z | SHIP-WITH-FIXES | `11ae36c4cd3a4ddbb7d84b0e6bf4eb87995bf93cefc7a7a393e2bd1f0c6b1077` | ok |

All four rows carry `process_status: ok`, so all four are verdict-bearing. The
two halves were reviewed independently; a finding raised on one half was not
shown to the reviewers of the other.

## Findings — source half

Every finding was checked at source. `${VAR}` substitution behaviour was
decided against the vendored parser (`dotenvy 0.15.7`), not assumed.

### S1 — an env file's own earlier assignment loses to the ambient process environment (CONFIRMED, MEDIUM, not blocking)

`apply_substitution` consults `env::var` FIRST and only falls back to keys read
earlier from the same file
(`~/.cargo/registry/.../dotenvy-0.15.7/src/parse.rs:265`), and
`from_read_iter` starts with an empty substitution map (`src/iter.rs:20`). So
`A=1` followed by `B=${A}` yields the process value of `A` when one exists.
The rationale comment at `src/config/env_overlay.rs:130-134` states the
opposite ("a key this same file has already assigned resolves within the
file"), which is true only when the ambient environment is silent. The
precedence itself is not new — the replaced loader
(`dotenvy::from_path_override`, deleted at payload-src.diff:1655) reached the
same `apply_substitution` — so this is a wrong comment and an inherited
sharp edge, not a regression.

### S2 — the cross-file substitution guard misses `${A}` inside a double-quoted value containing an apostrophe (CONFIRMED, MEDIUM, not blocking)

`first_expanded_substitution` enters single-quote state on any `'`, including
one inside a double-quoted region (`src/config/env_overlay.rs:214-218`), and
treats the remainder of the value as inert. `dotenvy` does not: inside weak
quotes a `'` is an ordinary character and `${A}` is still expanded
(`dotenvy-0.15.7/src/parse.rs:216-232`). `K="it's ${A}"` where `A` lives in
another env file therefore passes the guard at
`src/config/mod.rs:506` and the value silently expands to nothing — the exact
failure the guard exists to refuse.

### S3 — the same guard refuses `K=#${A}`, which the parser reads as an empty value (CONFIRMED, LOW, not blocking)

`dotenvy` returns an empty value with no expansion when the value begins with
`#` (`dotenvy-0.15.7/src/parse.rs:63-66`). The scanner only recognises a
comment when whitespace precedes the `#` (`src/config/env_overlay.rs:221`), so
it reports an expansion and `src/config/mod.rs:506-514` refuses to load. Needs
a value literally starting with `#` naming a key another env file defines;
rare, but the failure mode is a refused start.

### S4 — a UTF-8 byte-order mark now fails the parse (CONFIRMED, MEDIUM, release-note candidate)

`from_read_iter` is `Iter::new` with no BOM removal
(`dotenvy-0.15.7/src/lib.rs:303-305`); `remove_bom` runs only on the
`load`/`load_override` paths (`src/iter.rs:29-30`). The deleted loader was
`dotenvy::from_path_override` (payload-src.diff:1655), which stripped it. Both
server entry points load with `Tolerance::Fail` (`src/main.rs:556,609`), so a
BOM-prefixed env file that worked in 3.x refuses startup in 4.0.0. Grok raised
the same gap from the test side.

### S5 — `doctor` passes a config that `serve` refuses (CONFIRMED by both vendors, MEDIUM, not blocking)

`src/commands/doctor.rs:347` loads with `Config::load` (tolerant: a malformed
env file is warned and skipped) while startup uses `Config::load_evaluated`
(`src/main.rs:556,609`). The 4.0.0 notice tells operators a malformed
`env_files` line now fails startup; the pre-flight check that would catch it
still reports green.

### S6 — the environment-variable prefix match lost figment's case-insensitivity (CONFIRMED, MEDIUM, not blocking)

The replacement provider uses `key.strip_prefix("MCP_GATEWAY_")`
(`src/config/mod.rs:216`, prefix at `:150`), which is case-sensitive.
figment's `Env::prefixed` matches on `UncasedStr`
(`figment-0.10.19/src/providers/env.rs:198-204`, `:12`, `:509`), so
`mcp_gateway_SERVER__PORT` used to override and is now silently ignored.
Documented usage is uppercase, so exposure is limited to deployments that
spelled it otherwise.

### S7 — `list`, `get`, `remove` and `update` still fold an unparseable config into defaults (CONFIRMED, LOW, not blocking)

`src/commands/add_remove.rs:163,201,143,261` call
`config_persistence::load_config_or_default`, which warns and returns
`Config::default()` (`src/config_persistence.rs:20-29`). Only `add`
(`add_remove.rs:72`) uses the fallible `load_existing_or_default`. A broken
file reads as "no backends configured"; the GH #462 no-overwrite property
holds for `remove`/`update` only because the empty default trips the
missing-name guard before the write.

## Findings — tests half

These are defects in the new tests, not in shipped behaviour. A test that
cannot fail is a missing requirement, so they are recorded at the same weight
even though none of them can break a release.

### T8 — the reload fixture seeds `LiveConfig` from `Config::default()`, so no "unchanged config" case is unchanged (CONFIRMED by both vendors, MEDIUM, not blocking)

`reload_context_with_env` builds the live handle from defaults
(`src/config_reload/tests.rs:1977`) rather than from the evaluated startup
config. Every reload in this module therefore diffs defaults against the
fixture config and produces a large patch. ENVFILE.10c and ENVFILE.10.1 exist
to pin the empty-patch publish branch in `reload_outcome_locked`; neither ever
reaches it. An env-file-only rotation that skipped the overlay publish on
`patch.is_empty()` would ship green.

### T9 — ENVFILE.19f resolves `~/rot.env` against the real home directory (CONFIRMED by both vendors, MEDIUM, not blocking)

The case writes its fixture under a `TempDir` but constructs the resolver with
`RecordingHome::new()`, which reads `dirs::home_dir()`
(`src/config_reload/tests.rs:2224`). The tilde half of the conjunction is
therefore evaluated against a path the test never wrote, and a developer who
happens to own `~/rot.env` can flip the result.

### T10 — the rejected-reload case writes the same value before and after the malformed line (CONFIRMED, MEDIUM, not blocking)

The candidate file's valid assignment is byte-identical to the one already
published (`src/config_reload/tests.rs:2665`), so "the overlay is unchanged"
holds whether the failed load preserved the live value or published a
partially parsed candidate. The assertion cannot distinguish the two states it
was written to distinguish.

### T11 — ENVFILE.10c asserts on a `ResolvedAuthConfig` built before the reload (CONFIRMED, LOW, not blocking)

The holder under assertion is a local constructed ahead of the reload call
(`src/config_reload/tests.rs:2732`), so it cannot observe whether production
rebuilt auth from the new overlay. The check reads as a guarantee about
production and is a guarantee about a local variable.

### T12 — the dotenvy oracle cases may fail on a developer machine (CANNOT-VERIFY, LOW, not blocking)

`src/config/tests.rs:1568` and its neighbours assert substitution results for
the bare names `A`, `OTHER` and `BASE` while the process environment is
untouched. Given S1 — process values win — a machine exporting any of those
gets a different answer. What could not be determined: whether the cases
actually fail, because no test suite was executed in this session. The
mechanism is confirmed at source (`dotenvy-0.15.7/src/parse.rs:265`); the
outcome is not.

### T13 — the YAML fixture embeds an unescaped path inside double quotes (CANNOT-VERIFY, LOW, not blocking)

`src/config_reload/tests.rs:1962` interpolates a filesystem path into a
double-quoted YAML scalar, where `\` is an escape introducer. On a POSIX host
the paths contain no backslash and the fixture is well-formed. What could not
be determined: the Windows behaviour, which is the whole claim — this session
had no Windows host and CI's platform matrix for these tests was not read.

## Not covered

Stated plainly, because silent truncation reads as coverage.

- `src/config_reload/mod.rs` beyond the loader wiring. The changed
  `changed_startup_env_keys`, `ReloadContext::with_env` / `env_paths` /
  `live_env`, and the `with_pending_restart` signature change were read only
  as far as the env-file path required. Their own behaviour was not
  independently reviewed.
- `src/features/error_budget.rs`, 167 new lines, not read. It arrived in the
  same payload as GH #475 and is unrelated to the env-file work; both vendors
  noted the mixing but neither reviewed the feature.
- No test suite was executed. Every finding above is from source reading. T12
  and T13 are unresolved for exactly that reason.

## Release verdict

No confirmed finding blocks 4.0.0. S4 (BOM) and S6 (case-sensitive prefix) are
behaviour changes that reach existing installations and belong in the release
notes; S2 and S5 are real defects that degrade gracefully — a refused start
and a green pre-flight, both loud rather than silent. The tests-half findings
weaken future regression coverage and change nothing about what ships.
