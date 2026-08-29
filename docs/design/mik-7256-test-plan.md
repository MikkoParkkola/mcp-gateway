# MIK-7256 test plan

One row per acceptance criterion. An empty evidence cell is a finding, not an
omission. Criteria are in `docs/design/mik-7256-env-files-on-a-failed-load.md`.

| AC | case | level | type | fails before the fix because |
|---|---|---|---|---|
| ENVFILE.1 | run one ACCEPTED reload first so a non-default overlay is published, then reload a candidate whose already-listed env file sets three `MIK7256_FAIL_<uniq>*` names, with a config that fails validation; assert the process environment equals its pre-reload snapshot AND `LiveEnv::get()` is the same `Arc` as before | integration (config_reload) | negative | `Config::load` applies the env file before it validates. The overlay half is the one that keeps biting after the fix: the process half is structurally guaranteed once nothing calls `set_var`, so a test that only checked the process would pass against a build that published a failed candidate's values. The accepted reload first is what makes the `Arc` assertion falsifiable at all: from a fresh process both snapshots are the same default `Arc`, so the case would pass against a build that never publishes |
| ENVFILE.1b | same, but the reload is refused by the network posture rather than by validation | integration | negative | the apply happens before the refusal is computed |
| ENVFILE.2 | reload a candidate that SUCCEEDS, its already-listed env file sets `MIK7256_OK_<uniq>`; assert `fetch_credential` resolves the file's value afterwards, and that the process environment is unchanged | integration | negative + positive | before the fix the value reaches a reader only through the process write. Both halves are load-bearing: the positive proves the publish happened, the negative proves it happened without mutation |
| ENVFILE.3 | process holds nothing for `MIK7256_INH_<uniq>`; the already-listed env file now sets it; reload FAILS validation; spawn a backend that does not reference it; assert the child does not see it at all | integration (transport) | negative | today the failed reload has already set the process value; the child still does not inherit it, so the assertion that bites is on the gateway process, and the child half only pins that `env_clear` keeps holding |
| ENVFILE.4 | `Config::load(path)` with two env files, the second overriding the first; assert both variables land in the process and the override order holds | unit (config) | positive | passes before and after — the startup-parity pin, and the only case in the suite that expects a process write |
| ENVFILE.5 | reload a candidate that adds a backend whose `env` map contains `${MIK7256_NEW_<uniq>}`, with an already-listed env file now defining it; assert the running backend's resolved config carries the value | integration | positive | the value must reach the resolved config from the evaluation overlay, before anything is published |
| ENVFILE.6 | env file's contents change `MCP_GATEWAY_PORT` to `18082`; assert the reloaded config reports 18082; then repeat with `MCP_GATEWAY_PORT=18081` exported into the process and assert the reload STILL reports 18082; then remove the key from the env file and assert the reload stops reporting it rather than falling back to 18081 | integration | positive+negative | three drafts got this row wrong, the last two by asserting an exported value beats an env file. It does not: startup calls `dotenvy::from_path_override` (`src/config/mod.rs:303`), so the file overrides the process. The second half fails for any design that keeps the real `Env` provider in the reload merge, because the process still holds what startup wrote there. The third fails only for one that keeps it AND cannot tell an overlay-owned process key from a shell-exported one |
| ENVFILE.18 | for a key set spanning a plain key, a `__`-nested key, mixed case and a value containing `=`, assert `EffectiveEnv::data()` equals the real `Env::prefixed("MCP_GATEWAY_").split("__")` provider's `data()` with those same pairs exported — comparing the whole `Map<Profile, Dict>` return, not the inner `Dict`, so profile emission and key lowercasing are pinned by the same assertion | unit (config) | positive | the reimplementation risk is drift, and the library is its own oracle, so the case cannot pass by agreeing with the thing it checks. Fails on any transformation `EffectiveEnv` gets wrong that `Env` gets right |
| ENVFILE.19 | an `env_files` entry spelled `~/<file>` with `HOME` pointed at a temp dir; assert startup and the overlay resolve it to the same absolute path and read the same pairs | unit (config) | positive | tilde expansion is a supported spelling today (`src/config/mod.rs:290-298`); an overlay that skipped it would silently stop rotating those files, and nothing else in the plan would go red |
| ENVFILE.6b | a key that genuinely cannot be applied to a running process; assert the restart-required report names the key AND that neither the old nor the new value appears in it | integration | positive | retargeted: `MCP_GATEWAY_PORT` is applied live by `EffectiveEnv`, so the warn this row asserted described a lag the design removed. What survives the removal is the half that still binds — #439's no-values rule must not be reintroduced by this change's own reporting |
| ENVFILE.6d | mutate an env file between the load and the publish at startup; assert the published overlay carries the values the load applied, not the later edit | integration | negative | the second read this design eliminated cannot be reintroduced without failing here. Asserting "startup publishes an overlay" passes against a build that re-parses, because both reads agree whenever nothing edits the file — the mutation is what makes the case able to fail |
| ENVFILE.6c | an env file carrying a malformed line, at startup and again on a reload; assert each diagnostic names the file, the line number and the category, and that neither the offending line nor any value it contains appears | integration | negative | the no-secrets rule had no case at either entry point, so a diagnostic that echoed the line to be helpful would have shipped. A malformed line in a credential file is a credential |
| ENVFILE.6d | an accepted reload whose already-listed env file has been truncated mid-line, over keys the previous overlay owns; assert the reload is REFUSED, that the diagnostic names the file and the line, and that every key the previous overlay owned still resolves to its previous value | integration | negative | an infallible rebuild made a stray character indistinguishable from a deliberate deletion: the owned set is the cumulative union, so a key the truncated file stops supplying is owned-but-absent, which is exactly the shape of a removal. The assertion that bites is the third one — a refusal alone passes against a reload that refused for any other reason |
| ENVFILE.7 | `mutate_and_reload_outcome_within` with a closure that REJECTS, over a config whose env file sets `MIK7256_UI_<uniq>`; assert the process and the published overlay both equal their pre-call snapshots | integration (config_reload) | negative | `load_config_or_default` applies the candidate's env files before the closure runs |
| ENVFILE.7b | same path with a closure that SUCCEEDS, over a config whose already-listed env file sets `MIK7256_UIOK_<uniq>` referenced by a backend it adds; assert `ConfigMutation::Applied`, the file on disk carries the edit, and the resolved backend config carries the value | integration (config_reload) | positive | .7's twin. Without it, .7 passes against a UI path that reads nothing and applies nothing |
| ENVFILE.7c | same path, where the test's own mutation closure succeeds and then, as its last act, replaces the config file's PARENT DIRECTORY with a regular file; assert the closure ran, the error surfaces, and the overlay is unpublished | integration (config_reload) | negative | the failure must be the LATE one, after the closure. Directory permissions do not produce it: a privileged CI user ignores the write bit, so the case would pass vacuously on exactly the machines that gate a merge. A parent that is not a directory fails `create_scratch_exclusive` with `NotADirectory` for every user, and it cannot be pre-empted by pre-creating the scratch names, which `next_scratch_seed` makes unpredictable |
| ENVFILE.1c | reload a candidate whose YAML parses far enough to yield `env_files` but fails the second extraction — a typed field given the wrong type — over a config whose already-listed env file sets `MIK7256_PARSE_<uniq>`; assert the error surfaces and nothing is published | integration (config_reload) | negative | the exit has to be one that occurs AFTER env application. `Config::load` extracts `EnvFileConfig` first (`src/config/mod.rs:193-198`) and only then applies the files, so a syntactically malformed candidate never reaches the apply and cannot falsify the defect — the earlier version of this row named exactly that case, and the config is YAML, not TOML. This row was briefly two, `.1c` and `.1d`, which named one exit twice: a typed field given the wrong type IS the Figment type-extraction failure |
| ENVFILE.8 | an already-listed env file rewritten with a `EF BB BF` prefix, first line `MIK7256_BOM_<uniq>=v`; reload and assert the overlay carries the unprefixed name | integration | negative | `dotenvy`'s iterator path does not strip the BOM, so without an explicit strip the overlay names the variable `\u{feff}MIK7256_BOM_<uniq>` |
| ENVFILE.9 | running watcher over a config naming an env file; edit the env file's value for a `${VAR}` a backend uses; assert the new value reaches the running backend's resolved config | integration | positive | the behaviour option B would have removed |
| ENVFILE.10a | reload adding an `env:` reference in each of the five forms in turn, value defined only in an already-listed env file; assert validation PASSES for all five | integration | negative | `validate_env_reference` and the inline agent-key path read the process at validation time, so today all five are rejected. Five forms, not one: the funnel covers four and the agent-key site stands alone, and a design that threads the overlay into the funnel only passes a one-form case |
| ENVFILE.10b | the capability-credential form of .10a, driven through the live `fetch_credential` on an accepted reload; assert the new value is in use with no restart | integration | positive | the one reader that resolves per call — the proof the publish reaches a runtime consumer |
| ENVFILE.10c | the four auth forms of .10a on an accepted reload, over a config patch that is BYTE-IDENTICAL to the running config so the only change is the env file's value; assert the outcome reports `restart_required`, names the changed key, and the resolved holder still carries the startup value | integration | negative | asserts the narrowing rather than the capability. A single criterion previously asserted .10b's outcome for all five, which the source check disproved: `ResolvedAuthConfig::try_from_config` runs once at startup and nothing rebuilds it. The byte-identical patch is what makes the case able to fail: with any auth FIELD edited, the tracked-section reporting that already exists reports a restart on its own, so the criterion went green while the env-file-only rotation it exists to catch went unreported |
| ENVFILE.10.1 | env file ONLY is edited — config bytes byte-identical — watcher fires a reload; assert the rotation is in use afterwards | integration | negative | `load_config_patch` returns `Ok(None)` on an empty patch and `reload_outcome_locked` returns early, so a publish hung off the non-empty branch never runs — the change's own success case |
| ENVFILE.19b | with `MCP_GATEWAY_FIREWALL_SKIP_KEYS` narrowed in an env file and the reload accepted, assert the input scanner applies the NEW exclusion set; and with a backend endpoint rotated in an env file, assert `config_scanner` discovers the rotated value | integration | positive | the two readers the source scan did not reach — one `std::env::var` outside the enumerated set, one `env::vars()` behind an aliased import. Behavioural, because a scan is what missed them |
| ENVFILE.10.4 | accepted reload of an env-file-only edit that rotates a key the running config resolved through one of the startup-only consumers, run once per holder the derived set contains, the derived set enumerated in the row so a dropped holder is visible at review
rather than at implementation — attestation mode, signing key and key id
(`wiring.rs:117-119`), the key id's second reader
(`gateway/server/mod.rs:591-592`), and the firewall exclusion set
(`input_scanner.rs:72`) — so a holder the reporting misses fails
here rather than in production; assert the outcome names the changed key, reports `restart_required`, does not say `no_changes`, and carries the value nowhere; then repeat with a NON-empty config patch in the same reload and assert the same reporting | integration | positive | the criterion's own case, and the reason it is not scoped to the empty patch: an operator rotating a compromised credential alongside any other config edit is the likelier reload, and reporting keyed on patch-emptiness would go quiet on exactly that one |
| ENVFILE.10.2 | accepted reload whose `apply_patch` reports not-fully-applied (registry shutdown latch), over a candidate whose env file rotates a credential; assert nothing is published | integration | negative | the shutdown abort is the last exit an accepted reload can take, and a publish placed above it would fire on a reload that never committed |
| ENVFILE.10.3 | a reload that FOLLOWS a successful path-adding reload: reload 1 adds `extra.env` to `env_files` and is published; reload 2 changes something unrelated; assert reload 2 still does not read `extra.env` | integration | negative | the list must come from `LiveConfig::running()`, not `get()`. Taken from `get()`, reload 2 activates an unvalidated file while `pending_restart_fields` still says a restart is required |
| ENVFILE.11 | candidate ADDS `extra.env` to `env_files`, defining `MIK7256_ADD_<uniq>` and a `${MIK7256_ADD_<uniq>}` reference; reload succeeds; assert the reference resolved empty, the variable is in neither the process nor the overlay, and a warn names the key and the file | integration | negative | an unvalidated file cannot activate a credential by being named. Positive twin is .5, the same fixture with the file already listed |
| ENVFILE.12 | two already-listed env files, the second containing `B=${A}` where the first defines `A`, and a third pair `C=$A` in the UNBRACED spelling; attempt a reload; assert it is REFUSED, the message names the file and the key `A`, no value appears in it, and nothing is published. Second half: `Config::load` on the same fixture at startup succeeds and resolves `B` | integration + unit | negative | today the reload succeeds and `B` silently carries whatever the process held since startup — a rotation of `A` that never reaches `B`. The startup half pins that the refusal is scoped to the reload path. The unbraced pair is what fails a scan written for `${K}` alone: `dotenvy` substitutes both (`parse.rs:171-213`), so accepting `$A` would leave the defect reachable by the shorter spelling |
| ENVFILE.12-inert | env files carrying `${K}` inside a `#` comment, inside a single-quoted value, and escaped, where `K` is a key those files define; in both the braced and unbraced spellings; assert the reload is ACCEPTED, and assert against `dotenvy`'s own parse of each fixture that it substitutes nothing there | integration | negative | the refusal must key on tokens `dotenvy` would substitute, not on the characters. The second assertion is what turns the case into an oracle rather than a restatement of our reading of the parser: a fixture we call inert that `dotenvy` in fact substitutes fails here instead of shipping as a silent miss. Without this case the cheapest implementation — a raw substring scan — passes .12 and refuses reloads over bytes that change no value |
| ENVFILE.13 | accepted reload after a key is REMOVED from an already-listed env file whose value the process still holds from startup; assert the reader fails rather than resolving the startup value, and still fails after a second accepted reload that touches nothing — the removal is durable only if each overlay inherits the previous owned set | integration | negative | the case that distinguishes an overlay that owns a key domain from one consulted first and then fallen through. A fall-through implementation passes every rotation case in this plan and serves a deleted secret forever |
| ENVFILE.14 | accepted reload rotating a name referenced as `{env.NAME}` through `SecretResolver`; assert the next resolution returns the new value | integration | positive | the second lazy runtime reader (`src/secrets.rs:82`), reached from webhook signing, secret injection and the executor. `fetch_credential` alone was the enumeration this plan shipped with, and it is not the whole set |
| ENVFILE.17 | an env file whose second line is malformed and whose third is a valid assignment; build the overlay and run `Config::load` over the same bytes; assert both keep the first pair and neither takes the third | unit (config) | negative | "warn and skip" reads naturally as skip-the-line-and-continue, which would publish a pair startup never applies — live until the next restart, gone after it. The startup half is the oracle, so the case cannot pass by agreeing with itself |
| ENVFILE.16 | a `runtime.profiles.*.env_keys` name supplied by an env file; rotate it through an accepted reload and launch a runtime child; assert the child receives the new value, and receives nothing for that name when the key is removed instead | integration | positive | `StdRuntimeCommandRunner::run` copies the name out of `std::env::var_os` (`src/runtime/provider.rs:651`); nothing writes the process any more, so without the overlay the child gets the startup value or the deleted secret. Third reader the enumeration missed |
| ENVFILE.15 | rotate a key in an already-listed env file through an accepted reload, then write an admin-UI edit that references it; assert the write validates | integration | positive | the regression the fix itself creates: the value now lives in the overlay and no longer in the process, so a write path validating against the process alone rejects a configuration that works. Passes trivially before the change, which is why it is paired with .13 rather than standing alone |

Two rules the design states but no criterion owns, pinned as one case each:

| case | level | type | asserts |
|---|---|---|---|
| the refusal is not keyed on file boundaries | integration + unit | negative | ENVFILE.12's fixture puts `A` and `B=${A}` in DIFFERENT files; this one puts both in the SAME file. Assert the reload is refused there too, and that startup still resolves `B` to `1`. `dotenvy`'s `apply_substitution` consults `env::var` first and its per-file table second (dotenvy 0.15.7, `parse.rs:260-273`), so the same-file case is the one that resolves correctly at startup and is refused anyway — the refusal keys on the set of keys the env files define, not on which file defines them. A rule keyed on file boundaries passes ENVFILE.12 and fails this |
| duplicate key across files | unit (config) | positive | first file `A=1`, second `A=2`; assert the overlay yields `2`, matching `from_path_override`'s later-file-wins precedence |
| the applied bytes are the validated bytes | integration (config_reload) | negative | build the overlay, then rewrite the env file before the commit runs; assert the PUBLISHED overlay carries the value the evaluation captured, not the value now on disk. A commit that re-reads the files passes every other case and fails this one |
| overlay precedence | unit (config) | positive | overlay entry wins over a process variable of the same name, matching `from_path_override` |
| every operator-declared reference resolves through the overlay | unit (source scan) | negative | `pub(crate)` buys nothing here: `src/config_reload/` is the same crate, so the startup loader stays nameable and the compile-time claim this row used to make could never fail. What is checkable is the reader set: a test walks the source, collects every `std::env::var`/`var_os` call site outside tests, and fails on any that is not either overlay-aware or on the named infrastructure allowlist (`PATH`, `HOME`, `TMPDIR`, `NO_COLOR`). The prefix exemption `MCP_GATEWAY_*` is gone: it is what let `FIREWALL_SKIP_KEYS` through the scan, and the design replaced it with named call sites for exactly that reason. A prefix the scan waves past is a reader the scan cannot see. It fails when a new reader is added and nobody thought about the overlay, which is the actual failure mode — a scan is weak against an alias and strong against the omission this change is about. Two further assertions ride on the same walk, because they are the same kind of claim: `std::env::vars_os` appears only in the whole-environment test binary, and `Config::load` appears nowhere in it — the process separation the parallelism note describes, checked rather than asked for. Residual, stated: an alias (`use std::env::var as v`, a helper wrapping the call) evades all three. Closing that needs every environment read behind a wrapper and a lint forbidding the direct call, which is a crate-wide change this one does not carry; recorded as an observation, not filed |

## Can any of these pass while broken?

- .1, .1b, .3, .7 assert an ABSENCE. An absence passes trivially if the env
  file is never read at all — a fixture that writes it to the wrong path
  passes every one. Each pairs with .2 or .4 over the SAME fixture shape,
  which proves the file is real and its variables land when applied. Without
  that pairing the negative cases are unfalsifiable, and .2's reversal is what
  makes the pairing available at the reload level rather than only at startup.
- .11 is an absence with a positive twin in .5: the same fixture with the file
  already listed must resolve, which is what proves the path list is the only
  difference. Without .5 it passes against code that reads no env file at all.
- .5, .9 and .10a fail if the overlay is never consulted; .6 fails if the overlay
  reaches Figment in the wrong order, and .18 if it reaches it with the wrong
  transformation; .2 and .10b fail if the commit-time
  publish is dropped. The five together fix the boundary from both sides. Any
  one alone can pass with the boundary in the wrong place — which is exactly
  what happened to the previous design, where every case then written passed
  against a design that broke `env:`.
- .8 cannot fail before the fix in a useful way — the code it tests does not
  exist. It is a retrofit against new code, so it needs the falsifier probe:
  build the overlay WITHOUT the BOM strip, run it, and show the assertion
  fails on the variable name. Written and shown failing, not asserted to fail.
- Every negative case asserts ONE absent sentinel, which cannot see a partial
  apply that stopped before that name. The env-file fixtures for `.1`, `.1b`,
  `.1c`, `.7`, `.7c` and `.10.2` therefore define three variables, and
  each case compares the full `std::env::vars_os()` set before and after
  against the snapshot taken at case start — equality, not the absence of one
  key. A failed reload that set two of the three passes the sentinel form and
  fails this one.
- The full-environment comparison is only sound if nothing else in the process
  mutates the environment concurrently, and the suite runs tests in parallel
  threads. Every case that asserts on a whole-environment snapshot lives in its
  own integration-test binary (`tests/env_files_on_failed_load.rs`), which
  `cargo test` runs as a separate process. Serialising within the shared unit
  binary would be the alternative and it is weaker: any test added later
  without the marker silently breaks the comparison.
- No test calls `std::env::set_var`, so none needs `#[allow(unsafe_code)]`.
  Only .4 and .6 need a value in the real process environment, and it gets
  there through `Config::load` on a startup-shaped fixture, which writes it
  inside `dotenvy` — the only path in the design that still writes the process
  at all. The workspace lint stays intact and the tests exercise the real apply
  path rather than a hand-rolled substitute.
- The suite runs threads in parallel, so the cases that write the process are
  separated by PROCESS rather than by a lock — a lock is a convention every
  later test has to know about. The rule is one line and it is mechanical: a
  case that reaches `Config::load`, or any other startup path, does NOT live
  in the whole-environment binary. An earlier draft of this bullet named .4
  and .6 as the only writers and was wrong twice over: .12's startup half and
  .13's fixture both need a value applied by a real startup load, and both had
  been placed beside the snapshot cases.
- That leaves three homes. `tests/env_files_on_failed_load.rs` holds only
  reload-driven cases, which cannot write the process at all, so their
  whole-environment comparisons are sound however many run at once.
  `tests/env_files_startup_precedence.rs` holds .6, which must write
  `MCP_GATEWAY_PORT` — a name figment fixes, so the test cannot suffix it away
  — plus .12's startup half and .13's fixture, none of which compares a whole
  environment. The config unit binary keeps .4 and .17, which write uniquely
  suffixed names that no other test reads.
- The separation is enforced by the source-scan case, not by this paragraph:
  it asserts that `std::env::vars_os` appears only in the whole-environment
  binary and that `Config::load` appears nowhere in it. A later test violating
  either half fails the scan instead of quietly making a snapshot flaky.
- .12 asserts a REFUSAL, which passes trivially against a reload that refuses
  for some other reason. The assertion is on the message naming the file and
  the key, and its startup half must SUCCEED over the same bytes — a blanket
  refusal fails that half.
- .10.1 is the change's own success case and has no pre-fix failure to show:
  the early return it exercises is reached today, and what is missing is the
  publish that does not yet exist. It is a retrofit and needs the falsifier
  probe — place the publish on the non-empty-patch branch, run it, and show the
  assertion fail.
- .9's positive half passes trivially if filesystem events do not work in the
  test environment at all. The assertion is on the resolved VALUE reaching the
  backend config, not on a reload being published — a published reload that
  changed nothing satisfies the weaker form.

## Seams

`expand_env_vars` is a private method with one call site
(`src/config/mod.rs:313`), so the overlay parameter is compiler-enforced
there — but a compiler guarantee is not a test, which is why .5, .6, .8 and
.10a drive the loader end to end rather than calling `expand_string` directly.
Validation is the second seam: `validate_env_reference`
(`src/config/mod.rs:651`) funnels four call sites and the agent-key path
(`:433`) stands alone, so .10a must cover both — a design that threads the
overlay into the funnel and forgets the inline site passes a one-form case and
fails on agent secrets in production.

The third seam is the publish, and it is the one with no compiler help at all.
`LiveEnv` is a shared cell reached by handle — one per gateway, one per test
fixture, never a static — so a reload path that forgets to publish, or
publishes on the wrong branch, still compiles and still passes every case that
only reads the resolved config. The cases that hold it are .2 (published on
the ordinary success path), .10.1 (published on the empty-patch early return),
.10.2 and .7c (NOT published on the two late aborts) and .1/.1b/.1c (not
published on the three early exits). One publish site reachable from every exit
is what makes that set pass together; any arrangement that satisfies a subset
is the bug this table exists to catch.

The fourth seam is the reader set, and it is the one that leaks over time.
Nothing about the type system says a new `std::env::var` call has to know the
overlay exists, and the enumeration this plan shipped with was already wrong
once: it named `fetch_credential` and missed `SecretResolver::resolve`
(`src/secrets.rs:82`), which resolves `{env.NAME}` on the webhook, injection
and executor paths. So the set is held mechanically by the source-scan row
rather than by the enumeration, and the behavioural cases hold its two ends —
.10b for the credential reader, .14 for the resolver.

The fifth is the owned key domain. An overlay that answers owned keys itself
and one that merely answers first are indistinguishable on every rotation
case in this plan; they differ only on a removal, which is .13. That case
carries the whole distinction, so it cannot be dropped as an edge.
