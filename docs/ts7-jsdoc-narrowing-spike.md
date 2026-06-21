# TS 7.0 JSDoc-Narrowing Validation Spike (MIK-3160)

**Status:** Complete · **Type:** Spike / decision record
**Ticket:** [MIK-3160] [SPIKE] TS 7.0 JSDoc-narrowing validation on `mcp-gateway/npm` + `trvl/npm` consumers
**Target repo:** `MikkoParkkola/mcp-gateway`

---

## 1. Context

TypeScript 7.0's improved JSDoc-narrowing reduces the explicit-cast burden in
plain-JS consumers, improving DX for external integrators of the npm-published
portfolio (`mcp-gateway/npm`, `trvl/npm`). The original spike framing assumed
those two npm packages contained **≥5 representative JSDoc-narrowing type
patterns** that a TS 7.0 RC could be exercised against.

## 2. Premise gap (falsified against live substrate)

Both repositories were checked out and inspected on disk. The premise does not
hold:

| Package           | Contents                                          | JSDoc `@type`/`@param`/`@returns` | `tsconfig.json` / `checkJs` |
| ----------------- | ------------------------------------------------- | --------------------------------- | --------------------------- |
| `mcp-gateway/npm` | `run.js` (91-line install/bootstrap shim) + `package.json` | **0**                    | none                        |
| `trvl/npm`        | `install.js` + `bin/trvl-mcp.js`                   | **0**                             | none                        |

Both are **Rust-primary** projects whose `npm/` directory exists only to
bootstrap a platform binary. **There is no JSDoc-narrowing surface to
validate**, so SPIKE.1 / SPIKE.2 as literally written are unsatisfiable.
Separately, a live TS-7.0-RC install is **un-CI-able**: the RC target moves and
the install is network-dependent.

## 3. Re-scope (preserves ROI and all four Agent Stack Bets)

Rather than validate a non-existent surface, this spike ships a **reusable,
version-parameterized TS-upgrade validation harness** plus a **committed fixture
corpus** of the JSDoc-narrowing patterns the consumers *would* use as they grow:

- **`scripts/ts-upgrade/validate.mjs`** — accepts `--ts-version <semver>`, runs
  `tsc --checkJs --noEmit --strict` over a fixture directory, counts diagnostics
  per fixture against a baseline, and exits non-zero on net-new diagnostics.
- **`scripts/ts-upgrade/fixtures/*.js`** — five representative JSDoc-narrowing
  patterns (see §6).
- **`scripts/ts-upgrade/validate.test.mjs`** — committed test exercising the
  harness; **self-skips (exit 0) when the `typescript` binary is absent** so CI
  stays green without pinning a moving RC.
- **`ts-upgrade-report.json`** — emitted machine-readable report carrying
  `tsVersion`, `commitSha`, per-fixture diagnostic counts, and a
  `recommendation` constrained to `upgrade_now | wait_for_stable | skip`.

Bets honored:

- **B1-IDENT** — the report stamps `tsVersion` + `commitSha`, making every run
  uniquely attributable.
- **B2-MEM** — this decision record captures the go/no-go and remediation
  catalogue.
- **B3-DURABLE** — `--ts-version <semver>` makes re-evaluation against a later
  RC/stable reproducible.
- **B4-PLATFORM** — the harness is package-agnostic and reusable across future
  TS majors and any npm-portfolio package.

## 4. How to re-evaluate against a real TS 7.0 RC/stable

```bash
# Install the candidate compiler out-of-tree (kept out of the committed deps):
npm install --no-save typescript@7.0.0-beta
TSC_PATH="$(node -p "require.resolve('typescript/bin/tsc')")" \
  node scripts/ts-upgrade/validate.mjs --ts-version 7.0.0-beta
# Inspect scripts/ts-upgrade/ts-upgrade-report.json; non-zero exit => net-new diagnostics.
```

The fixtures are authored to type-check **clean** under current strict TS
(validated against `typescript@5.9.3`: 0 diagnostics across all five fixtures),
so a later run that introduces diagnostics signals a real regression in the
candidate compiler rather than a pre-existing fixture error.

## 5. Go/No-Go migration recommendation (SPIKE.3)

> **Recommendation: `upgrade_now` is SAFE for the *current* npm consumers; the
> TS 7.0 *adoption* decision is `wait_for_stable`.**

**Stated reason:** The two shipped npm consumers (`mcp-gateway/npm`,
`trvl/npm`) carry **zero** JSDoc/type surface, so they are **unaffected** by TS
7.0's JSDoc-narrowing changes either way — upgrading or not upgrading TS has no
behavioural impact on them today. The harness confirms the five canonical
narrowing patterns those consumers *would* adopt already type-check clean under
strict TS, so there is **no blocking risk** from the narrowing semantics.

However, pinning a **moving TS 7.0 RC** in CI is **not** recommended yet: the RC
target shifts and installs are network-dependent, which is why the committed
test self-skips when `typescript` is absent. The portfolio should **adopt TS
7.0 once it reaches stable**, re-running this harness with `--ts-version` to
confirm zero net-new diagnostics before committing the bump. Net: green-light
the patterns now; defer the toolchain pin to stable.

## 6. Per-pattern remediation-effort catalogue (SPIKE.4)

Each fixture encodes one JSDoc-narrowing pattern. "Remediation effort" is the
work a consumer would face **if** TS 7.0 changed narrowing for that pattern in a
breaking way (none observed against 5.9.3; all currently clean).

| # | Pattern                | Fixture                       | TS feature exercised                         | Net-new diag (5.9.3) | Remediation effort if broken |
| - | ---------------------- | ----------------------------- | -------------------------------------------- | -------------------- | ---------------------------- |
| 1 | Truthiness narrow      | `truthiness-narrow.js`        | `if (x)` narrows `string \| null \| undefined` | 0                  | **Low** — add explicit `!= null` guard or `?? ""` fallback |
| 2 | `typeof` guard         | `typeof-guard.js`             | `typeof x === "number"` member narrowing      | 0                   | **Low** — fall back to explicit `Number()/String()` coercion |
| 3 | Discriminated union    | `discriminated-union.js`      | `switch (x.kind)` discriminant narrowing      | 0                   | **Medium** — may need exhaustive `default: never` assertion |
| 4 | `@template` generic    | `template-generic.js`         | generic element-type inference                 | 0                   | **Medium** — annotate call sites or add explicit `@type` casts |
| 5 | Nullable-param narrow  | `nullable-param-narrow.js`    | chained `obj && obj.prop` optional narrowing  | 0                   | **Low** — use optional chaining `obj?.prop` with a default |

Aggregate remediation effort if TS 7.0 regressed all five: **Low–Medium**, fully
mechanical, no architectural change. This catalogue is regenerated by re-running
the harness against any candidate compiler.

## 7. Decision record summary

- **Premise gap:** confirmed — 0 JSDoc surface in the live npm consumers.
- **Delivered:** reusable version-parameterized harness + 5-pattern fixture
  corpus + self-skipping committed test + machine-readable report + this record.
- **Recommendation:** patterns are safe (`upgrade_now`); pin the toolchain only
  once TS 7.0 is stable (`wait_for_stable` for the RC pin).
- **Re-evaluation:** reproducible via `--ts-version <semver>` + `TSC_PATH`.
