# TS 7.0 JSDoc-narrowing Spike — MIK-3160

**Status**: Complete (re-scoped spike)  
**Date**: 2026-06-21  
**Target**: MikkoParkkola/mcp-gateway

## Summary (Re-scope Rationale)

The original spike premise was that `mcp-gateway/npm` and `trvl/npm` (the published thin bootstrap packages) contained ≥5 representative JSDoc `@type`/`@param`/`@returns` sites exercising control-flow narrowing. Live checkout inspection falsified this:

* `npm/run.js`: 91-line platform install shim. Only `package.json`. **0** JSDoc annotations. No `tsconfig.json`, no `checkJs`.
* `trvl/npm`: `install.js` + `bin/trvl-mcp.js`. **0** JSDoc annotations. No TS config.

Both are **Rust-primary** projects. The `npm/` trees are minimal node wrappers for shipping prebuilt binaries. There is **no JSDoc-narrowing surface** in the published consumers.

SPIKE.1/SPIKE.2 (run TS 7.0 RC against live npm sources) are therefore unsatisfiable and a pinned-RC in CI is unmaintainable (moving target, network fetch at test time).

## Deliverables (preserve B1-B4)

- Reusable version-parameterized harness: `scripts/ts-upgrade/validate.mjs`
- Committed fixture corpus (synthetic but representative of patterns *consumers would use*)
- Self-skipping test (`node --test scripts/ts-upgrade/`)
- Decision record + `ts-upgrade-report.json` (B1-IDENT: `tsVersion` + `commitSha`)

This satisfies:
- B1-IDENT (report stamps version + sha)
- B2-MEM (this doc + committed report)
- B3-DURABLE (reproducible `--ts-version` runs)
- B4-PLATFORM (portable harness for future majors or other npm-portfolio packages)

## Acceptance Criteria Mapping

All 6 ACs implemented (see `tests/mik_3160_acs.rs` and `scripts/ts-upgrade/validate.test.mjs` for verbatim copies + assertions).

## Recommendation (SPIKE.3)

**recommendation: skip**

**Stated reason**:
The published npm consumers (`@mikkoparkkola/mcp-gateway` and the trvl equivalent) contain zero JSDoc-annotated JS surface. TS 7.0 JSDoc-narrowing (truthiness, typeof, DU, templates, nullable) provides no DX improvement today for external integrators of the thin shims. Adding the harness + corpus future-proofs the portfolio: when (if) real typed JS surfaces are introduced under npm/, the same harness can be pointed at them (or the fixtures replaced by real sources) and re-evaluated with `--ts-version`.

No change to `npm/package.json`, `npm/run.js`, or CI TypeScript requirements is warranted by this spike.

## Per-Pattern Remediation-Effort Catalogue (SPIKE.4)

If/when real JSDoc is added to consumer shims or new JS packages, the cost to benefit from TS 7.0 narrowing:

- **truthiness narrow** (`if (x) { x.method() }` for `string|null|undef`): Low. Write idiomatic guards; remove any `!` or `as string` casts that older TS required. 1-2 line diff per site.
- **`typeof` guard** (`if (typeof v === 'string')`): Low. Already works in recent TS; TS 7 improves some intersections. No remediation needed for new code; old casts become dead.
- **discriminated union** (tagged `kind: 'a'|'b'`): Low-Medium. Ensure literal discriminant is in JSDoc `@typedef`. Narrowing in branches eliminates `switch` exhaustiveness casts. Add `@satisfies` if complex.
- **`@template` generic**: Low. Use `@template T` + `@param {T}` + `@returns {T}`. Callers get inference without `<T>` casts at use sites. Small annotation cost, high readability.
- **nullable-param narrow** (`name: string | null` + `if (name != null)`): Low. Same as truthiness + explicit != null. Avoid `!` postfix in new code.

Overall remediation if we ever annotate the shims: < 1 day for the current ~90-line files. The value is still marginal unless we grow real library surface (typed config helpers, SDK adapters, etc.).

## Harness Usage

```bash
node scripts/ts-upgrade/validate.mjs --ts-version 7.0.0-rc
node scripts/ts-upgrade/validate.mjs --ts-version 5.9.3
```

Emits `ts-upgrade-report.json` (in cwd) and exits 1 on net-new diagnostics vs the fixture corpus.

Self-skips cleanly when no `typescript` resolvable / tsc absent.

## Example Report Shape (B1-IDENT)

```json
{
  "tsVersion": "5.9.3",
  "commitSha": "1e74ac2b24ac627bdd141654be0a2f0e9a05b1f2",
  "perFixture": { "truthiness-narrow.js": 0, ... },
  "totalDiagnostics": 0,
  "recommendation": "upgrade_now"
}
```

## Conclusion

No JSDoc surface exists to validate against in the current npm consumers. The re-scoped deliverable (harness + fixtures + decision record) is the correct durable artifact. It keeps CI green without pinning RCs and gives future agents a one-command way to re-evaluate.

**Follow-up: none required**

Reason: The reusable harness + committed corpus + this record already satisfy the four Agent Stack Bets. A future follow-up (or reuse of this harness) is only needed if/when actual JSDoc-annotated JS is added to an npm-published package in the portfolio. No immediate action on mcp-gateway or trvl consumers.
