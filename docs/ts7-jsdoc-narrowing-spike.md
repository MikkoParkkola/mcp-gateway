# TypeScript 7 JSDoc narrowing

## Premise

The spike assumed `mcp-gateway/npm` and `trvl/npm` contained JSDoc annotations a TypeScript 7 release candidate could narrow. Both trees are install shims. `mcp-gateway/npm/run.js` and `trvl/npm/install.js` plus `trvl/npm/bin/trvl-mcp.js` have no `@type`, `@param`, or `@returns` annotations and no `tsconfig.json`.

## Recommendation

`skip`. There is no JSDoc surface for a TypeScript upgrade to improve. Installing a release candidate in CI would not change a consumer type-check.

## Remediation

| Pattern | Fixture | If a later package grows JSDoc |
|---|---|---|
| Truthiness narrow | `fixtures/truthiness.js` | Keep the truthy branch returning the narrowed string |
| `typeof` guard | `fixtures/typeof.js` | Narrow before reading `length` |
| Discriminated union | `fixtures/union.js` | Switch on `kind` before reading the payload |
| `@template` generic | `fixtures/template.js` | Return `T` unchanged |
| Nullable param | `fixtures/nullable.js` | Compare with `null` before use |

Re-run `node scripts/ts-upgrade/validate.mjs --ts-version <version>` when a stable TypeScript release claims new JSDoc narrowing. The harness writes `ts-upgrade-report.json` with `tsVersion`, the running `compilerVersion`, `commitSha`, and `recommendation` of `upgrade_now`, `wait_for_stable`, or `skip`. That recommendation describes the fixtures under the compiler that actually ran. It is `skip` when `--ts-version` does not match `tsc --version`. The migration decision for these npm trees stays `skip` until one of them grows JSDoc.
