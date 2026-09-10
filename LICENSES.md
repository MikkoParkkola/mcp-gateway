# Licensing

mcp-gateway is licensed under the **PolyForm Noncommercial License 1.0.0**.

## The rule

- **Every first-party file in this repository is licensed under the PolyForm
  Noncommercial License 1.0.0** (see
  [`LICENSE-NONCOMMERCIAL`](LICENSE-NONCOMMERCIAL)).
- Every such file carries a copyright line
  (`// SPDX-FileCopyrightText: <year> Mikko Parkkola`) immediately above an
  explicit `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header.

The header is affirmative on purpose: counsel flagged "absence means
Noncommercial" as the enforceability gap, because a file extracted from the
repository loses the context that would have said so. There is no second
license and no allowlist — a first-party file carrying any other identifier is
an error, not a carve-out, and CI (`scripts/ci/check-license-headers.sh`) fails
on it.

## Scope

The Noncommercial license applies to **first-party material authored for
mcp-gateway and owned by Mikko Parkkola**. It does **not** silently relicense:

- **Third-party material** — vendored code, dependencies, and any file carrying
  its own upstream license or copyright, which remains under its own terms.
- **Generated files** — anything produced by a build or codegen step, governed
  by the license of its generator/inputs.
- The license texts themselves (`LICENSE`, `LICENSE-MIT`,
  `LICENSE-NONCOMMERCIAL`), which are the standard license documents.

Any such out-of-scope path is recorded in
[`.license-scope-exclude`](.license-scope-exclude). The repository currently
contains no vendored or generated source files (no `@generated` markers, no
`build.rs`), so that list is empty today; it exists so the boundary stays
explicit if third-party material is ever added.

## What that means in practice

- **Noncommercial and personal use** of the whole project (including running the
  gateway) is free under PolyForm-Noncommercial.
- **Commercial use** — using the gateway inside a business, in a paid product, or
  as part of a commercial service — requires a **commercial license**. This
  covers the whole repository, including the generic building blocks (`protocol`,
  `semantic_search`, `transform`, `projection`, `validator`, `skills`,
  `capability/schema_validator`, `capability/hash`, `error.rs`, and the
  `gateway-core` crate) that earlier releases shipped under MIT headers. See
  [`COMMERCIAL.md`](COMMERCIAL.md).

## Package metadata

`PolyForm-Noncommercial-1.0.0` is a registered SPDX short identifier, so both
crates carry it directly: `license = "PolyForm-Noncommercial-1.0.0"` in the root
`Cargo.toml` and in `crates/gateway-core/Cargo.toml`, matching the identifier in
every file header. `npm/package.json` carries `"SEE LICENSE IN LICENSES.md"`,
which points readers at this file.

The license is not OSI-approved, so badges and scanners that equate
"OSI-approved" with "recognised" will flag it as non-standard. That is a
statement about openness, not about whether the identifier is valid. The file
headers, `LICENSE-NONCOMMERCIAL`, and this document are authoritative.

## History

Versions **3.0.0 through 3.2.1** were published with package metadata
indicating MIT for code that is Noncommercial from v3.3.0 onward. From v3.3.0
onward in the 3.x line, a small set of core files shipped under MIT headers;
from **v4.0.0** onward there is no MIT core. See [`NOTICE.md`](NOTICE.md) for
what was granted in which releases. We cannot and do not revoke rights already
granted for copies obtained under MIT.
