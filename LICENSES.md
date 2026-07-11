# Licensing

mcp-gateway uses **mixed, per-file licensing**.

## The rule

- Files whose first line is `// SPDX-License-Identifier: MIT` are licensed under
  the **MIT License** (see [`LICENSE-MIT`](LICENSE-MIT)).
- **Every other file is licensed under the PolyForm Noncommercial License 1.0.0**
  (see [`LICENSE-NONCOMMERCIAL`](LICENSE-NONCOMMERCIAL)). This is the
  **default** — absence of an MIT header means PolyForm-Noncommercial.

Every MIT-licensed file also carries a copyright line
(`// SPDX-FileCopyrightText: <year> Mikko Parkkola`) above the MIT identifier,
and every Noncommercial file carries the same copyright line above an explicit
`// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header. The license is
affirmative on every file, not inferred from absence.

## Scope of the default

The Noncommercial default applies to **first-party material authored for
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
  as part of a commercial service — requires a **commercial license** for the
  Noncommercial-licensed files, which is effectively the whole runnable gateway.
  See [`COMMERCIAL.md`](COMMERCIAL.md).
- The **MIT core** is a small set of simple, self-contained, generic building
  blocks with no enterprise-specific logic: the MCP protocol types (`protocol`),
  natural-language tool search (`semantic_search`), response shaping and
  transforms (`projection`, `transform`), the MCP-server design validator
  (`validator`), the capability→skill bridge (`skills`), generic capability
  JSON-schema validation and file hashing (`capability/schema_validator`,
  `capability/hash`), the foundational error type (`error.rs`), and the
  `gateway-core` crate (pure discovery/routing primitives). Anything an
  enterprise needs — the runnable gateway, ranking/authorization, the capability
  registry/marketplace, the capability definition + execution engine, identity,
  security, governance, deployment — is Noncommercial. The MIT core is building
  blocks; it is **not** a runnable free-for-commercial gateway.

The precise MIT-core paths are listed in [`.mit-core-allowlist`](.mit-core-allowlist)
and enforced in CI (`scripts/ci/check-license-headers.sh`).

## Why per-file, not a single package license

The commercial/enterprise logic (multi-user identity, isolation, security
governance, control plane, cost, attestation, key server, deployment) is woven
through the runtime, so a single package-level license would be wrong for at
least some files. Cargo's `license` field cannot express per-file mixed
licensing, so the crate uses `license-file = "LICENSES.md"`.

## History / correction

Versions **3.0.0 through 3.2.1** were published with package metadata indicating
MIT for code now licensed as Noncommercial from v3.3.0 onward. See
[`NOTICE.md`](NOTICE.md) for the correction. We cannot and do not revoke rights
already granted for copies obtained under MIT; those versions are deprecated.
