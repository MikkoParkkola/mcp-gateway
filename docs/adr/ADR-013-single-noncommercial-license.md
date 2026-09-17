# ADR-013: Single Noncommercial license for the whole repository

- **Status**: Proposed, 2026-09-10
- **Supersedes**: ADR-011 (PolyForm-Noncommercial default with a minimal MIT core)

## Context

ADR-011 kept a small MIT core inside a Noncommercial-default repository. The
split was defensible on paper and expensive in practice.

It burdened every reader. A developer evaluating the project, a packager
building a distribution, and a downstream consumer vendoring a module each had
to answer "which license governs this file?" before they could answer anything
else — per file, for a repository of ~370 source files. The answer was not
derivable from the package metadata, which could only say `license-file`, so the
question had to be re-asked at every layer.

It also created a second source of truth. `.mit-core-allowlist` enumerated the
MIT paths, and CI checked it bidirectionally against the 71 file headers the
allowlist covered by the 4.0.0 cut. Two lists that must agree will eventually
disagree: every module move, split, or rename
was an opportunity for the allowlist and the headers to drift, and the CI gate
existed to catch a class of error that only existed because there were two
lists.

And the core was not why people adopt the gateway. The MIT surface was
deliberately narrow — protocol types, search, transforms, a validator, hashing,
`gateway-core` — generic building blocks with no enterprise logic. Adoption is
driven by the runnable gateway and its capability routing, all of which was
already Noncommercial. The MIT core bought reusability that few asked for, at
the cost of a licensing model everyone had to read.

## Decision

One license for the whole repository, effective **4.0.0**: every first-party
file is licensed under the PolyForm Noncommercial License 1.0.0 and carries an
affirmative `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header
below its copyright line. `.mit-core-allowlist` is removed. A first-party file
carrying any other identifier is an error, not a carve-out.

The headers stay affirmative rather than inferred from absence: an extracted
file loses the context that would have said which license governs it, and
counsel identified that as the enforceability gap.

Rights granted in earlier releases are not revoked. `LICENSE-MIT` stays in the
tree because it is the text those grants refer to; `NOTICE.md` records which
releases granted what.

## Consequences

- `gateway-core` and the other former MIT-core modules are no longer available
  to downstream projects on MIT terms going forward. Anyone who took them as
  MIT and uses them commercially keeps that right for the copies they received,
  but a 4.0.0-or-later copy of the same code requires commercial terms.
- Prior grants stand. Recipients of 3.0.0–3.2.1 (package-level MIT) and of the
  MIT-headered core files in the 3.x line from 3.3.0 onward keep their rights to
  those artifacts as distributed. This is not preventable and is not being
  contested.
- The CI gate simplifies to one identifier. `scripts/ci/check-license-headers.sh`
  no longer needs to reconcile an allowlist against headers, and there is no
  second list to keep in sync.
- Package metadata now names the license instead of pointing at a file.
  ADR-011 chose `license-file = "LICENSES.md"` because the `license` field
  cannot express per-file mixed licensing; with one license that reason is void.
  `PolyForm-Noncommercial-1.0.0` is a registered SPDX short identifier (verified
  against the SPDX license list, which also carries
  `PolyForm-Small-Business-1.0.0`), so the root crate and `crates/gateway-core`
  both carry `license = "PolyForm-Noncommercial-1.0.0"`, matching the file
  headers. An earlier revision of this decision used
  `LicenseRef-PolyForm-Noncommercial-1.0.0`; that prefix is reserved for licenses
  absent from the SPDX list and would have hidden the license from any tool that
  resolves identifiers. npm stays on `SEE LICENSE IN LICENSES.md`, which is a
  `LicenseRef` and names the same license the headers do. The
  misread-by-badges problem accepted in ADR-011 remains, but it is now a single
  wrong-looking label rather than a mixed model that badges cannot express at
  all.
- Commercial reusers of the former MIT core have to take commercial terms to
  stay current. That is the intended trade: the licensing model is now one
  sentence, and the price is losing the small open surface.
