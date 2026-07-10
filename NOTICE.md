# NOTICE — licensing correction for versions 3.0.0–3.2.1

Versions **3.0.0 through 3.2.1** of mcp-gateway were published with package
metadata and artifacts indicating the **MIT License** for code that was intended
to be **Enterprise Edition** and licensed under **PolyForm Noncommercial 1.0.0**.
The whole 3.x line added enterprise features (multi-user identity, per-user
isolation, security governance, control plane, cost accounting, key server,
attestation, and more), and much of that shipped under the MIT default by
mistake.

**We cannot and do not revoke rights already granted for copies obtained under
MIT.** The MIT License is irrevocable and perpetual for copies already
distributed. If you obtained mcp-gateway 3.0.0–3.2.1 under MIT, your rights to
that copy are unchanged.

**Those versions are deprecated and should not be used as canonical licensing
guidance.** They have been withdrawn from active distribution channels where
possible (crates.io yank, deprecation notices on npm/Homebrew, container tags),
and are no longer the recommended or supported versions.

**Starting with version 3.3.0:**

- Files whose first line is `// SPDX-License-Identifier: MIT` are MIT-licensed.
- Every other file is licensed under PolyForm Noncommercial 1.0.0.
- Commercial use of the Noncommercial-licensed code (which is effectively the
  whole runnable gateway) requires a commercial license. See `COMMERCIAL.md`.

See [`LICENSES.md`](LICENSES.md) for the full model.
