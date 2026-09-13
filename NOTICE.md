# NOTICE — MIT grants in earlier releases

mcp-gateway is licensed under the PolyForm Noncommercial License 1.0.0 (see
[`LICENSES.md`](LICENSES.md)). Two earlier sets of releases distributed code
under the MIT License. This notice records exactly what was granted in which
releases, and what that means now.

**Rights already granted under MIT are not revoked.** The MIT License is
irrevocable and perpetual for copies already distributed. Nothing in the
current licensing changes the terms on which you received an earlier release.

## Versions 3.0.0 through 3.2.1 — MIT at the package level

Versions **3.0.0 through 3.2.1** were published with package metadata and
artifacts indicating the **MIT License** for the whole distribution. If you
obtained mcp-gateway 3.0.0–3.2.1 under MIT, your rights to **those exact
artifacts, as distributed in those versions,** are unchanged. You may continue
to use, modify, and combine that code under MIT, and combining it with other
work does not retroactively change its license.

Versions 3.0.0–3.2.1 are **deprecated** and are provided **AS IS**, without
warranty, support, security updates, or maintenance. As part of the v3.3.0
release they were withdrawn from active distribution channels where possible
(crates.io yank, deprecation notices on npm and Homebrew, container tag
deprecation) so that new installs resolve to the current release. They are no
longer the recommended or supported versions.

## Version 3.3.0 onward in the 3.x line — MIT headers on a core file set

Beginning with version **3.3.0**, mcp-gateway used a mixed, per-file licensing
model: the repository default was PolyForm Noncommercial 1.0.0, and a small
**MIT core** of generic building blocks carried
`// SPDX-License-Identifier: MIT` in each file's header. That model applied to
every 3.x release from 3.3.0 onward. The core file set is listed under
"MIT core (the entire open surface)" in
[`docs/adr/ADR-011-license-nc-default-flip.md`](docs/adr/ADR-011-license-nc-default-flip.md);
the `.mit-core-allowlist` file that enumerated it was removed in 4.0.0.

The MIT grant on those files is a per-file grant, not a package-level one: it
covers the specific files that carried an MIT header **as distributed in the
release you received**, and not the rest of that release, which was already
Noncommercial. Those files stay MIT for their recipients. You may continue to
use, modify, and combine them under MIT.

This is narrower than the 3.0.0–3.2.1 grant, where the package as a whole was
labeled MIT.

## Version 4.0.0 onward — a single license, no MIT core

From **4.0.0** onward there is no MIT core. Every first-party file in the
repository carries
`// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`, including the files
that were MIT in the 3.x line. Commercial use of any of it requires a
commercial license — see [`COMMERCIAL.md`](COMMERCIAL.md).

`LICENSE-MIT` remains in the tree because it is the license text those earlier
grants refer to. It does not license anything in the current tree.

## Which license applies to the copy you have

The releases are the boundary, and the 3.x and 4.x lines were maintained in
parallel for a period, so a release date does not settle it. **Check the header
in the copy you actually received.** A file that carries
`// SPDX-License-Identifier: MIT` in the artifact you obtained is MIT for that
copy; a file that carries
`// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` is Noncommercial. For
3.0.0–3.2.1, where the grant was made in the package metadata rather than in
file headers, the package metadata of the artifact you received governs.

See [`LICENSES.md`](LICENSES.md) for the current model.
