# Dependency Licenses (SBOM summary)

**Work:** mcp-gateway
**Generated:** 2026-07-12 via `cargo license` (machine-readable manifest:
[`dependency-licenses.tsv`](dependency-licenses.tsv), 426 crates).
**Purpose:** Confirm that third-party dependencies are compatible with a
PolyForm-Noncommercial-1.0.0 default plus a paid commercial-license offer, and
that none are relicensed under this project's Noncommercial terms.

## Bottom line

No dependency imposes a copyleft or source-disclosure obligation on this
project's first-party code, and no dependency is GPL / AGPL / SSPL / BUSL. The
tree is overwhelmingly permissive (MIT / Apache-2.0). A commercial,
source-available distribution is compatible with the dependency set, subject to
carrying each dependency's own notice.

## License family breakdown

| Family | Approx. count | Obligation | Compatible with NC + commercial? |
|---|---|---|---|
| Apache-2.0 OR MIT (and permissive multi-license) | ~264 | Notice / attribution | Yes |
| MIT | ~69 | Notice / attribution | Yes |
| Apache-2.0 (incl. WITH LLVM-exception, ISC combos) | ~25 | Notice; patent grant | Yes |
| Unicode-3.0 (ICU crates) | ~18 | Notice | Yes |
| ISC / BSD-2 / BSD-3 | ~15 | Notice | Yes |
| MIT OR Unlicense, permissive-OR-Zlib, 0BSD, CC0-1.0 | ~14 | Notice or none | Yes |
| CDLA-Permissive-2.0 (webpki-roots — data) | 3 | Notice (data) | Yes |
| **MPL-2.0** (`option-ext`) | 1 | **File-level** weak copyleft | Yes — obligation is limited to modifications of MPL files themselves; using the crate as a dependency does not affect first-party code |

`r-efi` appears with an LGPL option but is offered as `Apache-2.0 OR
LGPL-2.1-or-later OR MIT`; the permissive option is selected, so no LGPL
obligation attaches.

## Obligations to honor

1. **Notices** — permissive licenses (MIT / Apache-2.0 / BSD / ISC) require
   preserving copyright and license text. These are carried per Cargo's standard
   packaging; the release pipeline ships license files as assets.
2. **MPL-2.0** — if `option-ext`'s own source files are ever modified, those
   modifications must be made available under MPL-2.0. Using it unmodified as a
   dependency carries no such obligation on first-party code.
3. **No relicensing** — third-party crates retain their own licenses and are
   **not** covered by this project's PolyForm-Noncommercial default. The
   Noncommercial default scopes to first-party original material only.

## Regeneration

```
cargo license --tsv > docs/legal/dependency-licenses.tsv
```

Re-run at each release and before any commercial-license grant. `cargo deny` is
configured for CI enforcement of the allowed-license set.

## Standing

Not legal advice. A reasonable-diligence supply-chain review for counsel sign-off.
