# Commercial Use

`mcp-gateway` is licensed under the **PolyForm Noncommercial License 1.0.0** (as
of v4.0.0).

- Every first-party file in the repository is Noncommercial and carries an
  explicit `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header.
  There is no second license and no allowlist (see `LICENSES.md`).
- Releases before v3.3.0 were published with MIT metadata for code now licensed
  as Noncommercial, and v3.3.0 onward in the 3.x line shipped a small MIT core
  under per-file MIT headers. Those copies stay MIT for their recipients (a
  granted license cannot be revoked), but the 3.0.0–3.2.1 releases are
  deprecated and there is no MIT core from v4.0.0 onward. See `NOTICE.md`.

**Running the gateway commercially requires a commercial license.** The whole
project — dispatch, transport, backend management, ranking/authorization, the
capability registry/engine, identity, security, governance, cost, deployment,
and the generic building blocks that were MIT in the 3.x line — is
Noncommercial.

Examples that require a commercial license:

- A company runs the gateway (in any configuration) internally or in a product.
- A company uses the ranking, capability, identity, security, cost, governance,
  or control-plane code in a business system.
- Noncommercial-licensed code is forked, wrapped, modified, or copied into a
  business system.
- Noncommercial-licensed code is run as a hosted, shared, or managed MCP gateway service.
- Noncommercial-licensed code powers a paid product, SaaS, agent platform, consulting deliverable, or internal business platform.

These examples are **illustrative**. What counts as noncommercial (and therefore
free) is defined by the **PolyForm Noncommercial License 1.0.0** text itself (see
`LICENSE-NONCOMMERCIAL`); this document does not expand or narrow that
definition. Where an example and the license text differ, the license text
governs. If your use is genuinely noncommercial under that license, no commercial
license is needed; if you are unsure, ask (contact below).

## Standard commercial license

Companies can buy a standard commercial-use license through GitHub Sponsors:

- EUR 500/month per named project.
- Covers one company or organization using `mcp-gateway` Noncommercial-licensed code while sponsorship remains active.
- Covers routine internal business use, private forks, wrappers, private integrations, and shared internal services for that organization.
- Requires the sponsoring company to identify the licensed project, such as `mcp-gateway`, in the sponsor note or by email.
- Does not include support, SLA, custom development, indemnity, trademark rights, sublicensing, resale, or the right to offer `mcp-gateway` as a hosted or managed service to third parties unless separately agreed in writing.

The standard license is intended to be simple enough for normal team, department, or manager-level purchasing. It is not a blanket license for all Mikko Parkkola projects.

## Custom commercial terms

Custom terms are available for larger or unusual deployments, including:

- Multiple projects or portfolio-wide use.
- External-facing SaaS, hosted, managed-service, or resale use.
- Redistribution to customers, subsidiaries, contractors, or channel partners.
- High-scale deployments, regulated environments, procurement-specific contract terms, indemnity, support, SLA, or custom development.
- Strategic partnerships, revenue share, attribution plus upstream collaboration, or annual invoicing.

## Future modules

New features are licensed under PolyForm Noncommercial 1.0.0 like the rest of the repository, including features that are primarily valuable for enterprise governance, identity, audit, cost control, security policy, hosted operations, multi-tenant service operation, or commercial platform integration.

This does not change the MIT license for the earlier releases that were
distributed under MIT — neither the 3.0.0–3.2.1 packages nor the MIT-headered
core files in the 3.x line from v3.3.0 onward.

## Contact

- **Buy a standard license:** https://github.com/sponsors/MikkoParkkola
- **Custom terms, annual invoicing, procurement, resale, or licensing
  questions:** email **mikko.parkkola@iki.fi**.

Licensor: Mikko Parkkola, copyright holder of the original `mcp-gateway` work.
