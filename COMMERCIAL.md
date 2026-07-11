# Commercial Use

`mcp-gateway` uses **mixed, per-file licensing**, and the default is Noncommercial (as
of v3.3.0).

- The default license is **PolyForm Noncommercial 1.0.0**. Every source file is
  Noncommercial unless its first line is `// SPDX-License-Identifier: MIT`.
- Only a small **MIT core** of simple, generic building blocks is MIT (listed in
  `.mit-core-allowlist`; see `LICENSES.md`).
- Releases before v3.3.0 were published with MIT metadata for code now licensed
  as Noncommercial; those copies stay MIT (a granted license cannot be revoked)
  but are deprecated. See `NOTICE.md`.

**Running the gateway commercially requires a commercial license.** The runnable
gateway — dispatch, transport, backend management, ranking/authorization, the
capability registry/engine, identity, security, governance, cost, deployment —
is Noncommercial. The MIT core is reusable building blocks, not a runnable
free-for-commercial gateway.

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

## Future Noncommercial-licensed modules

New features that are primarily valuable for enterprise governance, identity, audit, cost control, security policy, hosted operations, multi-tenant service operation, or commercial platform integration may be added as Noncommercial-licensed files under PolyForm Noncommercial 1.0.0.

This does not change the MIT license for existing MIT releases or for core gateway files that remain MIT.

## Contact

- **Buy a standard license:** https://github.com/sponsors/MikkoParkkola
- **Custom terms, annual invoicing, procurement, resale, or licensing
  questions:** email **mikko.parkkola@iki.fi**.

Licensor: Mikko Parkkola, sole copyright owner of `mcp-gateway`.
