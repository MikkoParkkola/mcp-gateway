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
`LICENSE-NONCOMMERCIAL`). The additional nonprofit permission below supplements
that license; these examples do not otherwise expand or narrow its definition.
Where an example and the license text differ, the license text governs. If your
use is genuinely noncommercial under that license, no commercial
license is needed; if you are unsure, ask (contact below).

## Standard commercial license

The standard license covers **one company or organization and one named Mikko
Parkkola project**. Here, a named project means a product such as `mcp-gateway`,
`nab`, or `trvl`; it does **not** mean each of your applications, repositories,
agents, or deployments. Buying a license for `mcp-gateway` does not license the
other projects.

| License | Eligibility | GitHub Sponsors | Direct invoice |
| --- | --- | --- | --- |
| Small business | One organization with no more than five people | USD 100/month | EUR 100/month |
| Organization | One organization, without a headcount limit | USD 500/month | EUR 500/month |

The small-business headcount is the total number of people working in the
organization, including working owners, employees, and regular contractors;
it is not the number of gateway users. Each license covers one legal entity
or sole proprietorship. Separate subsidiaries and affiliates are not included.
If the organization grows beyond five people, use the Organization license
from the next monthly renewal.

GitHub Sponsors charges in **USD**. The **EUR** prices are separate direct-invoice
offers, not currency conversions. Contact the licensor to arrange an invoice
before relying on that purchase route.

Both standard licenses:

- Cover routine internal business use, private forks, wrappers, private
  integrations, and shared internal services for the licensed organization
  during the paid license period.
- Include the same software features. There are no license-imposed limits on
  internal users, applications, environments, deployments, MCP servers, tools,
  agents, or calls. Small-business eligibility still depends on the
  organization's total headcount. Hardware, model, and third-party service
  costs remain yours.
- Require you to identify the licensed organization and named project. After
  choosing a commercial-license tier, email **mikko.parkkola@iki.fi** with the
  organization's legal name, your sponsoring GitHub account, and the product
  name (`mcp-gateway`). A project-tagged link helps attribution but does not
  replace these details.
- Do not include support, SLA, custom development, indemnity, trademark rights,
  sublicensing, resale, access to unpublished repositories, or the right to
  offer `mcp-gateway` as a hosted or managed service to third parties unless
  separately agreed in writing.

Canceling renewal does not shorten a period already paid for. When the paid
period ends, commercial use must stop unless another applicable license or
written agreement permits it. Uses already permitted by the noncommercial
license remain permitted.

Existing sponsors retain the benefits promised for their existing tier, and
existing written commercial agreements continue to govern. These offers do
not remove those commitments or earlier MIT rights.

## Free use and optional support

Noncommercial use and the nonprofit, educational, public-research, government,
and other public-benefit uses permitted by `LICENSE-NONCOMMERCIAL` remain free.
The licensor additionally grants non-profit organizations permission to use the
software at no charge: use by a non-profit organization is a permitted purpose
under `LICENSE-NONCOMMERCIAL`, subject to that license's other conditions. This
additional permission does not narrow any rights that license already grants.
They use the same software, including its security and context-engineering
features. No sponsorship is required for those permitted uses.

The Coffee (USD 5 one-time), Supporter (USD 5/month), and Sustainer
(USD 25/month) tiers are optional contributions to maintenance. They do not
purchase a commercial license, support, an SLA, or custom work. Custom support
contributions also do not grant commercial rights unless separately agreed
in writing. Choose a commercial-license tier when commercial permission is
required.

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

- **Buy a standard license or contribute optional support:**
  https://github.com/sponsors/MikkoParkkola?metadata_project=mcp-gateway
- **Custom terms, annual invoicing, procurement, resale, or licensing
  questions:** email **mikko.parkkola@iki.fi**.

Licensor: Mikko Parkkola, copyright holder of the original `mcp-gateway` work.
