# Trust Fabric roadmap

Trust Fabric is the set of features that let an operator decide which MCP
servers and tools an agent may use, for whom, and on what evidence. This page
lists what ships in 4.0.0 and what is not in 4.0.0 yet. Items in the second
list are not scheduled. They are listed so you can plan around them.

## Shipped in 4.0.0

| Area | What it does | Docs |
|---|---|---|
| Identity grants | A capability marked `metadata.exposure: personal` runs only for a caller whose identity, owner evidence and live grant all match. Without them the call is refused before it reaches the backend. Capabilities default to `shared`, so single-user setups keep working. Grants live in a local file, edited with `mcp-gateway identity grants`. | [identity_grants.md](../identity_grants.md) |
| Shadow server discovery | A passive, local scan that lists MCP servers found in client configs, environment hints and process metadata that the gateway does not manage. It does not start servers or call tools, and it changes gateway config only when asked to. | `mcp-gateway cap discover --shadow` |
| Runtime isolation planning | Plans how a backend should start (local process, Docker or Podman), with policy for mounts, environment variables and network access, preflight checks and an audit record. Stdio backends can be launched through a `docker run --rm` or `podman run --rm` bridge. | [provider_planner.md](../runtime/provider_planner.md) |
| TrustCard and CBOM | A short trust summary per MCP server plus a machine-readable bill of materials for its tools, prompts, resources, permissions and provenance. `tools/list` descriptors carry a small TrustCard digest reference. The metadata is advisory and generated locally. | [trustcard.md](../trustcard.md) |
| Catalog evaluation | Evaluates a candidate MCP server before you enable it: metadata completeness, schema drift against a stored baseline, tool-poisoning scan results, missing behavior annotations and broad permissions. It returns a score, a policy verdict and a remediation plan. It is advisory, and it calls only fixtures marked safe, and only on an isolated runtime. | [catalog_trust_lab.md](../catalog_trust_lab.md) |
| Control-plane view | A read-only inventory of servers, tools, trust evidence, runtime health and audit evidence, at `GET /ui/api/control-plane` and the `/ui#control-plane` tab. It checks role-based access. | [control_plane.md](../control_plane.md) |
| Context integrity | Tool results are classified and tagged before they reach the agent. Local presets only record what they would change. The team-shared and strict presets enforce, and `security.posture: hardened` raises a monitoring preset to enforcing. | [OWASP self-assessment](../OWASP_AGENTIC_AI_COMPLIANCE.md) |
| Kubernetes | A security-hardened Helm chart (non-root, seccomp, read-only root filesystem) and experimental (v1alpha1) CRDs. | [DEPLOYMENT.md](../DEPLOYMENT.md) |
| Protocol imports | Turns OpenAPI, Postman collections, selected GraphQL operations and OCI MCP package metadata into capability drafts that stay disabled until reviewed. `mcp-gateway cap import` keeps the direct OpenAPI path. | [OPENAPI_IMPORT.md](../OPENAPI_IMPORT.md) |
| Adaptive ranking | Deterministic ranking behind `gateway_search_tools` and Code Mode `gateway_search`. Relevance comes first, then safety, policy fit, grant status and runtime health. Explanations are available on request with `explain=true`. | [adaptive_ranking.md](../adaptive_ranking.md) |

## Not in 4.0.0

- **Grant and policy changes from the control plane.** Its write endpoints
  refuse with 409 and name where to make the change instead: the identity
  grants file for grants, gateway config for policy. The web UI is read-only.
- **Fleet-wide discovery.** Shadow discovery is local only and does not scan
  network ranges.
- **Container lifecycle for HTTP backends.** Runtime isolation launches only
  stdio backends in a container. HTTP container endpoints and port mapping are
  not supported.
- **Managed sandbox execution for catalog evaluation.** Start and stop
  orchestration through the runtime planner is not wired to evaluation.
  Scanner adapters for dependency audit, SBOM, signature verification and
  external MCP safety scanners are not included.
- **A Kubernetes operator.** Kubernetes deployment uses the Helm chart. A
  controller with a reconcile loop is deferred until there is demand for it.
