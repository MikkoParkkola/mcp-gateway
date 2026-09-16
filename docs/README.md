# Documentation

Start with the [README](../README.md); this directory is the depth behind it.

## Using the gateway

| Document | Covers |
| --- | --- |
| [QUICKSTART](QUICKSTART.md) | First run, first backend, first tool call |
| [ARCHITECTURE](ARCHITECTURE.md) | How a request reaches a backend and comes back |
| [DEPLOYMENT](DEPLOYMENT.md) | Containers, Kubernetes, and the production posture |
| [OAUTH_CONFIG](OAUTH_CONFIG.md) | Authorizing backends that speak OAuth |
| [REMOTE_BACKENDS](REMOTE_BACKENDS.md) | Reaching backends that are not local processes |
| [WEBHOOKS](WEBHOOKS.md) | Inbound events |
| [OPENAPI_IMPORT](OPENAPI_IMPORT.md) | Turning an OpenAPI description into capabilities |
| [UPGRADING-4.0](UPGRADING-4.0.md) · [UPGRADING-3.0](UPGRADING-3.0.md) | What breaks between major versions, and what to do |

## Judging the gateway

| Document | Covers |
| --- | --- |
| [BENCHMARKS](BENCHMARKS.md) | The numbers, how they were measured, and where the model is optimistic |
| [OWASP_AGENTIC_AI_COMPLIANCE](OWASP_AGENTIC_AI_COMPLIANCE.md) | A scoped self-assessment, not a certification |
| [SECURITY_AUDIT](SECURITY_AUDIT.md) | Findings and their disposition |
| [spec-divergences](spec-divergences.md) | Where this gateway departs from the MCP specification, and why |
| [adr/](adr/) | The decisions that are settled, and what each one closed |

## Engineering record

`design/`, `requirements/` and `release/` are the working record of how the
above was built: dated design notes, release criteria and their evidence. They
are kept in the open so a claim can be traced to the run that supports it. They
are written for the people building the gateway, not for the people using it —
nothing here is required reading to run it.
