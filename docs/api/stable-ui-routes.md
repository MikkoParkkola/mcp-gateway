<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Stable UI API routes

> The listed methods and path templates are stable. Unlisted routes are unstable by default.

```text
GET /ui/api/status — Gateway health and the caller's access.
GET /ui/api/overview — Overview of gateway activity and backend health.
GET /ui/api/keys — Configured API keys and their last use, without secrets.
GET /ui/api/activity — Recent activity from the transparency logs.
GET /ui/api/decisions — Decisions awaiting an administrator.
GET /ui/api/refusals — Recent refused administration changes.
GET /ui/api/tools — Available tools and their schemas.
POST /ui/api/reload — Reload the gateway configuration.
GET /ui/api/events/dead-letters — List failed event deliveries.
POST /ui/api/events/dead-letters/{id}/replay — Queue one failed event delivery again.
POST /ui/api/events/dead-letters/replay — Replay a subscription's failed deliveries with all=1 and subscription query parameters.
POST /ui/api/backends/{name}/revive — Reset a backend's circuit breaker and restart its transport.
```
