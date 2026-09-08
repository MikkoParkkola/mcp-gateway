# OpenWebUI browser identity bridge — production contract

Status: implementation contract selected by release coordinator; independent review and product acceptance remain required. This supplements the approved personal-accounts design without closing C01–C07/A07.

## Mechanism and evidence

Use a dedicated same-origin HTTPS browser route and server-side verification of the existing OpenWebUI session. A tool-created journey link is never authentication. The isolated 2026-09-08 proof used real OWUI 0.9.6 signin/session lookup and real browsers: A confirmed exactly once; authenticated B, anonymous access and replay were refused. Cookies were Secure/HttpOnly/SameSite=Lax. It used a Python harness and an ephemeral SPKI-pinned certificate; it does not prove gateway routes, public deployment TLS, OAuth, encrypted storage or canonical Rust identity mapping.

## Identity verification boundary

A browser verifier is bound at startup to one configured installation ID, one HTTPS public origin and one fixed OWUI session endpoint. Require exact `/api/v1/auths/`, no userinfo/query/fragment. Upstream HTTPS is allowed; HTTP is allowed only for a literal loopback IP used behind the same host proxy. Never accept an endpoint or principal from browser input. Never follow upstream redirects. Bound connect/total timeout and response bytes (64 KiB); never log request cookies or raw response/error text.

Read only the exact `token` cookie, preserving duplicate detection across every Cookie header. Missing, duplicate, malformed or non-ASCII credential values refuse before network access. Forward only that cookie to the fixed endpoint, not other cookies, Authorization, client headers or an MCP route. A non-200 response refuses. Parse a nonempty string `id` from authenticated JSON; ignore profile, role, email, token and other fields. The real OWUI session endpoint owns session-expiry validation; revalidate at confirmation, never infer a logged-in browser from a copied MCP assertion.

Construct the same VerifiedIdentity issuer/subject as the signed-header adapter by sharing its existing namespaced_issuer helper and using VerifiedIdentity.stable_actor_id(). Do not introduce an `owui:...` principal string. Return a distinct VerifiedBrowserIdentity type whose constructor remains inside this verifier. Its diagnostic output must omit session material and profile data.

## Hosted route integration required after verifier

Explicit configuration only; absent bridge config installs no routes and reads no new secrets. The browser routes have their own authentication and must not weaken the normal MCP/API-key middleware. Require configured HTTPS origin at startup; never disable Secure cookies to accommodate HTTP.

GET start authenticates the browser, compares canonical principal to the journey owner and presents a confirmation form. It does not bind or consume the journey. POST confirmation requires exact Origin, pre-existing server-side browser challenge, synchronizer CSRF, one value for every protected cookie and a newly verified same principal. Rotate the gateway browser session and bind the journey atomically. Callback must check the bound session and atomically consume state before provider exchange. Cookies: Secure, HttpOnly, SameSite=Lax; scoped to `/accounts`; TTL no greater than the five-minute journey lifetime. Do not forward OWUI session material to the provider.

Encrypted journey state, PKCE S256, keyed opaque-state digests, owner/config/generation fencing, expiry, cancellation, capacity and audit behavior remain as specified in the approved account design. This verifier alone is not a completed hosted-consent feature.

## Delivery slices and acceptance

1. Browser verifier and real HTTP tests: duplicate/malformed cookies cause zero upstream requests; only token forwarded; timeout/oversize/redirect/non-200/invalid ID refuse; same installation yields the existing principal namespace, distinct installations remain distinct.
2. Explicit config and gateway browser routes with same-origin/CSRF/session enforcement; actual router tests must consume the verifier. No merge of test-only unused helpers as finished production wiring.
3. Encrypted journey lifecycle and provider callback commit using existing custody CAS/fences.
4. Real browser against gateway and actual OWUI UI, then Google connect/use/refresh/revoke/cancel/restart acceptance. The Python proof does not replace these cases.

Deployment: preserve existing Spark services and Tailscale routes. Choose and validate the dedicated HTTPS origin/proxy mapping before live rollout; do not assume the inspected 443/8443 routes expose OWUI.
