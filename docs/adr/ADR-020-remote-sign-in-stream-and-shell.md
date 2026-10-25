# ADR-020: Remote sign-in, the live stream, and how the shell is delivered

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.4 and ADR.7, decided together because each constrains the other); unblocks U3 (MIK-8856, live stream), UI1 (MIK-8875, shell) and UI12 (MIK-8886, progressive enhancement)
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

| # | Fact | Where |
|---|---|---|
| F1 | The browser sign-in cookie comes from a one-time dashboard link that opens only from a loopback peer; on a concrete network address the link is refused. | `src/gateway/ui/session.rs:154-167` |
| F2 | The other path is the API key typed into the page and held in page memory, sent as a bearer header; a reload signs out. | api-gaps.md section 3 "Sign-in today" |
| F3 | `EventSource` cannot send an `Authorization` header, so a bearer-only client cannot open an SSE stream. | WHATWG HTML, EventSource constructor |
| F4 | The new shell is one static document and content-hashed assets, unauthenticated like `/ui` and holding no gateway data; all data comes from `/ui/api/*`, which is authenticated. | `src/gateway/ui/shell.rs:3-7` |
| F5 | The shell's CSP allows scripts, fetches and form posts to its own origin only, nothing inline. | `src/gateway/ui/shell.rs:24-28` |

A no-JS form post (UI12's progressive enhancement) can carry a cookie but never a bearer header. So "every write works without JS for a remote operator" and "no new auth surface" cannot both hold.

## Options

1. **Bearer over fetch, no new auth surface.** Remote operators sign in with their key; the page keeps it in memory and sends it on every `/ui/api` call. Live updates use a `fetch` response read as a stream (`ReadableStream`), which can carry the header (F3 does not apply to fetch). No-JS writes work only with the loopback cookie (F1).
2. **An interactive login that issues a session cookie to remote peers.** Live updates can use plain `EventSource`, and no-JS forms work everywhere. A new auth surface: password or key exchange over the network, CSRF protection on every form, cookie flags, brute-force limits, and TLS made mandatory for it. It needs its own security review.

## Decision

Option 1 for 4.0.0.

- **Shell.** The shell stays static and unauthenticated (F4); it renders an empty frame and the sign-in step, and every number comes from authenticated `/ui/api` calls. No server-side rendering of authenticated HTML in 4.0.0.
- **Stream.** U3 serves the live feed as a streamed `fetch` response with the same authentication as `/ui/api`. A dropped stream reconnects with backoff and the top bar shows "Updates stopped at HH:MM · reconnecting" (frame 40s).
- **Remote sign-in.** The key stays in page memory, never in `localStorage` or a cookie; a reload asks for it again. The page tells the operator so once.
- **No JavaScript.** Reading and every write work without JS only on loopback, through the cookie session (F1). Remote operators need JS; UI12's budget (core JS under 200 KB, first paint under 1 s) keeps that cheap.
- **Later.** A remote session cookie (Option 2) is a v4.1.0 decision with its own security review; this ADR is superseded when it lands.

## Consequences

- No new authentication code in 4.0.0; the security posture is today's.
- A remote operator who reloads signs in again; phone users keep one tab.
- UI12's progressive-enhancement criterion reads "core reading and writing without JS on loopback; remote needs JS", not "everywhere".
- The shell needs no per-user rendering, so it stays cacheable and holds no data.
