# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.7.x   | :white_check_mark: |
| 2.6.x   | :white_check_mark: |
| < 2.6   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **mikko.parkkola@iki.fi** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
3. You will receive acknowledgment within 48 hours.
4. A fix will be developed and released within 7 days for critical issues.

## Security Architecture

MCP Gateway implements defense-in-depth across the six attack vectors identified by [Doyensec's MCP security research](https://blog.doyensec.com/2025/04/01/mcp.html), plus one the gateway's own shape adds: it listens on a local HTTP port, which a web page can reach.

### Defenses

| Attack Vector | Defense | Module |
|--------------|---------|--------|
| **Tool Poisoning / Rug Pull** | SHA-256 tool definition hashing, mutation detection | `src/security/tool_integrity.rs` |
| **Namespace Collision** | Cross-backend collision detection, namespace isolation | `src/security/scope_collision.rs` |
| **Prompt Injection** | 22+ regex pattern response scanning | `src/security/response_scanner.rs` |
| **Input Injection** | Shell/SQL/path traversal detection, input sanitization | `src/security/firewall/` |
| **Credential Exposure** | Response redaction (AWS, GitHub, JWT, etc.) | `src/security/firewall/redactor.rs` |
| **SSRF** | Private IP rejection on all outbound URLs | `src/security/` |
| **Cross-site access to the local port** | `Origin`, `Host`, HTTP/2 `:authority` and `Sec-Fetch-Site` validation ahead of auth | `src/gateway/router/origin_guard.rs` |

### Security Practices

- **Zero unsafe code**: `#![deny(unsafe_code)]` enforced at crate level
- **TLS/mTLS**: Full mutual TLS support with certificate-based access control
- **Authentication**: Bearer tokens, API keys, OIDC JWT verification, per-client scopes
- **Admin needs a credential**: with `auth.enabled = false` every caller over
  HTTP is an anonymous non-admin. Server management tools and the admin
  dashboard require an explicit credential, because an unauthenticated gateway
  cannot tell its operator from a web page that rebound a hostname to loopback.
  A stdio caller is admin: it spawned the process, so it already holds whatever
  the operator holds
- **Secrets**: OS keychain integration (macOS Keychain, Linux secret-service) — never stored in config
- **Circuit breakers**: Per-backend fault isolation prevents cascading failures
- **Rate limiting**: Token-bucket per-backend rate limiting
- **Audit logging**: NDJSON audit trail for all tool invocations

### Security Testing

- **53 dedicated security integration tests** (`tests/security_tests.rs`)
- **19 cross-feature integration tests** (`tests/cross_feature_tests.rs`)
- **Full `cargo test --all-features` suite** across unit, integration, and doc tests
- **Clippy pedantic** linting enforced in CI
- **Dependency audit**: All crypto via `rustls` (no OpenSSL)

For the full security audit report, see [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
