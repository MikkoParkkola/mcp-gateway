# Security Policy

## Supported Versions

Only the latest release is supported. Security fixes ship in a new release;
they are not backported to earlier versions.

| Version | Supported |
| ------- | ------------------ |
| [Latest release](https://github.com/MikkoParkkola/mcp-gateway/releases/latest) | :white_check_mark: |
| Anything older | :x: |

If you are running an older version, upgrading to the latest release is the fix.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Preferred: use GitHub's private vulnerability reporting on this repository
   (**Security** -> **Report a vulnerability**). It keeps the report private,
   threads the discussion with the maintainer, and records your credit on the
   advisory when it is published.
3. Alternatively, email **mikko.parkkola@iki.fi** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
4. You will receive acknowledgment within 48 hours.
5. A fix will be developed and released within 7 days for critical issues.

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

### Known limitations

- **Windows file permissions**: files holding secrets — the config with its
  admin token, generated mTLS private keys, stored OAuth tokens — are created
  owner-only (`0600`) on Unix. Windows has no equivalent in the Rust standard
  library: the file inherits the ACL of the directory it is written to.
  Restricting the DACL requires a Win32 call, and this crate denies `unsafe`
  code, so the gateway does not claim a permission it cannot set. It warns once
  per process when it writes such a file. **On Windows, put the config and any
  key material in a directory only the gateway's account can read.** Tracked
  rather than silently accepted; a safe wrapper for the Win32 call is the fix,
  and it needs a Windows host to verify on.

### Security Testing

- **53 dedicated security integration tests** (`tests/security_tests.rs`)
- **19 cross-feature integration tests** (`tests/cross_feature_tests.rs`)
- **Full `cargo test --all-features` suite** across unit, integration, and doc tests
- **Clippy pedantic** linting enforced in CI
- **Dependency audit**: All crypto via `rustls` (no OpenSSL)

For the full security audit report, see [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
