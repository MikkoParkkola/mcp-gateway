# Public provenance signatures

A second, publicly verifiable signature over each runtime-provenance receipt.
The HMAC in `_meta.provenance` stays the gateway's own seal; the Ed25519
signature travels beside it as the `public_signature` member, so anyone
holding the public JWK can verify a receipt without any gateway secret.

## Setup

Set two environment variables (an env file works; see `docs/DEPLOYMENT.md`):

```bash
openssl rand -base64 32  # put the output in GATEWAY_PROVENANCE_SIGNING_SEED
```

```env
GATEWAY_PROVENANCE_SIGNING_SEED=<base64 of 32 random bytes>
GATEWAY_PROVENANCE_KEY_ID=prov-2026-10
```

The seed is STANDARD base64 of exactly 32 bytes. The key id is required when
the seed is set, is 1-64 bytes of `0x21..=0x7E`, and must name neither the
attestation key id nor its `bnaut/` form. A malformed seed or key id refuses
startup with a value-free error. Unset or blank means no public signature,
and the HMAC output is byte-identical to stamping without it.

Export the public key and publish the JWK to verifiers:

```bash
mcp-gateway provenance public-key
# {"jwk":{"kty":"OKP","crv":"Ed25519","kid":"prov-2026-10","x":"..."},"thumbprint":"..."}
```

## Signed bytes

`public_signature` is `{"payload": <String>, "sig": <String>}`:

- `payload` is base64url without padding of the exact JSON bytes of
  `{"v":1,"alg":"EdDSA","kid":<kid>,"receipt":<receipt>,"result_sha256":<hex or null>}`,
  built with `serde_json::json!` in that member order.
- `sig` is base64url without padding of the 64-byte Ed25519 signature over
  `b"mcp-gateway-provenance-ed25519-v1\0"` followed by the payload bytes.
- `result_sha256` is the hex digest of the result, or null when there is no
  result to bind.

The verifier checks the signature over the decoded payload bytes it was
given; it never re-canonicalizes.

## Verifier order

1. A provisional duplicate-rejecting parse of the payload, only to read
   `kid` (`duplicate_member` for a duplicate member at any depth).
2. Key selection by `kid` (`unknown_kid`).
3. The Ed25519 check over the tag plus the payload bytes (`bad_signature`).
4. Profile: `v` is 1 and `alg` is `EdDSA` (`bad_profile`), and the outer
   `receipt` is JSON-equal to the payload `receipt`
   (`outer_receipt_mismatch`).
5. Result binding: a null digest is `UNBOUND`; a given result is recomputed
   and a mismatch is `result_mismatch`; a given result that is unhashable
   while the digest is non-null is `result_unhashable`; equal is `BOUND`;
   no result is `SIGNATURE-ONLY`.

## Statuses and flags

- `BOUND` (exit 0): the signature is valid and the given result matches.
- `UNBOUND` (exit 1 unless `--accept-unbound`): the signature is valid but
  the payload carries no result digest.
- `SIGNATURE-ONLY` (exit 1 unless `--signature-only`): the signature is
  valid and no result was offered.
- `INVALID <reason>` (exit 1): anything else.

```bash
# Bind to a result file:
mcp-gateway provenance verify --trust jwk.json provenance.json --result result.json
# BOUND kid=prov-2026-10

# Check a signature without a result:
mcp-gateway provenance verify --trust jwk.json provenance.json --signature-only
# SIGNATURE-ONLY kid=prov-2026-10 (accepted: --signature-only)

# Accept a receipt that carries no digest:
mcp-gateway provenance verify --trust jwk.json event.json --result event-result.json --accept-unbound
# UNBOUND kid=prov-2026-10 (accepted: --accept-unbound)
```

`<receipt>` may be a provenance object or a full stamped result (its
`_meta.provenance` is used); `--result` may likewise be a bare or stamped
result.

Unbound receipts come from event receipts, non-object results, and results
holding an integer outside ±(2^53−1).

## Digest recipe for non-Rust verifiers

`result_sha256` is SHA-256 hex of RFC 8785 canonical JSON of the result
object without its top-level `_meta` and `_signature` members, refusing
(non-interoperable) numbers outside the exact-integer range: integers must
be within ±(2^53−1); anything else unhashable yields a null digest.

## Rotation

To rotate with an overlap window: publish the new JWK first, set the new
seed and kid and restart, have verifiers trust both kids (the `--trust`
file accepts a `{"keys":[...]}` set) until the old receipts' retention
ends, then drop the old kid.

## Reference verifier (Python, documentation only)

```python
import base64, hashlib, json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TAG = b"mcp-gateway-provenance-ed25519-v1\0"

def b64u_no_pad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def verify(jwk: dict, prov: dict) -> dict:
    payload_b64 = prov["public_signature"]["payload"]
    sig = b64u_no_pad(prov["public_signature"]["sig"])
    payload = b64u_no_pad(payload_b64)
    if len(sig) != 64 or "=" in payload_b64 or "=" in prov["public_signature"]["sig"]:
        raise ValueError("bad_encoding")
    key = Ed25519PublicKey.from_public_bytes(b64u_no_pad(jwk["x"]))
    key.verify(sig, TAG + payload)
    body = json.loads(payload)
    assert body["v"] == 1 and body["alg"] == "EdDSA"
    assert body["kid"] == jwk["kid"]
    assert body["receipt"] == prov["receipt"]
    return body
```
