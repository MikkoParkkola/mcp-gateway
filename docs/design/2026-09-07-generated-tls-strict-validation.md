# Generated certificates: strict X.509 compatibility

Status: design/plan gate closed (Grok SHIP, GPT finder SHIP). Both test reviewers
approved the compiled regression. Implementation passes five new and 67 existing
mTLS tests; CLI-generated server and client chains pass strict OpenSSL validation.
Quantitative checks pass for the changed code. Live acceptance and final code
review remain open.

Owner ticket: [MIK-7212](https://linear.app/parm/issue/MIK-7212/critical-proxy-drops-mrtr-inputresponses-and-requeststate-write-the).
All four `MIK-7212.TLSCERT` acceptance checkboxes are in its description.

FOR: unblock the 4.0 HTTP/TLS independent acceptance drive by making newly
generated gateway CA and issued server/client certificates acceptable to strict
X.509 validators without weakening authentication.

OUT: replacing existing keys or certificates automatically, new trust policy,
new certificate CLI options, certificate algorithm/validity changes, and changes
to the HTTP shutdown repair. This is W01 compatibility repair within the approved
release scope; release delivery remains the parent objective.

## Evidence and decision

The independent HTTP driver used CLI binary SHA256
`4ebf189bad8e0af59540fb56fdb10754ebb6e6696cc5c61efbf27cc85cc6adbc`.
Plain MCP initialization/listing and CA-verified TLS health worked. Python 3.13
default verification rejected the generated TLS chain before the MCP request.
The driver's HTTP.1–HTTP.5 verdicts are INVESTIGATE, not accepted.

Coordinator reproduction with the same certificates:
`openssl verify -x509_strict -CAfile tls/ca.crt tls/server.crt` reports error 85,
missing Authority Key Identifier, and error 92, missing CA key-usage extension.
The CA already has a Subject Key Identifier and critical CA basic constraints.
No product private keys were exported from a live service; the fixture is isolated.

[Python's ssl documentation](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)
records strict verification in the defaults from 3.13.
[RFC 5280 sections 4.2.1.1–4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1)
define CA-issued AKI, CA SKI and CA key-usage requirements. The self-signed root
exception permits omission of root AKI. rcgen 0.14.9's current source defaults
to empty key usages and disabled AKI; its existing extension support is reusable.

The bounded repair configures certificate-signing and CRL-signing usage for newly
generated CAs, and enables issuer-derived AKI for both issued leaf variants.
Keep existing algorithms, SANs, identity fields, validity, file permissions and
TLS verification settings. Existing external CA input remains supported.
Changing validator flags would conceal malformed output and is rejected;
replacing rcgen would add unnecessary dependency and cryptographic risk.

Target: `CertGenerator::init_ca` and `CertGenerator::issue_leaf` in
`src/mtls/cert_manager.rs`, focused tests, and operator TLS documentation.
GitNexus upstream impact: medium for both; init_ca has 14 direct callers and
issue_leaf has 7, in mTLS and TLS CLI flows. Verify both server and client issuance.

## Acceptance and test plan

| AC | Case and level/type | Falsifier and required evidence |
| --- | --- | --- |
| MIK-7212.TLSCERT.1 | Generate a CA; parse actual DER and require critical key usage with certificate-signing and CRL-signing bits. Component, positive conformance. | Current init_ca lacks the extension: compiled assertion failure. Existing unique-key and PEM tests stay green. |
| MIK-7212.TLSCERT.2 | Issue DNS server and SPIFFE client leaves; parse DER and require noncritical AKI equal to issuer SKI. Preserve DNS/URI SANs. Component, positive identity/conformance. | Current issue_leaf lacks AKI: both compiled assertion failures. Also issue from an external fixture CA with an explicit nondefault SKI, proving issuer reuse rather than a new derived value. |
| MIK-7212.TLSCERT.3 | Generate CA/server/client through real CLI; require strict OpenSSL server/client chain verification. Serve with `require_client_cert: true`; Python 3.13 default context loads the generated client certificate/key and completes MCP initialize/list. System/acceptance, interoperability. | Original binary fails strict verification. On the same positively verified live endpoint, wrong hostname and untrusted CA must raise `SSLCertVerificationError` with the respective hostname-mismatch and issuer/trust verification reason; connection refusal/timeout is not a passing negative. Missing/untrusted client certificates must also fail the authenticated handshake. Reuse the independent driver for affected confirmation. |
| MIK-7212.TLSCERT.4 | Rehearse side-by-side CA generation, overlapping trust distribution, leaf cutover and rollback in isolated directories/services. System/acceptance, upgrade. | Preserve hashes of old material; new strict mTLS succeeds only after new trust and leaf distribution. Existing legacy-client access remains verifiable with CA-verified curl, and reverting the isolated service to retained old material restores the original legacy connection. Do not claim strict clients work with the malformed old generation. |

Tests precede implementation and receive their own review. Portable DER assertions
run in normal Rust tests. OpenSSL and Python checks run in the Spark release lane;
missing or older tooling is a blocked check, never a silent pass. Cheapest next
check is the DER regression against unchanged production, then strict chain and
real TLS validation after repair. Any additional strict-validator failure is
diagnosed before claiming TLSCERT.3.

DoR: the user has authorized closing release gaps and retaining full DoD. There
is no new user policy decision. Value is restoring standards-compliant TLS
interoperability. Security risk is overbroad CA usage or wrong issuer binding;
the assertions constrain those fields and negative trust/hostname controls
prevent verification relaxation. No new dependencies, personal data or service
deployment. Critical changed-code coverage >=95% and viable mutants >=85%
apply; unchanged module coverage is reported separately. Final review remains
two code legs and independent functional confirmation, with actual exit and
material-bound ledger receipts.

Backlog evidence read live on 2026-09-07: B1 MIK-7212 exists and is In Progress;
B2 Urgent priority, 8-point parent estimate, mcp-gateway label/project, Mikko
assignee/team and v4.0.0 milestone are populated; B3 parent MIK-7211 and existing
blocked-by MIK-7388 are retained. That dependency concerns wider MRTR dispatch;
this certificate generator repair is independent, and explicitly blocks the
existing HTTP acceptance drive. B4 the four ticket-prefixed checkboxes above
are recorded in the issue description. B5 the existing Urgent v4.0.0 position
applies. No new cycle, point estimate, due date or workflow state is invented.

## Upgrade and delivery

Only newly generated material changes. An existing gateway-generated CA without
key usage also needs reissuance and trust-store updates for strict validation;
issuing a new leaf alone does not repair that CA. The operator procedure is:

1. Preserve the old certificates, keys, config and trust bundles. Generate the new
   CA and server/client leaves in a separate directory, never over existing files.
2. Distribute combined old/new CA trust to server and clients before cutting over
   leaf/key paths. Verify existing legacy clients still connect. Old malformed
   chains remain incompatible with strict verification even with overlapping trust.
3. Switch the isolated server and client leaf/key configuration to the new
   generation, then prove strict Python mTLS initialize/list and legacy-client
   compatibility. Enable strict consumers only once that positive check passes.
4. Rehearse rollback by restoring retained old leaf/key/config references while
   keeping overlapping trust; verify the original legacy client again. Rollback
   restores legacy service, not strict compatibility with a malformed old CA.
5. Remove old trust only after all consumers have migrated and the operator has
   ended the rollback window. This repair never chooses that window or removes
   a user's existing trust automatically.

MIK-7212.TLSCERT.4 exercises steps 1–4 using isolated service instances. The
documentation explains step 5 as an operator action; no live Spark service or
user trust store is changed during validation.
Run focused mTLS regressions and formatting/lint checks, then integrate evidence
into W01. This design grants no release, merge or deployment verdict.

## Review disposition

The first GPT process exited 143 without a verdict; its identical-material retry
exited 0 with SHIP-WITH-FIXES. Grok exited 0 with SHIP. Unique ledger rows and
scope/material/head bindings are verified. The first design digest remains
`6084dd1ff5855846550d7f02f8c0884c956c4e3b3a80a489e46d6a03fcaf4750`.

The four GPT findings are addressed by the rollout sequence plus TLSCERT.4,
mandatory live client-certificate authentication, verification-specific negative
oracles, and the populated owner ticket/AC mapping. This receipt adds explicit
upgrade acceptance detail within W01 and the existing release upgrade obligation;
it changes no automatic rotation behavior or approved product scope. GPT finder
confirmation returned SHIP with actual exit 0 and verified material/ledger
binding (`43ba777f41ae0164bf49854a58efed06b95baf2b871e289bfa11f707c9c13162`).
Unchanged Grok approval is retained. Both test-review legs returned SHIP for
material `7daa9c681cfb6ea54a375790d53df7f0cbb71d59a0513a5ab9082abb200fd048`.

## Implementation checkpoint, 2026-09-06 21:59 UTC

`src/mtls/cert_manager.rs` now sets the two CA signing usages and enables
issuer-derived AKI on issued leaves. Its SHA256 is
`aded91190f51bfd3ed6e34ab581607eb5bba526b45f05153e8b60f2d516d5b43`.
All five DER regressions first failed on the unchanged generator at the intended
missing-extension assertions, then passed after the repair. The existing 67
mTLS tests also pass. The first fixture compilation failure was corrected before
the semantic red run and does not count as a behavioral test failure.

Rebuilt CLI SHA256
`c560d16fb3fe0b512b8dc47f6f0da89eeab8548cacefc5a4d5559501ed98b59c`
generated fresh isolated CA/server/client material. Both `openssl verify
-x509_strict` purpose checks passed, with hostname verification for the server.
This proves generation and strict chain validation; TLSCERT.3/.4 still require
live mTLS, specific negative controls and the isolated rollout/rollback drive.

The first cargo-mutants run generated two whole-function `Default` replacements.
Both fail to compile because `GeneratedCert` has no `Default` implementation:
zero viable mutants is not an 85% pass. Do not change the production API merely
to make these generated replacements viable. The first coverage run exercised
both changed executable lines, but its source-binding receipt raced with that
in-place mutation run. That receipt is preserved. A fresh bounded run passed all
five tests with the expected source hash verified before and after execution.
Both changed lines (203 and 248) were exercised: 2/2 changed-line coverage.
Whole-module coverage from this five-test scope is 67/208 lines (32.21%); it is
not a module-wide 95% claim. The replacement receipt is
`/home/mikko/codex/tlscert-coverage-r2/summary.json` on Spark, exported directly
from the current test binary.

The second cargo-mutants run supplies a valid existing `Error::Config` value:
two viable replacements caught, zero missed or timed out, and the two unviable
`Default` replacements still disclosed. This is 100% of a small two-mutant viable
inventory, not a broad module score. Four additional compiling faults remove
certificate-signing usage, remove CRL-signing usage, grant unrelated digital-
signature usage, and disable leaf AKI. Every fault fails at the corresponding
DER assertion. The source is restored byte-for-byte and all five tests pass.
Commands, diffs, actual exits and source hashes are preserved in
`/home/mikko/codex/tlscert-mutations-r2/summary.json` and its adjacent logs.
No production `Default` implementation or lint suppression was added. Final
code review and live functional confirmation remain open.
