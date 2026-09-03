# MRTR.9a — a client's declared elicitation *modes*, not just the capability name

## SCOPE (§P0)

**FOR:** making `InputRequired::undeclared` refuse an elicitation request whose
*mode* the client did not declare, so that `MRTR.9a` is met.

**OUT**, explicitly:

- `sampling/createMessage` and `roots/list`. Neither carries a mode substructure
  in this revision, and inventing a general "capability sub-feature" mechanism to
  hold one of them is a design for a caller that does not exist.
- `MRTR.9b`. A separate row with a separate criterion.
- Every `DE-9a` continuation variant. This change creates none; it adds no
  new error code at all.
- `DE-9` itself — which code an *unrecognised method* is refused with. The
  wiring design expected it to land here; it does not, because a mode gate
  never reclassifies a method. It is re-deferred with its four fields under
  *Unknowns*, not answered (see *The DE-9 sub-decision* below). What **is** in
  scope is the payload the *mode* refusal carries, because the refusal has to
  carry something.
- The declaration path for anything other than `_meta`-carried
  `clientCapabilities` — the era probe and per-backend detection are cluster B.
- Widening `RequestFields` to answer questions no consumer asks.

## The problem

The specification is a `MUST NOT`, not a `SHOULD`:

> Servers **MUST NOT** send elicitation requests with modes that are not
> supported by the client.
> — <https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#capabilities>

The gateway cannot obey it, because the information is destroyed at parse. At
`src/protocol/meta.rs:185-191` the `clientCapabilities` object is flattened to
the *names* of its non-null keys:

- a client declaring `{"elicitation": {"form": {}}}` and
- a client declaring `{"elicitation": {"url": {}}}`

produce the byte-identical `declared_capabilities` vector `["elicitation"]`.

Downstream, `InputRequired::undeclared` (`src/protocol/mrtr.rs:296+`) maps a
request's `method` to a capability *name* through `required_capability`
(`meta.rs:255-263`) and asks whether that name is in the vector. The mode in
`entry.params.mode` is never consulted, because by then there is nothing to
compare it against. A url-mode elicitation to a form-only client passes the gate
**by construction** — the gate is not weak, it is blind.

The two cases already in the tree state exactly this:

- `ac_mrtr_9a_a_url_mode_request_to_a_form_only_client_is_refused`
  (`tests/mik_7212_acs.rs:1759`) — **RED** today, on its own criterion assertion.
- `ac_mrtr_9a_a_form_mode_request_to_a_form_only_client_is_relayed` (`:1782`) —
  **GREEN**, and it is what stops "refuse every elicitation" from satisfying the
  first. A gate no client could ever pass is not a gate.

That red case is the free failure §P2 asks for. Nothing here is retrofitted.

## The measured constraint that bounds every option

`declared_capabilities` is a `Vec<String>` for a stated reason, and the reason is
a security property rather than a preference. Verbatim, `meta.rs:61-69`:

> Names rather than the subtree they came from. Every consumer asks the same
> question — was this capability declared — and keeping the whole
> `clientCapabilities` value to answer it copied an attacker-sized, arbitrarily
> deep object out of every request, on a path that runs before anything has
> decided the request is even wanted.
>
> A null value is not a declaration: the specification's rule is that a server
> may not rely on what was not declared, and explicitly-absent is still absent.

Two requirements fall out, and any option that breaks either is rejected on the
spot:

1. **What is retained is bounded in size by the gateway, never by the caller.**
   The parse runs before admission control, so an unbounded copy is a remote
   memory amplification with no authenticated caller behind it.
2. **Absent stays absent.** A null, and anything the gateway cannot interpret,
   is not a declaration.

The first premise — "every consumer asks the same question" — is what this
change falsifies. One consumer now asks a second question. The economy stands;
the flattening was correct for the question that existed when it was written.

## Trust boundary and threats (DoR C6, C15)

This change parses caller-controlled data before the caller has been admitted
to anything, so the canonical readiness gates apply and are answered here
rather than assumed.

**Trust boundary (C15).** Tier: **unauth** — a capability declaration arrives in
`_meta` on a request and is read before any admission decision uses it. Data
locality: **local**; the declaration is parsed, reduced to a fixed set and
dropped, and nothing about it is stored or forwarded. Partition behaviour:
**N/A** — no distributed state, no replication, no consensus on this path.
Crypto: **none introduced**, so `T1c` post-quantum readiness is N/A rather than
deferred.

**STRIDE (C6), short form.** Only three of the six bear on this path, and the
mitigation for each is a part of this change rather than a promise:

| | applies | mitigation |
|---|---|---|
| Spoofing | no | a client that over-declares a mode harms only itself; the gateway grants it nothing |
| Tampering | no | the declaration is read, not written back or persisted |
| Repudiation | no | no audit claim rests on the declared set |
| **Information disclosure** | **yes** | `url` mode exists so that data other than the URL is *not* exposed to the client. Sending a url-mode request to a client that never declared url is the disclosure, and refusing it is this criterion |
| **Denial of service** | **yes** | today's `Vec<String>` is caller-sized and retained pre-admission — an amplification this change closes by reducing to a fixed gateway-owned set at parse |
| **Elevation of privilege** | **yes** | an undeclared mode is a capability the gateway hands a backend that was never granted it; the gate is the control |

The information-disclosure and elevation rows are the same refusal seen from
two ends, which is why one gate closes both. The denial-of-service row is
independent of the criterion and would be worth doing on its own.

## Wire shape

Confirmed against the fixtures already in the tree
(`tests/mik_7212_acs.rs:1758-1795`): the mode is a string at `params.mode` of the
`elicitation/create` entry, e.g.

```
{"api_key": {"method": "elicitation/create",
             "params": {"mode": "url", "url": "…", "message": "…"}}}
```

and the declaration side nests one object per supported mode under the
capability: `{"elicitation": {"form": {}}}`.

The specification fixes one normalization that must not be invented later:
an empty `"elicitation": {}` is equivalent to `{"form": {}}`. A client that
declares the capability and names no mode has declared **form**.

**The same default binds the request side, and the specification fixes that
one too.** An earlier draft called it the gateway's own decision, on the reading
that the passage above covers only the declaration side. It does — but a second
passage covers the request side, and the review that questioned the attribution
was right to. The request-parameter table for `elicitation/create` reads
*"`mode` … Optional for form mode (defaults to `"form"` if omitted)"*
(<https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation>).
Both defaults are normative and neither is ours to change. An `elicitation/create` entry carrying
no `params.mode` is a *form* request, not a modeless one. Without this, the
natural reading of "refuse a request whose mode was not declared" refuses every
request that omits the field — a compliant form-mode request from a form-only client, which is the
exact case the second test in the tree exists to protect. Both sides normalize
to the same value, once, at parse.

Mode keys match **exactly and case-sensitively**, against a lowercase
vocabulary. Anything else is a per-call-site normalization rule, and multiple
sites deriving it independently is the failure option A was rejected for.

## Options

### A — keep `Vec<String>`, store joined names

Append `"elicitation/form"` alongside or instead of `"elicitation"`.

**Rejected.** It reintroduces a parse at every read site: `declares_capability`
and `required_capability` both compare whole strings, so each of the three
call sites would have to learn a separator convention, and a site that forgets
it silently reverts to today's blind behaviour. Its second problem is the reverse of what it looks like: raw
strings store an unrecognised mode *verbatim*, which lets a caller pre-declare
the exact string a later build learns to honour. Filtering that needs the closed
vocabulary of option B — at which point A is B carrying a separator convention.

### B — a fixed gateway-owned set, with no caller string retained at all *(chosen)*

Replace the `Vec<String>` with a **fixed-size set the gateway owns end to end**:
the three capabilities `required_capability` can name, and for elicitation the
modes it can honour. Nothing caller-supplied survives the parse — an unrecognised
capability key and an unrecognised mode key are both dropped there, which is the
same disposal a null already gets.

This is stronger than the first draft of this option, which kept the vector and
closed only the mode vocabulary. That version did not deliver the size bound it
claimed: a caller sending ten thousand capability keys still got ten thousand
records allocated pre-admission. Closing the mode vocabulary while leaving the
outer collection caller-sized would have moved the amplification, not removed it.

The stronger form is available because **no consumer ever asks about a
caller-supplied name.** Verified at source: `declares_capability` is called at
exactly one site (`src/gateway/router/handlers.rs:781`) and its argument is the
return of `required_capability`, which answers with one of three `&'static str`;
`InputRequired::undeclared` does the same. A set that can represent only those
three is not a restriction on any question the code asks.

Both constraints then hold *by type* rather than by review:

- Size is fixed by the gateway. No request can enlarge it.
- Absent stays absent, one level down: an unrecognised mode is not a
  declaration, so it can never satisfy a request. A closed vocabulary is the
  feature here — an open one would let a caller declare the exact string a future
  gateway learns to honour.
- `{}` normalizes to form at parse, once, so no consumer re-derives it — and
  the default is keyed on the object being **syntactically empty**, applied
  *before* unrecognised keys are dropped. Applied after, `{"telepathy": {}}`
  would filter to empty and then acquire form, turning a declaration of nothing
  the gateway understands into a declaration of form. That is requirement 2
  inverted, and the ordering is what prevents it.

**This closes a pre-existing amplification rather than avoiding a new one.**
Today's `Vec<String>` is already caller-sized, on the same pre-admission path,
and the comment at `meta.rs:61-65` records that risk being reduced from a deep
object to a flat list of names — not to a bounded one. Fixing it here is in
scope because this change rewrites that exact field; it is not a tidy-up of
neighbouring code.

Cost, stated: four sites change shape (`RequestFields`, the accessor, the two
`handlers.rs` consumers at `:693` and `:1152`), and one type crosses from
`meta.rs` into `mrtr.rs`'s signature.

### C — retain the whole `clientCapabilities` value, query on demand

**Rejected by the measured constraint.** This is precisely the design the comment
at `meta.rs:61-65` records having removed, for a reason that has not changed: the
copy is attacker-sized and happens before anything has decided the request is
wanted. Re-adding it to answer one more question would trade a remote memory
amplification for a field lookup.

## The DE-9 sub-decision

Binding decision 8 puts the `DE-9` error-code scope with this row. `DE-9` is the
**error code an unrecognised input method is refused with** (wiring design
`:663`, second finding). Its
seven continuation variants are `DE-9a` (`:687`), a separate sub-decision this
change does not touch — `MRTR.9a` is not a continuation redemption at all.

**This change adds no new error code.** An earlier draft argued for one on the
grounds that a mode refusal is actionable where a capability refusal is
terminal: the server could retry in a mode the client did declare. That
justification is false, and the refusal path says so. `handlers.rs:783` returns
the refusal to the **client**, as a `JsonRpcResponse::error` on the client's own
connection. The backend server that issued the elicitation never sees it, so no
code carried there can tell it to retry. Distinguishing an outcome for a reader
that does not exist is not a distinction.

### The payload has to survive one more hop than the first draft accounted for

Writing mode detail at `handlers.rs:790` is not enough, and the review caught
this. `error_response_preserving_status` (`src/gateway/meta_mcp/mod.rs:179-200`)
rebuilds the error and forwards **exactly one** key — `requiredCapabilities` —
discarding everything else in `data`. Mode detail written upstream would be
dropped before any client saw it, and every test that asserted it at the write
site would still pass.

The allowlist is deliberate and stays: the comment there records that `data` is
a shared channel, and that `invoke_tool` puts a *backend's* error data into the
same variant, so forwarding wholesale would let a backend choose the gateway's
HTTP status. The change is therefore to add **one more gateway-owned key** to
that allowlist, alongside the existing one — the same discipline, one entry
wider. The key is named here so that the write site, the allowlist and the test
cannot each pick their own: **`unsupportedElicitationMode`**, a constant beside
`REQUIRED_CAPABILITIES_DATA_KEY` (`src/gateway/meta_mcp/invoke.rs:626`), whose
value is the refused mode as the gateway's own enum renders it — never the
caller's string. The plan's case 6 asserts the payload after this conversion, not before.

The refusal **message** changes too. Today it reads *"client did not declare the
'elicitation' capability"*, which is false for a client that declared
elicitation and not the mode. A refusal that misstates its own reason sends the
client to fix something that is not broken.

`DE-9` itself stays open, and an earlier draft of this document closed it by
restating it. It asked what code an *unrecognised method* is refused with, on
the ground that `-32021` means a capability is missing when nothing is; this
document answered a different question — what a *mode* refusal carries — and
called `DE-9` resolved. A question answered by being reworded is not answered.
It is re-deferred below with its four fields, and the wiring design's
expectation that it would land here is what this paragraph corrects.

What this change does settle is the mode refusal's own payload. It keeps code
`-32021` and gains structured detail in `error.data`: the mode requested. It
does **not** keep `requiredCapabilities`. That field names what the client must
declare to succeed, and for a mode mismatch the client has already declared
`elicitation` — repeating it is the same false instruction as the message this
change is rewriting, in a field instead of a sentence. A client that wants to
distinguish *mode* from *capability* reads a field; nothing has to learn a new
code, and nothing in the error vocabulary becomes a contract this change is
stuck supporting.

## Risks, reversibility, exit criteria, prior art

**Risk — vocabulary drift.** The specification adds a mode the gateway's set
does not carry, and the gateway refuses it until updated. This is the closed
vocabulary working as designed rather than a defect, but it is an interop lag
and it is stated: a new mode is a code change, not a config one. Accepted
knowingly; the alternative is honouring strings the gateway cannot service.

**Risk — the struct crosses a module boundary.** `meta.rs` now owns a type
`mrtr.rs` names in a signature. Contained: one type, one direction, no cycle.

**Reversibility — one-way door: none.** Everything here is internal. The
declaration type is private to the gateway, `error.data` is additive to a code
that already ships, and no new error code is introduced — which is the part
that *would* have been sticky, since a code, once emitted, is a contract clients
may come to depend on. Reverting is deleting the type and restoring the
`Vec<String>`, at the cost of returning to today's blind gate. No migration and
no persisted state.

One qualification, because the first draft overstated this. The added
`error.data` fields **are** an observable contract — the design tells clients to
read them instead of a new error code, which is the whole reason no new code is
minted. A rollback must keep the field shape it shipped, or it breaks the
clients that took the design at its word. Additive-and-stable is cheap to
honour, and saying so here stops a later rollback discovering it.

**Exit criteria.** Every case in the sibling test plan passes — the matrix and
cases 2 through 7, not only the two that predate it — and the existing suite
stays green; `ac_mrtr_9a_a_url_mode_request_to_a_form_only_client_is_refused`
is green on its own criterion assertion; no other `DE-9a` variant is added; `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings` clean. Anything beyond that is a
different row.

**Prior art.** In-tree: this is the same shape as `required_capability`'s
`&'static str` answers — a closed gateway-owned vocabulary, already the
established way this codebase refuses to let a caller name its own key. Outside
the tree, the specification's own capability negotiation is the prior art the
design follows rather than invents: a server may rely only on what was declared,
which is the rule this change extends one level down. No external mechanism was
adopted, so there is nothing to attribute.

## Unknowns

All four **resolved**; per §P1 each records the answer, not the plan to get one.

- *Is the red case genuinely red, or is it ignored/absent?* — ran
  `cargo test --test mik_7212_acs ac_mrtr_9a` — **1 passed, 1 failed**, the
  failure on the criterion's own assertion message — **changed:** confirms the
  free failure and removes the retrofitting exception from this change.
- *Does the wire put the mode somewhere the gate can reach?* — read
  `tests/mik_7212_acs.rs:1758-1795` — mode is a plain string at `params.mode`,
  declaration nests one object per mode — **changed:** killed a variant of option
  B that would have needed a second lookup path for the request side.
- *Is a null-valued mode a declaration?* — read `meta.rs:67-69` — no; the
  existing rule already answers it — **changed:** nothing, and saying so is the
  point: the rule generalizes one level down without amendment.

- *Is the request-side omitted-mode default ours or the specification's?* —
  fetched the elicitation specification page and read its request-parameter
  table — the entry reads *"Optional for form mode (defaults to `"form"` if
  omitted)"*, so the rule is normative — **changed:** reversed this document's
  attribution of that default, and with it the reversibility argument: a
  gateway policy could be revisited, a MUST cannot.

**Deferred:** `DE-9` — what error code an unrecognised *input method* is
refused with. **Owner:** the `DE-9` row of the wiring design, unmoved by this
change. **What would resolve it:** a decision on whether an unclassifiable
upstream method is a protocol error (`-32600`) or keeps a gateway-specific
code, taken against the specification's error-handling sentence. **When:** with
the next change that touches the unrecognised-method arm of the refusal path.
**If it resolves badly:** a client keeps reading `-32021` for a malformed
upstream response and retries a declaration that cannot help — today's
behaviour, unchanged by this row and not worsened by it.

Nothing in this change depends on that answer: the mode gate refuses a mode the
client did not declare, which is a capability question, and it never
reclassifies a method.

## Review record

Three dual-vendor rounds on this document and its sibling test plan. Round 1
found a missing matrix row that changed what the plan covers; round 2 found
repairs that had moved a defect rather than removed it; round 3 found only
residue from round 2's repairs — a phrase to delete, a count to reconcile, a
cell to name. Finding count stayed flat while severity collapsed, which is the
signal the process document names: a round that only tightens edges is
polishing a protocol that should be code. Design review closes here; the next
verdict is taken on the implementation.

**Declined — a typed return from `required_capability`.** Both rounds raised it
as an improvement: the function answers with one of three `&'static str`
values, and this change converts those back into set members, so a fourth
capability would compile silently rather than fail. Real, and out of scope per
§P0 — it changes a signature this change only reads, on the capability axis
rather than the mode axis, and the conversion it removes is three arms of a
match with no caller string in it. Recorded as an observation rather than a
ticket: the disposal a finding earns when it is worth remembering and nobody
must act.
