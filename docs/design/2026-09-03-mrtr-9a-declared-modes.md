# MRTR.9a — a client's declared elicitation *modes*, not just the capability name

## SCOPE (§P0)

**FOR:** making `InputRequired::undeclared` refuse an elicitation request whose
*mode* the client did not declare, so that `MRTR.9a` is met.

**OUT**, explicitly:

- `sampling/createMessage` and `roots/list`. Neither carries a mode substructure
  in this revision, and inventing a general "capability sub-feature" mechanism to
  hold one of them is a design for a caller that does not exist.
- `MRTR.9b`. A separate row with a separate criterion.
- Every continuation variant of `DE-9` other than the one this change creates
  (see *The DE-9 sub-decision* below).
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

## Options

### A — keep `Vec<String>`, store joined names

Append `"elicitation/form"` alongside or instead of `"elicitation"`.

**Rejected.** It reintroduces a parse at every read site: `declares_capability`
and `required_capability` both compare whole strings, so each of the three
call sites would have to learn a separator convention, and a site that forgets
it silently reverts to today's blind behaviour. It also cannot express *the
client declared a mode this build does not know*, which is the case where
refusing is mandatory.

### B — a bounded declaration struct with a closed mode vocabulary *(chosen)*

Replace the `Vec<String>` element with a small fixed-size record: the capability
name, plus a set of modes drawn from a **closed vocabulary the gateway owns**.
Both constraints above hold, and hold *by type* rather than by review:

- Size is bounded by the vocabulary, not by the request. A client sending ten
  thousand mode keys yields at most the vocabulary's worth of set bits; the rest
  are dropped at parse, which is the same disposal a null already gets.
- An unrecognised mode is **not** a declaration, so it can never satisfy a
  request. This is requirement 2 applied one level down, and it is the reason a
  closed vocabulary is a feature rather than a limitation: an open one would let
  an attacker declare the exact string a future gateway learns to honour.
- `{}` normalizes to form at parse, once, so no consumer re-derives it.

The comparison the gate performs stays a membership test — the shape it tests
gains a dimension, and the question "was this capability declared" is answered by
the same call for the two capabilities that have no modes.

Cost, stated: three sites change shape (`RequestFields`, the accessor, the two
`handlers.rs` consumers at `:693` and `:1152`), and one type crosses from
`meta.rs` into `mrtr.rs`'s signature.

### C — retain the whole `clientCapabilities` value, query on demand

**Rejected by the measured constraint.** This is precisely the design the comment
at `meta.rs:61-65` records having removed, for a reason that has not changed: the
copy is attacker-sized and happens before anything has decided the request is
wanted. Re-adding it to answer one more question would trade a remote memory
amplification for a field lookup.

## The DE-9 sub-decision

Binding decision 8 puts the `DE-9` error-code scope with this row, so it is
settled here rather than deferred.

`DE-9`'s seven continuation variants were collapsed onto one code because their
outcome is *identical*: the caller is told the continuation cannot be redeemed,
and which of the seven ways it failed changes nothing the caller can act on.

**That collapse does not extend to mode refusal, and the reason is the
difference in what the caller can do about it.** A mode refusal is not one
outcome: *you asked for a mode this client does not have* is actionable — the
server can retry in a mode the client did declare — while *you asked for a
capability this client does not have* is terminal. Collapsing them would tell a
server to give up where it could have succeeded. So the mode refusal carries its
own code, and this is the only `DE-9` variant this change adds.

## Unknowns

Both **resolved**; per §P1 each records the answer, not the plan to get one.

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

**Deferred:** none. Nothing in this change waits on an open question.
