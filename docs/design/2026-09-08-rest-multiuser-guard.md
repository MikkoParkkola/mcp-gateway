# Account-bound multi-user REST guard repair

Scope: permit managed/external descriptor-bound calls for verified callers while preserving legacy/shared OAuth isolation. Stdio installation, bridge projection and consent UI are separate release work.

Measured RED: 18 REST cases pass, three multi-user cases fail; two return the legacy -32001 refusal and the MetaMcp case reaches only the initial credential release. The prior tests never enabled multi_user.

The backend validates personal ownership, path selectors and schema before new custody acquisition. It then prepares/revalidates the account context through the existing executor helper, evaluates OAuth isolation, and passes that same context into execution. Existing inner-cache and egress rechecks remain. Unbound legacy guard behavior is retained.

The guard exception requires a prepared credential, exact capability descriptor and auth-key matches, and exact VerifiedIdentity.stable_actor_id equality with the prepared actor. GrantSubject is not account identity. A shared descriptor yields no prepared credential and retains legacy isolation. Missing identity, strategy, expired credential or revoked lease refuses before cache/HTTP.

Rejected: blanket auth.account exception, rewriting shared_account, duplicate resolver, reminting a carried credential, extending credential expiry, and acquiring custody before invalid backend arguments are rejected.

Grok design review initially failed for unspecified schema ordering and actor matching. Both requirements are explicitly incorporated above. Regression plan covers production backend and MetaMcp multi-user dispatch, real warm hit, Alice/Bob isolation, absent identity/strategy, revocation, legacy/shared isolation, mismatched carried credentials and no acquisition for invalid arguments. Existing shared_account and personal legacy positive controls remain. Implementation and confirmation review are pending; this receipt is not a release approval.
