// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Caller-addressed external-state detection.

use super::CapabilityDefinition;

/// `true` when this capability hands a caller-chosen destination to a third
/// party that will later call it.
///
/// Such a call creates persistent state outside this gateway, addressed by the
/// caller and authorised by the operator's credential — an out-of-band channel
/// that needs no readable response. `linear_create_webhook` is the shape:
/// a URL parameter, posted to Linear, which then delivers events to it.
///
/// Derived from the definition rather than a hand-kept list, so a capability
/// added later inherits the rule instead of needing to be remembered. The
/// ticket that filed this recorded a hand count of six URL-taking capabilities;
/// the count was wrong, which is the argument for deriving it.
#[must_use]
pub fn creates_caller_addressed_external_state(def: &CapabilityDefinition) -> bool {
    // Not an HTTP method test: a capability backed by a CLI has no method, and
    // `gws_gmail_watch` — which registers a Pub/Sub topic — is exactly that. A
    // read-only capability cannot register anything, so that flag is the
    // transport-independent question, with the method as a fallback where the
    // flag was left at its default.
    // An explicit `read_only: true` settles it. The previous form OR'd the
    // provider method in, so a capability that declared itself read-only but
    // reached its API with POST — which plenty do — was treated as mutating,
    // and an unauthenticated laptop client lost a tool it should have.
    if def.metadata.read_only {
        return false;
    }
    // An explicit declaration wins over EVERY inference below, which is why it
    // is read here rather than further down. Name inference is a fallback, not
    // the contract: `gws_gmail_watch` registers a Pub/Sub topic, whose
    // destination is not a URL and whose name is not "webhook", and inference
    // alone missed it. Read after the inference short-circuits — as it was
    // until MIK-7262 — the declaration lost to the very heuristics it exists to
    // overrule: a GET-reached or `properties`-less definition returned `false`
    // before anyone looked at what its author said.
    // It stays BELOW `read_only` deliberately: that flag is also an author
    // declaration, and the older one. Two explicit declarations in conflict
    // resolve to read-only rather than silently reversing the ruling above.
    if let Some(declared) = def.metadata.registers_external_callback {
        return declared;
    }
    let mutating = def
        .providers
        .named
        .values()
        .chain(def.providers.fallback.iter())
        .any(|p| {
            matches!(
                p.config.method.to_ascii_uppercase().as_str(),
                "POST" | "PUT" | "PATCH"
            )
        })
        // A CLI-backed capability has no HTTP method; not being read-only is
        // what makes it mutating there.
        || def.providers.named.values().any(|p| p.service == "cli");
    if !mutating {
        return false;
    }
    let Some(props) = def
        .schema
        .input
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return false;
    };
    // Narrow deliberately. "Mutating, and takes a URL" is too broad: archiving a
    // page or attaching a link posts a URL as DATA, and blocking those behind
    // admin would take ordinary tools away from the single-user client for no
    // security gain. What matters is REGISTERING an address the third party
    // will later deliver to.
    let name = def.name.to_ascii_lowercase();
    let registers_a_callback = ["webhook", "subscribe", "callback", "watch", "notify"]
        .iter()
        .any(|k| name.contains(k));
    if !registers_a_callback {
        return false;
    }

    props.iter().any(|(name, spec)| {
        let lower = name.to_ascii_lowercase();
        // Not only URLs. A Pub/Sub topic, a queue name or an address is just as
        // much a caller-chosen destination that a third party will deliver to.
        let looks_like_a_destination = lower == "url"
            || lower.ends_with("_url")
            || lower == "callback"
            || lower == "webhook"
            || lower == "endpoint"
            || lower == "address"
            || lower.contains("topic")
            || lower.contains("queue")
            || lower.contains("channel");
        let declared_uri = spec.get("format").and_then(|f| f.as_str()) == Some("uri");
        looks_like_a_destination || declared_uri
    })
}
