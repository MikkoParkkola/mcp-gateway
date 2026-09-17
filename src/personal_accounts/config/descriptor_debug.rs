// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Manual `Debug` for `AccountDescriptor`.
//!
//! The derived implementation rendered `client_secret_ref` verbatim, so any
//! descriptor reaching a log line, a panic message or an error chain carried
//! the secret reference with it. Presence is diagnostically useful and is
//! kept; the string itself never is. Serialization is untouched -- the
//! reference must still round-trip through configuration.

use std::fmt;

use super::AccountDescriptor;

impl fmt::Debug for AccountDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountDescriptor")
            .field("mode", &self.mode)
            .field("provider", &self.provider)
            .field("resource", &self.resource)
            .field("issuer", &self.issuer)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret_ref",
                &self.client_secret_ref.as_ref().map(|_| "<redacted>"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("send_resource_parameter", &self.send_resource_parameter)
            // Non-secret by construction: strategy kind, audience, session mode
            // and an endpoint URL. Its own `Debug` carries no credential.
            .field("external_strategy", &self.external_strategy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::AccountDescriptor;

    /// Minimal DTO: `mode` + `provider` are the only required fields, every
    /// other one defaults, so the fixture stays honest about what a descriptor
    /// needs to be formatted safely -- which is nothing but deserialization.
    fn descriptor(secret_ref: Option<&str>) -> AccountDescriptor {
        let mut value = serde_json::json!({
            "mode": "shared",
            "provider": "acme-directory",
        });
        if let Some(secret) = secret_ref {
            value["client_secret_ref"] = serde_json::Value::String(secret.to_string());
        }
        serde_json::from_value(value).expect("descriptor fixture must deserialize")
    }

    #[test]
    fn debug_redacts_client_secret_ref_but_keeps_nonsecret_metadata() {
        // Both shapes the configuration table admits: the sanctioned env
        // reference, and the inline literal that is a configuration error but
        // must still never reach a log line.
        for secret in [
            "env:ACCOUNT_LEAK_LINT_CLIENT_SECRET",
            "inline-9f3c-literal-not-an-env-reference",
        ] {
            let descriptor = descriptor(Some(secret));
            let rendered = format!("{descriptor:?}");

            assert!(
                rendered.contains("acme-directory"),
                "provider must survive Debug: {rendered}"
            );
            assert!(
                rendered.contains(&format!("{:?}", descriptor.mode)),
                "mode must survive Debug: {rendered}"
            );
            assert!(
                rendered.contains("client_secret_ref: Some("),
                "Option presence must survive Debug: {rendered}"
            );
            assert!(
                !rendered.contains(secret),
                "Debug leaked the client secret reference: {rendered}"
            );

            // Positive control: redaction is a formatting property only. The
            // field is still on the struct and still serializes verbatim.
            let serialized = serde_json::to_value(&descriptor).expect("descriptor must serialize");
            assert_eq!(serialized["client_secret_ref"], serde_json::json!(secret));
        }

        let absent = descriptor(None);
        let rendered = format!("{absent:?}");
        assert!(
            rendered.contains("acme-directory"),
            "provider must survive Debug: {rendered}"
        );
        assert!(
            rendered.contains("client_secret_ref: None"),
            "absence must render as absence: {rendered}"
        );
    }
}
