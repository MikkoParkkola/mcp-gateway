// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Parse before any editor response can echo bytes, then judge typed headers.

use std::collections::HashSet;

use super::file_writer::{FieldError, Refused};
use super::{CapabilityDefinition, ProviderConfig};
use crate::config::secret_values::{Syntax, ValueClass, classify, credential_name};
use crate::yaml::Value;

/// Both parser shapes must be readable before pin, stale or write diagnostics.
/// The tree also catches entries a typed map would silently overwrite.
pub(crate) fn check(text: &str) -> Result<(), Refused> {
    let doc =
        crate::yaml::from_str::<Value>(text).map_err(|error| parse_refusal(error.location()))?;
    let capability = crate::yaml::from_str::<CapabilityDefinition>(text)
        .map_err(|error| parse_refusal(error.location()))?;
    let parameters = plain_inputs(&capability.schema.input);
    let declared = crate::validator::schema_helpers::input_property_names(&capability.schema.input);
    let syntax = Syntax::Brace { parameters };
    let source_collisions =
        crate::yaml::from_str::<SourceKeys>(text).map_err(|_| parse_refusal(None))?;
    if colliding_keys(&doc) || source_collisions.0 {
        // Keep the existing field refusal for a visible literal in either
        // duplicate entry. Nothing from a colliding map can ever be saved.
        refuse_colliding_headers(text, &doc, &syntax, &declared)?;
        return Err(parse_refusal(None));
    }
    let mut errors = Vec::new();
    let mut inspect = |name: &str, provider: &ProviderConfig| {
        for (header, value) in &provider.config.headers {
            if credential_name(header)
                && !safe_header(value, &syntax, &declared, |key| {
                    provider.config.static_params.contains_key(key)
                })
            {
                errors.push(header_error(name, header));
            }
        }
    };
    for (name, provider) in &capability.providers.named {
        inspect(name, provider);
    }
    for (index, provider) in capability.providers.fallback.iter().enumerate() {
        inspect(&format!("fallback[{index}]"), provider);
    }
    header_result(errors)
}

fn parse_refusal(at: Option<crate::yaml::Location>) -> Refused {
    Refused::Invalid {
        errors: vec![FieldError {
            line: at.map(|position| position.line()),
            column: at.map(|position| position.column()),
            field: None,
            message: "Capability YAML could not be parsed safely".to_owned(),
        }],
        patch: None,
    }
}

/// Tags do not distinguish keys for the typed loader; scalar text does not
/// distinguish a number/bool/null from a string with that normalized text.
fn colliding_keys(value: &Value) -> bool {
    match value.untag_ref() {
        Value::Mapping(mapping) => {
            let mut seen = HashSet::new();
            mapping.iter().any(|(key, value)| {
                let text = match key.untag_ref() {
                    Value::String(s) => Some(s.clone()),
                    Value::Bool(b) => Some(b.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Null => Some("null".to_owned()),
                    _ => None,
                };
                text.is_some_and(|text| !seen.insert(text))
                    || colliding_keys(key)
                    || colliding_keys(value)
            })
        }
        Value::Sequence(sequence) => sequence.iter().any(colliding_keys),
        _ => false,
    }
}

/// The generic tree loses the source spelling of scalar keys (`TRUE`,
/// `0x7b`). A String-key traversal also catches those keys paired with a
/// quoted copy, following aliases through the same deserializer as the loader.
struct SourceKeys(bool);

impl<'de> serde::Deserialize<'de> for SourceKeys {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::{EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
        struct Keys;
        impl<'de> Visitor<'de> for Keys {
            type Value = SourceKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a YAML value with scalar mapping keys")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<SourceKeys, E> {
                Ok(SourceKeys(false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SourceKeys, A::Error> {
                let mut collision = false;
                while let Some(SourceKeys(child)) = seq.next_element()? {
                    collision |= child;
                }
                Ok(SourceKeys(collision))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SourceKeys, A::Error> {
                let mut seen = HashSet::new();
                let mut collision = false;
                while let Some(key) = map.next_key::<String>()? {
                    collision |= !seen.insert(key);
                    collision |= map.next_value::<SourceKeys>()?.0;
                }
                Ok(SourceKeys(collision))
            }
            fn visit_enum<A: EnumAccess<'de>>(self, tagged: A) -> Result<SourceKeys, A::Error> {
                let (_, value) = tagged.variant::<serde::de::IgnoredAny>()?;
                value.newtype_variant()
            }
        }
        de.deserialize_any(Keys)
    }
}

fn plain_inputs(input: &serde_json::Value) -> HashSet<String> {
    let Some(root) = input.as_object() else {
        return HashSet::new();
    };
    if !root.iter().all(|(key, value)| match key.as_str() {
        "type" | "title" | "description" | "properties" | "required" => true,
        "additionalProperties" => value.is_boolean(),
        _ => false,
    }) {
        return HashSet::new();
    }
    let mut parameters = crate::validator::schema_helpers::input_property_names(input);
    parameters.retain(|name| {
        input["properties"][name]
            .as_object()
            .is_some_and(|property| {
                property.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "type"
                            | "title"
                            | "description"
                            | "format"
                            | "minLength"
                            | "maxLength"
                            | "minimum"
                            | "maximum"
                            | "pattern"
                    )
                })
            })
    });
    parameters
}

fn safe_header(
    value: &str,
    syntax: &Syntax,
    declared: &HashSet<String>,
    is_static: impl Fn(&str) -> bool,
) -> bool {
    let Syntax::Brace { parameters } = syntax else {
        return false;
    };
    let mut count = 0;
    let mut baked = false;
    let runtime = HashSet::new();
    let scanned = crate::secrets::fill_placeholders(value, |key| {
        count += 1;
        if !key.starts_with("env.") && !key.starts_with("keychain.") {
            baked |= is_static(key)
                || (declared.contains(key) && !parameters.contains(key))
                || (!parameters.contains(key)
                    && !super::validator::is_known_placeholder(key, &runtime));
        }
        Ok(None)
    });
    scanned.is_ok() && count == 1 && !baked && classify(value, syntax) == Ok(ValueClass::Kept)
}

fn header_error(provider: &str, header: &str) -> FieldError {
    FieldError {
        line: None,
        column: None,
        field: Some(format!("providers.{provider}.config.headers.{header}")),
        message: "Use {env.NAME} or {keychain.NAME}, optionally after one scheme prefix such as `Bearer `.".to_owned(),
    }
}

fn header_result(mut errors: Vec<FieldError>) -> Result<(), Refused> {
    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort_by(|a, b| a.field.cmp(&b.field));
        Err(Refused::LiteralCredential { errors })
    }
}

/// Only used to preserve field diagnostics on already-refused collisions.
/// Ordinary documents are inspected exclusively through their typed providers.
fn refuse_colliding_headers(
    text: &str,
    doc: &Value,
    syntax: &Syntax,
    declared: &HashSet<String>,
) -> Result<(), Refused> {
    let mut errors = Vec::new();
    let mut inspect = |name: &str, provider: &Value| {
        let Some(headers) = provider["config"]["headers"].as_mapping() else {
            return;
        };
        for (header, value) in headers {
            if let Some(header) = header.as_str()
                && credential_name(header)
                && !value.as_str().is_some_and(|value| {
                    safe_header(value, syntax, declared, |key| {
                        provider["config"]["static_params"].get(key).is_some()
                    })
                })
            {
                errors.push(header_error(name, header));
            }
        }
    };
    for (name, provider) in provider_entries_of(text, doc) {
        if name == "fallback"
            && let Some(entries) = provider.as_sequence()
        {
            for (index, entry) in entries.iter().enumerate() {
                inspect(&format!("fallback[{index}]"), entry);
            }
        } else {
            inspect(&name, &provider);
        }
    }
    header_result(errors)
}

/// The provider entries of `text` by the loader's own scalar-name semantics:
/// string deserialization keeps the source text of a name (even `TRUE` or
/// `0x7b`), which a `Value` tree has already normalized. When the document
/// does not deserialize that way, fall back to the tree so a malformed
/// unrelated key cannot hide a header from inspection.
fn provider_entries_of(text: &str, doc: &crate::yaml::Value) -> Vec<(String, crate::yaml::Value)> {
    use crate::yaml::Value;

    struct Entries;
    impl<'de> serde::de::Visitor<'de> for Entries {
        type Value = Vec<(String, Value)>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a provider mapping")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut entries = Vec::new();
            while let Some(entry) = map.next_entry()? {
                entries.push(entry);
            }
            Ok(entries)
        }
    }
    fn entries<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<(String, Value)>, D::Error> {
        de.deserialize_map(Entries)
    }
    #[derive(serde::Deserialize)]
    struct NamedProviders {
        #[serde(deserialize_with = "entries")]
        providers: Vec<(String, Value)>,
    }
    if let Ok(named) = crate::yaml::from_str::<NamedProviders>(text) {
        return named.providers;
    }
    doc.as_mapping()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.untag_ref().as_str() == Some("providers"))
        .filter_map(|(_, value)| value.as_mapping())
        .flatten()
        .map(|(name, provider)| {
            let name = match name.untag_ref() {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Null => "null".to_string(),
                _ => "[non-scalar]".to_string(),
            };
            (name, provider.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::file_writer::{preview, validate};
    use std::path::Path;

    fn document(header: &str) -> String {
        format!(
            "fulcrum: '1.0'\nname: kept\ndescription: header check\nschema:\n  input:\n    type: object\n    properties:\n      token:\n        type: string\nproviders:\n  primary:\n    config:\n      base_url: https://example.com\n      path: /\n      headers:\n        Authorization: '{header}'\n"
        )
    }

    #[test]
    fn safe_duplicate_values_are_still_refused_without_a_patch() {
        let base = document("{env.KEY}");
        for text in [
            base.replace("Authorization:", "!x Authorization:")
                + "        Authorization: '{env.OTHER}'\n",
            base.clone() + "extra: {123: a, '123': b}\n",
            base.clone() + "extra: [{!x true: a, 'true': b}]\n",
            base.clone() + "extra: {TRUE: a, 'TRUE': b}\n",
            base.clone() + "extra: {0x7b: a, '0x7b': b}\n",
            base.clone() + "extra: {&key TRUE: a, 'TRUE': b}\n",
        ] {
            assert!(matches!(
                check(&text),
                Err(Refused::Invalid { patch: None, .. })
            ));
            assert!(matches!(
                preview(&text, None),
                Err(Refused::Invalid { patch: None, .. })
            ));
        }
    }

    #[test]
    fn parse_failures_keep_only_parser_positions_even_before_pin_refusals() {
        let base = document("{env.KEY}");
        for text in [
            base.clone() + "        Authorization: 'secret-canary'\n",
            base.replace("  primary:", "  secret-canary:\n    timeout: []"),
            base.clone() + "broken: [secret-canary\n",
        ] {
            let error = crate::yaml::from_str::<Value>(&text)
                .err()
                .unwrap_or_else(|| {
                    crate::yaml::from_str::<CapabilityDefinition>(&text).expect_err("typed error")
                });
            let expected = error.location();
            let Err(Refused::Invalid {
                errors,
                patch: None,
            }) = preview(&text, Some("sha256: broken\n"))
            else {
                panic!("parse refusal must precede pin diagnostics");
            };
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].line, expected.map(|at| at.line()));
            assert_eq!(errors[0].column, expected.map(|at| at.column()));
            assert_eq!(errors[0].field, None);
            assert_eq!(
                errors[0].message,
                "Capability YAML could not be parsed safely"
            );
            assert_eq!(validate(&text, Path::new("kept.yaml"), None), Err(errors));
        }
    }

    #[test]
    fn schema_allowlist_and_typed_keys_cannot_bake_a_credential() {
        let base = document("{token}");
        for addition in [
            "default: secret",
            "$ref: '#/token'",
            "enum: [secret]",
            "const: secret",
            "examples: [secret]",
        ] {
            let text = base.replace(
                "        type: string",
                &format!("        type: string\n        {addition}"),
            );
            assert!(matches!(
                check(&text),
                Err(Refused::LiteralCredential { .. })
            ));
        }
        for addition in [
            "additionalProperties: {const: secret}",
            "anyOf: [{properties: {token: {const: secret}}}]",
        ] {
            let text = base.replace(
                "    type: object",
                &format!("    type: object\n    {addition}"),
            );
            assert!(matches!(
                check(&text),
                Err(Refused::LiteralCredential { .. })
            ));
        }
        assert!(
            check(&base.replace(
                "    type: object",
                "    type: object\n    additionalProperties: false"
            ))
            .is_ok()
        );
        for key in ["config", "headers"] {
            let text = document("secret").replace(&format!("{key}:"), &format!("!x {key}:"));
            assert!(matches!(
                check(&text),
                Err(Refused::LiteralCredential { .. })
            ));
        }
        let text = base.replace(
            "      headers:",
            "      !x static_params: {token: '{env.KEY}'}\n      headers:",
        );
        assert!(matches!(
            check(&text),
            Err(Refused::LiteralCredential { .. })
        ));
        assert!(matches!(
            check(&document("{env.A}{env.B}")),
            Err(Refused::LiteralCredential { .. })
        ));
    }
}
