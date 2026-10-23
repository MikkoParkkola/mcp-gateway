// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8666: a `personal_managed` descriptor without the resource or issuer an
//! account key binds to is refused with the same words before and after the key
//! projection moved into one constructor.

use super::{account_key_descriptor, compile_descriptor};
use crate::personal_accounts::config::AccountDescriptor;

fn without(field: &str) -> AccountDescriptor {
    let mut value = serde_json::json!({
        "mode": "personal_managed", "provider": "contoso",
        "resource": "https://api.example/", "issuer": "https://login.example"
    });
    value.as_object_mut().unwrap().remove(field);
    serde_json::from_value(value).unwrap()
}

#[test]
fn a_binding_and_a_compiled_descriptor_name_the_missing_key_fields() {
    for field in ["resource", "issuer"] {
        let Err(bound) = account_key_descriptor("api", "work", &without(field)) else {
            panic!("binding accepted a descriptor without {field}")
        };
        assert!(bound.to_string().contains("backend 'api' references personal_managed account descriptor 'work', which is missing the resource/issuer the account key is built from"), "{field}: {bound}");
        let Err(compiled) = compile_descriptor("work", &without(field)) else {
            panic!("compile accepted a descriptor without {field}")
        };
        assert!(compiled.to_string().contains("personal_managed account descriptor 'work' is missing the resource/issuer the account key is built from"), "{field}: {compiled}");
    }
}
