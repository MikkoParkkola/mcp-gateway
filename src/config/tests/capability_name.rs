// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8358.CAPCFG.1: the capabilities backend shares the registry's name
//! space. A `capabilities.name` equal to a registry backend name is refused,
//! whichever side is enabled (MIK-8298: switching a section on never
//! surfaces an inert rule for the first time).

use super::*;

/// A backend that validates on its own: a stdio command.
fn stdio_backend(enabled: bool) -> BackendConfig {
    BackendConfig {
        enabled,
        transport: TransportConfig::Stdio {
            command: "my-server".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    }
}

/// A config whose registry holds one stdio backend named `backend`.
fn with_backend(backend: &str, capabilities: &str, enabled: (bool, bool)) -> Config {
    let mut config = Config::default();
    config
        .backends
        .insert(backend.to_string(), stdio_backend(enabled.0));
    config.capabilities.name = capabilities.to_string();
    config.capabilities.enabled = enabled.1;
    config
}

/// Red on the line: the colliding config validates.
#[test]
fn a_capabilities_name_equal_to_a_backend_name_is_refused() {
    for enabled in [(true, true), (true, false), (false, true), (false, false)] {
        let result = with_backend("tools", "tools", enabled).validate();
        let Err(crate::Error::ConfigValidation(message)) = result else {
            panic!("CAPCFG.1 enabled={enabled:?}: the collision loads: {result:?}");
        };
        assert!(
            message.contains("capabilities.name") && message.contains("backends.tools"),
            "CAPCFG.1 enabled={enabled:?}: the refusal names both sides: {message}"
        );
    }
}

/// The default capabilities name collides with a backend of that name too.
#[test]
fn the_default_capabilities_name_collides_with_a_backend_named_gateway() {
    let mut config = Config::default();
    config
        .backends
        .insert("gateway".to_string(), stdio_backend(true));
    assert!(
        matches!(config.validate(), Err(crate::Error::ConfigValidation(m)) if m.contains("backends.gateway")),
        "CAPCFG.1: the default name is a name"
    );
}

/// Control: the same backend under another name validates, so the refusal
/// above is the collision and nothing else.
#[test]
fn distinct_names_still_validate() {
    let result = with_backend("tools", "capabilities", (true, true)).validate();
    assert!(result.is_ok(), "CAPCFG.1 control: {result:?}");
}
