// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.1 B5: the meta-MCP firewall and the direct route's firewall
//! hold one relay detector, so what one route records the other checks.

use std::sync::Arc;

use super::Gateway;
use crate::config::Config;

#[tokio::test]
async fn both_firewalls_share_one_relay_detector() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = "security:\n  firewall:\n    collusion:\n      action: observe\n";
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("the collusion section loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("meta-MCP builds")
        .meta_mcp;
    let direct = gateway.response_firewall(&meta);
    let meta_fw = meta
        .firewall
        .as_ref()
        .expect("the meta-MCP firewall is wired");
    let (a, b) = (meta_fw.collusion_detector(), direct.collusion_detector());
    let (a, b) = (
        a.expect("relay detection is on"),
        b.expect("relay detection is on"),
    );
    assert!(
        Arc::ptr_eq(a, b),
        "two detectors: a relay across routes goes unseen"
    );
}

/// MIK-8276: both firewalls startup builds exempt the keyring the gateway
/// mints continuations with (#2210). Random ciphertext holds a credential
/// shape about once in 20,000 envelopes; a firewall without the keyring
/// redacts it and refuses the question (-32600). The router's engine comes
/// from the same `response_firewall` that `run` calls.
#[tokio::test]
async fn both_firewalls_exempt_the_gateways_own_continuations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "{}\n").expect("write config");
    let config = Config::load(Some(&path)).expect("an empty config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("meta-MCP builds")
        .meta_mcp;
    let keys = meta.continuation();
    let meta_fw = meta
        .firewall
        .as_ref()
        .expect("the meta-MCP firewall is wired");
    let direct = gateway.response_firewall(&meta);
    for (name, fw) in [("meta-MCP", &**meta_fw), ("router", &*direct)] {
        assert!(
            fw.continuations_for_test()
                .is_some_and(|own| Arc::ptr_eq(&own, &keys)),
            "the {name} firewall does not exempt the gateway's keyring"
        );
    }
}
