// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `config` with both request-path security flags off, as the fixtures that
//! include this set them on `AppState` before the flags moved into the
//! published config (ADR-023).

use mcp_gateway::config::Config;

pub fn flags_off(config: &Config) -> Config {
    let mut config = config.clone();
    config.security.sanitize_input = false;
    config.security.ssrf_protection = false;
    config
}
