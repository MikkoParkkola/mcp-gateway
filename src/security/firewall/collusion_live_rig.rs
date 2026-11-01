// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test rig for relay detection that follows the published configuration
//! (ADR-029, amended): a firewall and the `LiveConfig` a gateway would run
//! it under, built from ONE configuration, so a fixture never pairs a
//! `block` detector with a generation that says `off`.
//!

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::config_reload::{Generation, LiveConfig};
use crate::gateway::router::AppState;

use super::{Firewall, FirewallConfig};

/// A firewall built from `firewall`, and a `LiveConfig` whose published
/// configuration carries that same firewall section over `live`'s other
/// settings and its resolved keys.
///
/// Keeping `live`'s keys matters: a fresh `LiveConfig::new` resolves
/// authentication from the configuration alone, and a fixture's keyed
/// callers would then carry no verified principal.
pub(crate) fn paired(firewall: FirewallConfig, live: &LiveConfig) -> (Firewall, LiveConfig) {
    let firewall = Firewall::from_config(firewall, None);
    let live = live_of(live, &firewall);
    (firewall, live)
}

/// `live`'s configuration with `firewall`'s own section in place of its
/// firewall section, and its resolved keys.
pub(crate) fn live_of(live: &LiveConfig, firewall: &Firewall) -> LiveConfig {
    let mut config = (*live.get()).clone();
    config.security.firewall = firewall.config.clone();
    LiveConfig::with_auth(config, Arc::clone(live.generation().auth()))
}

/// Publish, as `state`'s live config, the configuration `firewall` was
/// built from: for a fixture that hands its relay firewall to the Meta-MCP.
pub(crate) fn pair_state(state: &mut Arc<AppState>, firewall: &Firewall) {
    let live = live_of(&state.live_config, firewall);
    Arc::get_mut(state).expect("state is unique").live_config = Arc::new(live);
}

/// [`pair_state`] with the firewall the state's Meta-MCP runs, when it runs one.
pub(crate) fn pair_state_with_meta(state: &mut Arc<AppState>) {
    if let Some(firewall) = state.meta_mcp.firewall_for_test() {
        pair_state(state, &firewall);
    }
}

/// The firewall's receipt clock frozen at the call: a window of a second
/// cannot age out on a slow run, and only `advance_collusion_clock_for_test`
/// moves it.
pub(crate) fn freeze(firewall: &Firewall) {
    firewall.advance_collusion_clock_for_test(Duration::ZERO);
}

impl Firewall {
    /// The generation a gateway would publish for the configuration this
    /// firewall was built from: its view and its action agree with the
    /// firewall, for a test that judges a call under "the" generation.
    pub(crate) fn paired_generation_for_test(&self) -> Arc<Generation> {
        let mut config = Config::default();
        config.security.firewall = self.config.clone();
        LiveConfig::new(config).generation()
    }
}

/// A one-shot test hook, patterned on the generation build's `refuse_hook`:
/// armed on a current-thread runtime, run once at a production seam, with a
/// count of how often the seam was reached so a row cannot pass vacuously if
/// the seam moves.
#[derive(Default)]
pub(crate) struct Hook {
    action: std::cell::RefCell<Option<Box<dyn FnOnce()>>>,
    reached: std::cell::Cell<u32>,
}

impl Hook {
    /// Run `action` the next time the seam is reached.
    pub(crate) fn arm(&self, action: impl FnOnce() + 'static) {
        *self.action.borrow_mut() = Some(Box::new(action));
    }

    /// Called at the seam: count the visit and run the armed action, once.
    pub(crate) fn run(&self) {
        self.reached.set(self.reached.get() + 1);
        let action = self.action.borrow_mut().take();
        if let Some(action) = action {
            action();
        }
    }

    /// How many times the seam was reached on this thread.
    pub(crate) fn reached(&self) -> u32 {
        self.reached.get()
    }
}
