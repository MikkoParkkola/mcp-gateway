// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test rig for relay detection that follows the published configuration
//! (ADR-029, amended): a firewall and the `LiveConfig` a gateway would run
//! it under, built from ONE configuration, so a fixture never pairs a
//! `block` detector with a generation that says `off`.
//!

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::Config;
use crate::config_reload::{Generation, LiveConfig};
use crate::gateway::router::AppState;

use super::{
    AllowedFlow, CollusionAction, CollusionConfig, Firewall, FirewallAction, FirewallConfig,
    FirewallVerdict, RelayCaller,
};

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

    /// [`Self::check_relay`] under [`Self::paired_generation_for_test`]'s view.
    pub(crate) fn check_relay_paired(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        params: &Value,
        audit: (&str, &str),
    ) -> FirewallVerdict {
        let generation = self.paired_generation_for_test();
        self.check_relay(
            generation.collusion_view(),
            caller,
            server,
            tool,
            params,
            audit,
        )
    }

    /// [`Self::relay_block_message`] under the paired generation's view.
    pub(crate) fn relay_block_message_paired(
        &self,
        caller: RelayCaller<'_>,
        target: (&str, &str),
        params: &Value,
        audit: (&str, &str),
    ) -> Option<String> {
        let generation = self.paired_generation_for_test();
        self.relay_block_message(generation.collusion_view(), caller, target, params, audit)
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

/// Ordinary prose, long enough for several fingerprints.
pub(crate) const PROSE: &str = "The orchard ledger for the north slope records seven rows of late \
    pears, the grafting dates for each rootstock, the hours the drip lines ran during the dry \
    weeks of August, and which crew pruned the older trees after the second frost.";

/// A result carrying the gateway's own sensitive classification: the fact
/// is inferred from the result, not from any `sources` list.
pub(crate) fn classified(text: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "_context_integrity": {"classification": {"data_classes": ["personal_data"]}},
    })
}

/// A plain text result.
pub(crate) fn plain(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

/// `source -> egress` as an `allowed_flows` entry.
pub(crate) fn flow(source: &str, egress: &str) -> AllowedFlow {
    AllowedFlow {
        source: source.to_string(),
        egress: egress.to_string(),
    }
}

/// A configuration whose collusion section runs `action` over `sources` and
/// `flows`, one match enough, a 600 s window.
pub(crate) fn config(
    action: CollusionAction,
    sources: &[&str],
    flows: Vec<AllowedFlow>,
) -> crate::config::Config {
    let mut config = Config::default();
    config.security.firewall = FirewallConfig {
        collusion: CollusionConfig {
            action,
            min_matches: 1,
            sources: sources.iter().map(|s| (*s).to_string()).collect(),
            allowed_flows: flows,
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    config
}

/// Why a relay was reported, as the finding's wording names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    Relay,
    OtherSource,
    Capacity,
}

/// The reason in `verdict`'s finding; `None` for no finding.
pub(crate) fn why(verdict: &FirewallVerdict) -> Option<Why> {
    let description = &verdict.findings.first()?.description;
    Some(if description.contains("different tool") {
        Why::OtherSource
    } else if description.contains("capacity") || description.contains("ran out of room") {
        Why::Capacity
    } else {
        Why::Relay
    })
}

/// `verdict` is a `-32002` refusal.
pub(crate) fn refused(verdict: &FirewallVerdict) -> bool {
    !verdict.allowed && verdict.action == FirewallAction::Block
}

/// `verdict` is an observed relay: allowed, warned, one finding.
pub(crate) fn observed(verdict: &FirewallVerdict) -> bool {
    verdict.allowed && verdict.action == FirewallAction::Warn && verdict.findings.len() == 1
}

impl Rig {
    /// Record `result` as delivered to `who` from `server:tool`, under
    /// `generation`.
    pub(crate) fn deliver(
        &self,
        who: &str,
        (server, tool): (&str, &str),
        result: &Value,
        generation: &Generation,
    ) {
        // No detector (a startup `off` on base) means nothing to record: the
        // row then fails at its own assertion, not here.
        let Some(digest) = self.firewall.delivery_digest(server, tool, result) else {
            return;
        };
        self.firewall
            .record_digest(RelayCaller::Keyed(who), server, tool, &digest, generation);
    }

    /// The verdict on `who` sending `text` through `server:tool`, judged
    /// under `generation`'s view.
    pub(crate) fn relays(
        &self,
        who: &str,
        (server, tool): (&str, &str),
        text: &str,
        generation: &Generation,
    ) -> FirewallVerdict {
        let params = json!({"name": tool, "arguments": {"text": text}});
        self.firewall.check_relay(
            generation.collusion_view(),
            RelayCaller::Keyed(who),
            server,
            tool,
            &params,
            ("s", who),
        )
    }
}

/// A firewall and its live configuration, with the generation a row pins.
pub(crate) struct Rig {
    pub(crate) firewall: Arc<Firewall>,
    pub(crate) live: Arc<LiveConfig>,
}

impl Rig {
    /// Build both from `config`, every k-gram kept and the clock frozen.
    pub(crate) fn new(config: Config) -> Self {
        let firewall = Firewall::from_config(config.security.firewall.clone(), None)
            .keyed_for_test()
            .keeping_every_kgram();
        freeze(&firewall);
        let firewall = Arc::new(firewall);
        Self {
            firewall,
            live: Arc::new(LiveConfig::new(config)),
        }
    }

    /// Publish the current configuration edited by `edit`.
    pub(crate) fn reload(&self, edit: impl FnOnce(&mut Config)) {
        let mut config = (*self.live.get()).clone();
        edit(&mut config);
        self.live.set(config);
    }

    /// The generation published now, to be held as a request's pinned one.
    pub(crate) fn generation(&self) -> Arc<Generation> {
        self.live.generation()
    }

    /// Let every receipt recorded so far lapse by `by`.
    pub(crate) fn lapse(&self, by: Duration) {
        self.firewall.advance_collusion_clock_for_test(by);
    }
}

/// A text of exactly one k-gram (48 normalised characters), unique per `i`:
/// with every k-gram kept it is one fingerprint, so a counter or a budget
/// moves once per delivery of it.
pub(crate) fn one_fp(i: u64) -> String {
    format!("{i:0>48}")
}
