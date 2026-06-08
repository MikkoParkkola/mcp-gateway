//! Backend warm-start orchestration shared by HTTP and stdio server modes.

use std::sync::Arc;

use tracing::{info, warn};

use crate::backend::BackendRegistry;

#[derive(Clone, Copy)]
pub(super) enum WarmStartMode {
    Http,
    Stdio,
}

pub(super) fn build_warm_start_list(
    backends: &BackendRegistry,
    configured: &[String],
    announce_selection: bool,
) -> Vec<String> {
    resolve_warm_start_names(
        configured,
        backends
            .all()
            .iter()
            .map(|backend| backend.name.clone())
            .collect(),
        announce_selection,
    )
}

/// Whether a successful warm-start should immediately prefetch (and cache) the
/// backend's tool list.
///
/// Tool discovery (`gateway_search` / `tools/list`) only surfaces backends with
/// a populated tool cache; an empty cache is skipped. Subprocess backends
/// (codex, other stdio command servers) therefore stay invisible unless their
/// tools are prefetched here. This must happen in **both** transport modes —
/// the gateway is commonly run via `serve --stdio` (how Claude Code / Codex
/// connect), and gating prefetch on HTTP-only left every stdio-mode subprocess
/// backend with zero discoverable tools (MIK-4649).
const fn warm_start_prefetches_tools(mode: WarmStartMode) -> bool {
    // Both modes prefetch: stdio-mode subprocess backends were previously left
    // with empty tool caches and zero discoverable tools (MIK-4649).
    matches!(mode, WarmStartMode::Http | WarmStartMode::Stdio)
}

pub(super) fn spawn_warm_start_task(
    backends: &Arc<BackendRegistry>,
    warm_start_list: Vec<String>,
    mode: WarmStartMode,
) {
    for name in warm_start_list {
        let backends = Arc::clone(backends);
        tokio::spawn(async move {
            let Some(backend) = backends.get(&name) else {
                if matches!(mode, WarmStartMode::Http) {
                    warn!(backend = %name, "Backend not found for warm-start");
                }
                return;
            };

            match backend.start().await {
                Ok(()) => {
                    if warm_start_prefetches_tools(mode) {
                        match backend.get_tools_shared().await {
                            Ok(tools) => info!(
                                backend = %name,
                                tools = tools.len(),
                                "Warm-started + tools cached"
                            ),
                            Err(e) => warn!(
                                backend = %name,
                                error = %e,
                                "Warm-started but tool prefetch failed"
                            ),
                        }
                    }
                }
                Err(e) if matches!(mode, WarmStartMode::Stdio) => {
                    warn!(backend = %name, error = %e, "Warm-start failed (stdio)");
                }
                Err(e) => warn!(backend = %name, error = %e, "Warm-start failed"),
            }
        });
    }
}

fn resolve_warm_start_names(
    configured: &[String],
    all_names: Vec<String>,
    announce_selection: bool,
) -> Vec<String> {
    if configured.is_empty() {
        if announce_selection {
            info!(
                "Warm-starting ALL {} backends (tool prefetch)",
                all_names.len()
            );
        }
        all_names
    } else {
        if announce_selection {
            info!("Warm-starting backends: {:?}", configured);
        }
        configured.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{WarmStartMode, resolve_warm_start_names, warm_start_prefetches_tools};

    #[test]
    fn warm_start_prefetches_tools_in_both_modes() {
        // Tool prefetch must happen regardless of transport mode. Gating it on
        // HTTP-only left every stdio-mode subprocess backend (e.g. codex) with
        // an empty tool cache, so its tools never appeared in discovery
        // (MIK-4649).
        assert!(
            warm_start_prefetches_tools(WarmStartMode::Http),
            "HTTP mode must prefetch tools"
        );
        assert!(
            warm_start_prefetches_tools(WarmStartMode::Stdio),
            "Stdio mode must prefetch tools (MIK-4649: codex tools were invisible)"
        );
    }

    #[test]
    fn resolve_warm_start_names_uses_all_backends_when_config_is_empty() {
        let resolved = resolve_warm_start_names(&[], vec!["a".to_string(), "b".to_string()], false);

        assert_eq!(resolved, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn resolve_warm_start_names_prefers_configured_list() {
        let resolved = resolve_warm_start_names(
            &["configured".to_string()],
            vec!["a".to_string(), "b".to_string()],
            false,
        );

        assert_eq!(resolved, vec!["configured".to_string()]);
    }
}
