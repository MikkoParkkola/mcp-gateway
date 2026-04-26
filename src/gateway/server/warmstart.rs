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
                Ok(()) if matches!(mode, WarmStartMode::Http) => {
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
                Ok(()) => {}
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
    use super::resolve_warm_start_names;

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
