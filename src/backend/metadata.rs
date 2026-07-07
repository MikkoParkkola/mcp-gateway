//! Cached metadata accessors: tools, resources, resource templates, and
//! prompts, each backed by a single-flight [`super::cached_metadata::CachedMetadata`]
//! slot on [`super::Backend`].

use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use super::Backend;
use super::annotations::normalize_tool_annotations;
use super::cached_metadata::CachedMetadata;
use crate::Error;
use crate::Result;
use crate::protocol::{
    Prompt, PromptsListResult, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult, Tool, ToolsListResult,
};

impl Backend {
    /// Get cached tools (or fetch if needed)
    ///
    /// Check if this backend has cached tools (non-blocking).
    ///
    /// Returns `true` if tools are cached and the cache hasn't expired.
    /// Used by `search_tools` to skip unstarted backends.
    #[must_use]
    pub fn has_cached_tools(&self) -> bool {
        self.tools_cache.is_fresh(self.cache_ttl)
    }

    /// Return the number of tools in the cache (non-blocking, no network I/O).
    ///
    /// Returns `0` when the cache is empty or has never been populated.
    /// This is intentionally best-effort: it reads whatever is in the cache
    /// without triggering a refresh, so the count may be stale.
    #[must_use]
    pub fn cached_tools_count(&self) -> usize {
        self.tools_cache
            .with_cached(|tools| tools.map_or(0, |tools| tools.len()))
    }

    /// Return the names of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty `Vec` when the cache is empty or has never been populated.
    /// Intended for producing "did you mean?" suggestions on unknown tool names.
    #[must_use]
    pub fn get_cached_tool_names(&self) -> Vec<String> {
        self.tools_cache.with_cached(|tools| {
            tools
                .map(|tools| tools.iter().map(|t| t.name.clone()).collect())
                .unwrap_or_default()
        })
    }

    /// Return a single tool by exact name from the cache (non-blocking, no network I/O).
    ///
    /// Returns `None` when the cache is empty, has never been populated, or does
    /// not contain a tool with the given name.  Intended for resolving surfaced
    /// tool schemas at `tools/list` time.
    #[must_use]
    pub fn get_cached_tool(&self, name: &str) -> Option<Tool> {
        self.tools_cache.with_cached(|tools| {
            tools.and_then(|tools| tools.iter().find(|t| t.name == name).cloned())
        })
    }

    /// Return a snapshot of all cached tools (non-blocking, no network I/O).
    ///
    /// Returns an empty shared vector when the cache is empty or has never been
    /// populated. Used by the `spec-preview` filtered `tools/list`
    /// implementation to avoid cloning the full tool list on every cache hit.
    #[must_use]
    pub fn get_cached_tools_snapshot(&self) -> Arc<Vec<Tool>> {
        self.tools_cache
            .snapshot_shared()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    async fn get_cached_list_shared<T, F>(
        &self,
        cache: &CachedMetadata<Vec<T>>,
        method: &str,
        kind: &'static str,
        parse: F,
    ) -> Result<Arc<Vec<T>>>
    where
        F: Fn(Value) -> Result<Vec<T>>,
    {
        cache
            .get_or_fetch_shared(self.cache_ttl, || async {
                self.ensure_started().await?;

                let response = self.request_internal(method, None).await?;
                if let Some(error) = response.error {
                    return Err(Error::json_rpc(error.code, error.message));
                }
                let items = if let Some(result) = response.result {
                    parse(result)?
                } else {
                    Vec::new()
                };

                debug!(backend = %self.name, kind, count = items.len(), "Backend metadata cached");

                Ok(items)
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools_shared(&self) -> Result<Arc<Vec<Tool>>> {
        self.get_cached_list_shared(&self.tools_cache, "tools/list", "tools", |result| {
            let mut tools = serde_json::from_value::<ToolsListResult>(result)?.tools;
            normalize_tool_annotations(&self.name, &mut tools);
            Ok(tools)
        })
        .await
    }

    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    pub async fn get_tools(&self) -> Result<Vec<Tool>> {
        self.get_tools_shared()
            .await
            .map(|tools| tools.as_ref().clone())
    }

    /// Get cached resources (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_shared(&self) -> Result<Arc<Vec<Resource>>> {
        self.get_cached_list_shared(
            &self.resources_cache,
            "resources/list",
            "resources",
            |result| Ok(serde_json::from_value::<ResourcesListResult>(result)?.resources),
        )
        .await
    }

    /// Get cached resources (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources(&self) -> Result<Vec<Resource>> {
        self.get_resources_shared()
            .await
            .map(|resources| resources.as_ref().clone())
    }

    /// Get cached resource templates (or fetch if needed) without cloning the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_shared(&self) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_cached_list_shared(
            &self.resource_templates_cache,
            "resources/templates/list",
            "resource_templates",
            |result| {
                Ok(
                    serde_json::from_value::<ResourcesTemplatesListResult>(result)?
                        .resource_templates,
                )
            },
        )
        .await
    }

    /// Get cached resource templates (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates(&self) -> Result<Vec<ResourceTemplate>> {
        self.get_resource_templates_shared()
            .await
            .map(|templates| templates.as_ref().clone())
    }

    /// Get cached prompts (or fetch if needed) without cloning the cached list.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_shared(&self) -> Result<Arc<Vec<Prompt>>> {
        self.get_cached_list_shared(&self.prompts_cache, "prompts/list", "prompts", |result| {
            Ok(serde_json::from_value::<PromptsListResult>(result)?.prompts)
        })
        .await
    }

    /// Get cached prompts (or fetch if needed)
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts(&self) -> Result<Vec<Prompt>> {
        self.get_prompts_shared()
            .await
            .map(|prompts| prompts.as_ref().clone())
    }
}
