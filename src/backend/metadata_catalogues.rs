// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resources, resource-template and prompts accessors on
//! [`super::Backend`], each filled through the shared `get_cached_list_for`.

use std::sync::Arc;

use super::super::fill_check::FillBound;
use super::{Backend, ListFamily, resources_truncated_flag};
use crate::Result;
use crate::protocol::{
    Prompt, PromptsListResult, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult,
};
use crate::transport::LentCredential;

impl Backend {
    /// The resource catalogue the SHARED slot serves.
    ///
    /// For readers that hold no caller: startup prefetch, the operator UI and
    /// the provider adapter.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_shared(&self) -> Result<Arc<Vec<Resource>>> {
        self.get_resources_for_binding_lent(None, LentCredential::default())
            .await
    }

    /// The resource catalogue THIS CALLER's pool slot serves.
    ///
    /// Same contract as [`Self::get_tools_for_binding`]: `binding` is the
    /// caller's `PropagatedCredential::cache_binding`, everything that is not a
    /// propagating backend with a binding collapses to the shared slot, and `extra_headers` are the headers that slot's transport was
    /// opened with — carried on a `PerUser` slot, dropped on the shared one.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the resources request fails.
    pub async fn get_resources_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<Resource>>> {
        self.get_resources_for_binding_lent(binding, LentCredential::unchecked(extra_headers))
            .await
    }

    /// [`Self::get_resources_for_binding`] for a credential the mint core produced,
    /// which may carry the send check the plain-slice entry cannot express.
    pub(crate) async fn get_resources_for_binding_lent(
        &self,
        binding: Option<&str>,
        extra_headers: LentCredential,
    ) -> Result<Arc<Vec<Resource>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.resources_cache,
            ListFamily {
                method: "resources/list",
                kind: "resources",
                list_key: "resources",
                truncated_flag: Some(resources_truncated_flag),
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                Ok((
                    serde_json::from_value::<ResourcesListResult>(result)?.resources,
                    None,
                ))
            },
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

    /// The resource-template catalogue the SHARED slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_shared(&self) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_resource_templates_for_binding_lent(None, LentCredential::default())
            .await
    }

    /// The resource-template catalogue THIS CALLER's pool slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the templates request fails.
    pub async fn get_resource_templates_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_resource_templates_for_binding_lent(
            binding,
            LentCredential::unchecked(extra_headers),
        )
        .await
    }

    /// [`Self::get_resource_templates_for_binding`] for a credential the mint core produced,
    /// which may carry the send check the plain-slice entry cannot express.
    pub(crate) async fn get_resource_templates_for_binding_lent(
        &self,
        binding: Option<&str>,
        extra_headers: LentCredential,
    ) -> Result<Arc<Vec<ResourceTemplate>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.resource_templates_cache,
            ListFamily {
                method: "resources/templates/list",
                kind: "resource_templates",
                list_key: "resourceTemplates",
                truncated_flag: None,
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                let templates = serde_json::from_value::<ResourcesTemplatesListResult>(result)?;
                Ok((templates.resource_templates, None))
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

    /// The prompt catalogue the SHARED slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_shared(&self) -> Result<Arc<Vec<Prompt>>> {
        self.get_prompts_for_binding_lent(None, LentCredential::default())
            .await
    }

    /// The prompt catalogue THIS CALLER's pool slot serves.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the prompts request fails.
    pub async fn get_prompts_for_binding(
        &self,
        binding: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<Arc<Vec<Prompt>>> {
        self.get_prompts_for_binding_lent(binding, LentCredential::unchecked(extra_headers))
            .await
    }

    /// [`Self::get_prompts_for_binding`] for a credential the mint core produced,
    /// which may carry the send check the plain-slice entry cannot express.
    pub(crate) async fn get_prompts_for_binding_lent(
        &self,
        binding: Option<&str>,
        extra_headers: LentCredential,
    ) -> Result<Arc<Vec<Prompt>>> {
        self.get_cached_list_for(
            binding,
            |entry| &entry.prompts_cache,
            ListFamily {
                method: "prompts/list",
                kind: "prompts",
                list_key: "prompts",
                truncated_flag: None,
                cooldown: false,
                stale_hit: false,
            },
            extra_headers,
            FillBound::DrainBudget,
            |result| {
                Ok((
                    serde_json::from_value::<PromptsListResult>(result)?.prompts,
                    None,
                ))
            },
        )
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
