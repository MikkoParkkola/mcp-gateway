// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! mcp-gateway Kubernetes operator — Enterprise Edition.
//!
//! Watches Gateway, MCPServer, Policy, TrustCardReference, and RuntimeProfile
//! custom resources and reconciles them into Kubernetes workload resources
//! (Deployment, Service, ConfigMap, NetworkPolicy, ServiceAccount, RBAC).
//!
//! MIK-6560: Kubernetes Operator + Enterprise Runtime Packaging

pub mod controller;
pub mod crd;
pub mod reconciler;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!("mcp-gateway-operator starting");

    let namespace = std::env::var("WATCH_NAMESPACE").unwrap_or_else(|_| "default".into());
    tracing::info!(%namespace, "watching namespace");

    controller::run(namespace).await
}
