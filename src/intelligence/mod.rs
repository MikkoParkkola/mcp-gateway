//! Market Intelligence Integration
//!
//! Provides on-chain insights for various networks.

pub mod models;
pub mod solana;
pub mod ethereum;
pub mod manager;

use async_trait::async_trait;
use crate::error::Result;
use models::{WhaleMovement, DexFlow};

/// Trait for chain-specific intelligence fetchers.
#[async_trait]
pub trait ChainFetcher: Send + Sync {
    /// Fetch recent whale movements.
    async fn fetch_whale_movements(&self) -> Result<Vec<WhaleMovement>>;
    /// Fetch recent DEX flows.
    async fn fetch_dex_flows(&self) -> Result<Vec<DexFlow>>;
}
