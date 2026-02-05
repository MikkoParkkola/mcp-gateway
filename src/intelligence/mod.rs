//! Market Intelligence Integration
//!
//! Provides on-chain insights for various networks.

pub mod models;
pub mod solana;
pub mod ethereum;
pub mod base;
pub mod manager;

use async_trait::async_trait;
use crate::error::Result;
use models::MarketInsight;

/// Trait for chain-specific intelligence fetchers.
#[async_trait]
pub trait ChainFetcher: Send + Sync {
    /// Fetch all market insights for this chain.
    async fn fetch_insights(&self) -> Result<Vec<MarketInsight>>;
}
