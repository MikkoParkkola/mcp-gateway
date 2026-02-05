//! Intelligence Data Models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Supported Blockchain Networks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Chain {
    /// Solana Network
    Solana,
    /// Ethereum Mainnet
    Ethereum,
    /// Base Layer 2
    Base,
    /// Arbitrum Layer 2
    Arbitrum,
}

/// Movement of assets by large holders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhaleMovement {
    /// The chain where the movement occurred.
    pub chain: Chain,
    /// Transaction hash.
    pub tx_hash: String,
    /// Sender address.
    pub from_address: String,
    /// Receiver address.
    pub to_address: String,
    /// Asset symbol.
    pub asset: String,
    /// Amount in native units.
    pub amount: f64,
    /// Estimated USD value.
    pub usd_value: f64,
    /// When it occurred.
    pub timestamp: DateTime<Utc>,
    /// Associated labels.
    pub labels: Vec<String>,
}

/// Side of a DEX swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwapSide {
    /// Token Purchase
    Buy,
    /// Token Sale
    Sell,
    /// Unknown side
    Unknown,
}

/// Swap event on a Decentralized Exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFlow {
    /// The chain where the swap occurred.
    pub chain: Chain,
    /// Name of the DEX.
    pub dex: String,
    /// Trading pair.
    pub pair: String,
    /// Side (Buy/Sell).
    pub side: SwapSide,
    /// Amount of token in.
    pub amount_in: f64,
    /// Amount of token out.
    pub amount_out: f64,
    /// Estimated USD value.
    pub usd_value: f64,
    /// When it occurred.
    pub timestamp: DateTime<Utc>,
}

/// Union of different insight types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "insight_type", content = "data")]
pub enum InsightData {
    /// Whale movement insight.
    Whale(WhaleMovement),
    /// DEX flow insight.
    Dex(DexFlow),
}

/// High-level market insight record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketInsight {
    /// Unique identifier.
    pub id: Uuid,
    /// Human-readable summary.
    pub summary: String,
    /// Detailed insight data.
    pub data: InsightData,
    /// Confidence level (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f32>,
    /// When the insight was generated.
    pub timestamp: DateTime<Utc>,
}
