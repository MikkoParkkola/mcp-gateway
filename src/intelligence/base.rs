//! Base Intelligence Fetcher

use async_trait::async_trait;
use crate::error::Result;
use super::{ChainFetcher, models::{DexFlow, Chain, MarketInsight, InsightData, SwapSide}};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// Fetcher for Base network intelligence.
pub struct BaseFetcher {
    client: Client,
}

impl BaseFetcher {
    /// Create a new Base fetcher.
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
        }
    }
}

#[async_trait]
impl ChainFetcher for BaseFetcher {
    async fn fetch_insights(&self) -> Result<Vec<MarketInsight>> {
        // Use DexScreener API to get trending Base pairs
        let url = "https://api.dexscreener.com/latest/dex/search/?q=base";
        let response = self.client.get(url).send().await?;
        let response = response.error_for_status()?;
        let data = response.json::<Value>().await?;
        
        let mut insights = Vec::new();
        if let Some(pairs) = data["pairs"].as_array() {
            for pair in pairs.iter().take(5) {
                if pair["chainId"] == "base" {
                    let flow = DexFlow {
                        chain: Chain::Base,
                        dex: pair["dexId"].as_str().unwrap_or("Unknown").to_string(),
                        pair: format!("{}/{}", 
                            pair["baseToken"]["symbol"].as_str().unwrap_or("?"), 
                            pair["quoteToken"]["symbol"].as_str().unwrap_or("?")),
                        side: SwapSide::Unknown,
                        amount_in: 0.0,
                        amount_out: 0.0,
                        usd_value: pair["volume"]["h24"].as_f64().unwrap_or(0.0),
                        timestamp: chrono::Utc::now(),
                    };

                    insights.push(MarketInsight {
                        id: uuid::Uuid::new_v4(),
                        summary: format!("DEX Signal: {} volume on {} ({})", flow.pair, flow.dex, flow.usd_value),
                        data: InsightData::Dex(flow),
                        confidence_score: None,
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
        
        Ok(insights)
    }
}

impl Default for BaseFetcher {
    fn default() -> Self {
        Self::new()
    }
}
