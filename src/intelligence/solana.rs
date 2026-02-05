//! Solana Intelligence Fetcher

use async_trait::async_trait;
use crate::error::Result;
use super::{ChainFetcher, models::{WhaleMovement, DexFlow, Chain, MarketInsight, InsightData, SwapSide}};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// Fetcher for Solana network intelligence.
pub struct SolanaFetcher {
    client: Client,
    api_key: String,
}

impl SolanaFetcher {
    /// Create a new Solana fetcher.
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
        }
    }

    async fn get_helius_transactions(&self) -> Result<Vec<Value>> {
        // Helius Enhanced Transactions API: https://docs.helius.dev/solana-api-reference/enhanced-transactions-api
        let url = "https://api.helius.xyz/v0/transactions";

        let response = self.client.get(url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?;
        
        let response = response.error_for_status()?;
        let txs = response.json::<Vec<Value>>().await?;
        Ok(txs)
    }

    fn parse_whale_movements(&self, txs: &[Value]) -> Vec<WhaleMovement> {
        let mut whales = Vec::new();

        for tx in txs {
            if tx["type"] == "TRANSFER" {
                if let Some(native_transfers) = tx["nativeTransfers"].as_array() {
                    for nt in native_transfers {
                        let amount_lamports = nt["amount"].as_f64().unwrap_or(0.0);
                        let amount_sol = amount_lamports / 1_000_000_000.0;
                        
                        // Threshold: > 100 SOL
                        if amount_sol > 100.0 {
                            whales.push(WhaleMovement {
                                chain: Chain::Solana,
                                tx_hash: tx["signature"].as_str().unwrap_or("unknown").to_string(),
                                from_address: nt["fromUserAccount"].as_str().unwrap_or("unknown").to_string(),
                                to_address: nt["toUserAccount"].as_str().unwrap_or("unknown").to_string(),
                                asset: "SOL".to_string(),
                                amount: amount_sol,
                                usd_value: 0.0, // Price data unavailable without dedicated oracle
                                timestamp: chrono::Utc::now(), 
                                labels: vec!["Solana Whale".to_string()],
                            });
                        }
                    }
                }
            }
        }

        whales
    }

    fn parse_dex_flows(&self, txs: &[Value]) -> Vec<DexFlow> {
        let mut flows = Vec::new();

        for tx in txs {
            if tx["type"] == "SWAP" {
                if let Some(token_transfers) = tx["tokenTransfers"].as_array() {
                    if token_transfers.len() >= 2 {
                        let in_transfer = &token_transfers[0];
                        let out_transfer = &token_transfers[1];

                        flows.push(DexFlow {
                            chain: Chain::Solana,
                            dex: tx["source"].as_str().unwrap_or("Unknown DEX").to_string(),
                            pair: format!("{}/{}", 
                                in_transfer["mint"].as_str().unwrap_or("unknown"), 
                                out_transfer["mint"].as_str().unwrap_or("unknown")),
                            side: SwapSide::Unknown,
                            amount_in: in_transfer["tokenAmount"].as_f64().unwrap_or(0.0),
                            amount_out: out_transfer["tokenAmount"].as_f64().unwrap_or(0.0),
                            usd_value: 0.0, 
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        flows
    }
}

#[async_trait]
impl ChainFetcher for SolanaFetcher {
    async fn fetch_insights(&self) -> Result<Vec<MarketInsight>> {
        if self.api_key.is_empty() {
            return Ok(vec![]);
        }
        
        let txs = self.get_helius_transactions().await?;
        let mut insights = Vec::new();

        // Parse whale movements
        for movement in self.parse_whale_movements(&txs) {
            insights.push(MarketInsight {
                id: uuid::Uuid::new_v4(),
                summary: format!("Whale Alert: {} {} moved on {:?}", movement.amount, movement.asset, movement.chain),
                data: InsightData::Whale(movement),
                confidence_score: None,
                timestamp: chrono::Utc::now(),
            });
        }

        // Parse DEX flows
        for flow in self.parse_dex_flows(&txs) {
            insights.push(MarketInsight {
                id: uuid::Uuid::new_v4(),
                summary: format!("DEX Signal: {} swap on {} ", flow.pair, flow.dex),
                data: InsightData::Dex(flow),
                confidence_score: None,
                timestamp: chrono::Utc::now(),
            });
        }

        Ok(insights)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_solana_fetcher_new() {
        let fetcher = SolanaFetcher::new("test_key".to_string());
        assert_eq!(fetcher.api_key, "test_key");
    }

    #[tokio::test]
    async fn test_parse_helius_tx_to_whale_movement() {
        let tx_json = r#"{
            "description": "Account A transferred 1000 SOL to Account B",
            "type": "TRANSFER",
            "source": "SYSTEM_PROGRAM",
            "fee": 5000,
            "signature": "sig123",
            "timestamp": 1670000000,
            "nativeTransfers": [
                {
                    "fromUserAccount": "addr_from",
                    "toUserAccount": "addr_to",
                    "amount": 1000000000000
                }
            ]
        }"#;
        let tx: Value = serde_json::from_str(tx_json).unwrap();
        let fetcher = SolanaFetcher::new("test_key".to_string());
        let whales = fetcher.parse_whale_movements(&[tx]);
        
        assert_eq!(whales.len(), 1);
        assert_eq!(whales[0].amount, 1000.0);
        assert_eq!(whales[0].asset, "SOL");
        assert_eq!(whales[0].tx_hash, "sig123");
    }

    #[tokio::test]
    async fn test_parse_helius_tx_to_dex_flow() {
        let tx_json = r#"{
            "type": "SWAP",
            "source": "RAYDIUM",
            "tokenTransfers": [
                {
                    "tokenAmount": 100.0,
                    "mint": "token_a"
                },
                {
                    "tokenAmount": 5.0,
                    "mint": "token_b"
                }
            ]
        }"#;
        let tx: Value = serde_json::from_str(tx_json).unwrap();
        let fetcher = SolanaFetcher::new("test_key".to_string());
        let flows = fetcher.parse_dex_flows(&[tx]);
        
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].dex, "RAYDIUM");
        assert_eq!(flows[0].amount_in, 100.0);
        assert_eq!(flows[0].amount_out, 5.0);
        assert_eq!(flows[0].pair, "token_a/token_b");
    }
}
