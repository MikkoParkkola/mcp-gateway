//! Ethereum Intelligence Fetcher

use async_trait::async_trait;
use crate::error::Result;
use super::{ChainFetcher, models::{WhaleMovement, DexFlow, Chain}};
use reqwest::Client;
use serde_json::Value;

/// Fetcher for Ethereum network intelligence.
pub struct EthereumFetcher {
    client: Client,
    api_key: String,
}

impl EthereumFetcher {
    /// Create a new Ethereum fetcher.
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    async fn get_whale_alert_transactions(&self) -> Result<Vec<Value>> {
        // Whale Alert API: https://docs.whale-alert.io/
        let url = format!(
            "https://api.whale-alert.io/v1/transactions?api_key={}&min_value=500000",
            self.api_key
        );

        let response = self.client.get(url).send().await?;
        let data = response.json::<Value>().await?;
        
        let txs = data["transactions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
            
        Ok(txs)
    }

    fn parse_whale_movements(&self, txs: Vec<Value>) -> Vec<WhaleMovement> {
        let mut whales = Vec::new();

        for tx in txs {
            if tx["blockchain"] == "ethereum" {
                whales.push(WhaleMovement {
                    chain: Chain::Ethereum,
                    tx_hash: tx["hash"].as_str().unwrap_or("unknown").to_string(),
                    from_address: tx["from"]["address"].as_str().unwrap_or("unknown").to_string(),
                    to_address: tx["to"]["address"].as_str().unwrap_or("unknown").to_string(),
                    asset: tx["symbol"].as_str().unwrap_or("ETH").to_string(),
                    amount: tx["amount"].as_f64().unwrap_or(0.0),
                    usd_value: tx["amount_usd"].as_f64().unwrap_or(0.0),
                    timestamp: chrono::Utc::now(), // Simplified
                    labels: vec!["Ethereum Whale".to_string()],
                });
            }
        }

        whales
    }
}

#[async_trait]
impl ChainFetcher for EthereumFetcher {
    async fn fetch_whale_movements(&self) -> Result<Vec<WhaleMovement>> {
        if self.api_key.is_empty() {
            return Ok(vec![]);
        }
        let txs = self.get_whale_alert_transactions().await?;
        Ok(self.parse_whale_movements(txs))
    }

    async fn fetch_dex_flows(&self) -> Result<Vec<DexFlow>> {
        // Use DexScreener API to get trending Ethereum pairs
        let url = "https://api.dexscreener.com/latest/dex/search/?q=ethereum";
        let response = self.client.get(url).send().await?;
        let data = response.json::<Value>().await?;
        
        let mut flows = Vec::new();
        if let Some(pairs) = data["pairs"].as_array() {
            for pair in pairs.iter().take(5) {
                if pair["chainId"] == "ethereum" {
                    flows.push(DexFlow {
                        chain: Chain::Ethereum,
                        dex: pair["dexId"].as_str().unwrap_or("Unknown").to_string(),
                        pair: format!("{}/{}", 
                            pair["baseToken"]["symbol"].as_str().unwrap_or("?"), 
                            pair["quoteToken"]["symbol"].as_str().unwrap_or("?")),
                        side: super::models::SwapSide::Buy, // Simplified
                        amount_in: 0.0,
                        amount_out: 0.0,
                        usd_value: pair["volume"]["h24"].as_f64().unwrap_or(0.0),
                        timestamp: chrono::Utc::now(),
                    });
                }
            }
        }
        
        Ok(flows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_whale_alert_tx() {
        let tx_json = r#"{
            "blockchain": "ethereum",
            "symbol": "ETH",
            "id": "123",
            "transaction_type": "transfer",
            "hash": "0xabc",
            "from": {"address": "0xfrom", "owner": "exchange"},
            "to": {"address": "0xto", "owner": "whale"},
            "timestamp": 1670000000,
            "amount": 500.5,
            "amount_usd": 1001000.0
        }"#;
        let tx: Value = serde_json::from_str(tx_json).unwrap();
        let fetcher = EthereumFetcher::new("test".to_string());
        let whales = fetcher.parse_whale_movements(vec![tx]);

        assert_eq!(whales.len(), 1);
        assert_eq!(whales[0].amount, 500.5);
        assert_eq!(whales[0].usd_value, 1001000.0);
    }
}
