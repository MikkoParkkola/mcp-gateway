//! Intelligence Fetcher Manager
//!
//! Orchestrates multiple chain fetchers to aggregate market insights.

use std::sync::Arc;
use tokio::sync::mpsc;
use crate::error::Result;
use super::{ChainFetcher, models::MarketInsight};

/// Manager for orchestrating intelligence fetchers.
pub struct IntelligenceManager {
    fetchers: Vec<Arc<dyn ChainFetcher>>,
}

impl IntelligenceManager {
    /// Create a new intelligence manager.
    pub fn new() -> Self {
        Self {
            fetchers: Vec::new(),
        }
    }

    /// Add a chain fetcher to the manager.
    pub fn add_fetcher(&mut self, fetcher: Arc<dyn ChainFetcher>) {
        self.fetchers.push(fetcher);
    }

    /// Run a single aggregation cycle across all fetchers.
    pub async fn aggregate_insights(&self) -> Result<Vec<MarketInsight>> {
        let (tx, mut rx) = mpsc::channel(100);
        let mut insights = Vec::new();

        for fetcher in &self.fetchers {
            let tx = tx.clone();
            let fetcher = fetcher.clone();
            
            tokio::spawn(async move {
                // Fetch whale movements
                if let Ok(whales) = fetcher.fetch_whale_movements().await {
                    for movement in whales {
                        let insight = MarketInsight {
                            id: uuid::Uuid::new_v4(),
                            summary: format!("Whale Alert: {} {} moved on {:?}", movement.amount, movement.asset, movement.chain),
                            data: super::models::InsightData::Whale(movement),
                            confidence_score: 1.0,
                            timestamp: chrono::Utc::now(),
                        };
                        let _ = tx.send(insight).await;
                    }
                }
                
                // Fetch DEX flows
                if let Ok(flows) = fetcher.fetch_dex_flows().await {
                    for flow in flows {
                        let insight = MarketInsight {
                            id: uuid::Uuid::new_v4(),
                            summary: format!("DEX Signal: {} swap on {} ({})", flow.pair, flow.dex, flow.usd_value),
                            data: super::models::InsightData::Dex(flow),
                            confidence_score: 0.8,
                            timestamp: chrono::Utc::now(),
                        };
                        let _ = tx.send(insight).await;
                    }
                }
            });
        }

        // Close the channel so rx finishes
        drop(tx);

        while let Some(insight) = rx.recv().await {
            insights.push(insight);
        }

        Ok(insights)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::models::{WhaleMovement, DexFlow, Chain};
    use async_trait::async_trait;

    struct MockFetcher;

    #[async_trait]
    impl crate::intelligence::ChainFetcher for MockFetcher {
        async fn fetch_whale_movements(&self) -> Result<Vec<WhaleMovement>> {
            Ok(vec![WhaleMovement {
                chain: Chain::Ethereum,
                tx_hash: "0x123".to_string(),
                from_address: "from".to_string(),
                to_address: "to".to_string(),
                asset: "ETH".to_string(),
                amount: 100.0,
                usd_value: 200000.0,
                timestamp: chrono::Utc::now(),
                labels: vec![],
            }])
        }

        async fn fetch_dex_flows(&self) -> Result<Vec<DexFlow>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_intelligence_manager_aggregate() {
        let mut manager = IntelligenceManager::new();
        manager.add_fetcher(Arc::new(MockFetcher));
        
        let insights = manager.aggregate_insights().await.unwrap();
        assert_eq!(insights.len(), 1);
        assert!(insights[0].summary.contains("Whale Alert"));
    }
}

impl Default for IntelligenceManager {
    fn default() -> Self {
        Self::new()
    }
}
