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

    /// Run a single aggregation cycle across all fetchers, optionally filtering by chain.
    pub async fn aggregate_insights(&self, chains: Option<Vec<String>>) -> Result<Vec<MarketInsight>> {
        let (tx, mut rx) = mpsc::channel(100);
        let mut insights = Vec::new();

        for fetcher in &self.fetchers {
            let tx = tx.clone();
            let fetcher = fetcher.clone();
            let chains = chains.clone();
            
            tokio::spawn(async move {
                match fetcher.fetch_insights().await {
                    Ok(results) => {
                        for insight in results {
                            // Filter by chain if specified
                            if let Some(ref c) = chains {
                                let chain_str = match &insight.data {
                                    super::models::InsightData::Whale(w) => format!("{:?}", w.chain),
                                    super::models::InsightData::Dex(d) => format!("{:?}", d.chain),
                                }.to_lowercase();
                                
                                if !c.iter().any(|filter| filter.to_lowercase() == chain_str) {
                                    continue;
                                }
                            }
                            let _ = tx.send(insight).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch insights from fetcher: {}", e);
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
    use super::super::models::{WhaleMovement, Chain, MarketInsight, InsightData};
    use async_trait::async_trait;

    struct MockFetcher;

    #[async_trait]
    impl crate::intelligence::ChainFetcher for MockFetcher {
        async fn fetch_insights(&self) -> Result<Vec<MarketInsight>> {
            Ok(vec![MarketInsight {
                id: uuid::Uuid::new_v4(),
                summary: "Mock Insight".to_string(),
                data: InsightData::Whale(WhaleMovement {
                    chain: Chain::Ethereum,
                    tx_hash: "0x123".to_string(),
                    from_address: "from".to_string(),
                    to_address: "to".to_string(),
                    asset: "ETH".to_string(),
                    amount: 100.0,
                    usd_value: 200000.0,
                    timestamp: chrono::Utc::now(),
                    labels: vec![],
                }),
                confidence_score: Some(1.0),
                timestamp: chrono::Utc::now(),
            }])
        }
    }

    #[tokio::test]
    async fn test_intelligence_manager_aggregate() {
        let mut manager = IntelligenceManager::new();
        manager.add_fetcher(Arc::new(MockFetcher));
        
        let insights = manager.aggregate_insights(None).await.unwrap();
        assert_eq!(insights.len(), 1);
        assert!(insights[0].summary.contains("Mock Insight"));
    }
}

impl Default for IntelligenceManager {
    fn default() -> Self {
        Self::new()
    }
}
