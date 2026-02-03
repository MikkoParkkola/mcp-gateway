# Design Doc: On-Chain Market Intelligence Co-Pilot

## Overview
This document outlines the architecture for integrating on-chain market intelligence into `mcp-gateway`. The goal is to provide real-time insights into whale movements and DEX flows across multiple chains (Solana, Ethereum, Base, Arbitrum) with high-speed aggregation.

## Objectives
- Implement data models for `whale_movement` and `dex_flow`.
- Build parallel fetchers for 4 chains (Solana, ETH, Base, Arbitrum).
- Define a unified `MarketInsight` output format.
- Integrate with high-level aggregators (Whale Alert, DexScreener) and reliable RPC fallbacks.

## Data Models

### 1. `WhaleMovement`
Captures significant transactions (e.g., >$500k USD equivalent).
- `chain`: enum (Solana, Ethereum, Base, Arbitrum)
- `tx_hash`: String
- `from_address`: String
- `to_address`: String
- `asset`: String (symbol)
- `amount`: Decimal
- `usd_value`: Decimal
- `timestamp`: DateTime
- `labels`: List of tags (e.g., "Exchange", "Whale Wallet", "Burn")

### 2. `DexFlow`
Captures swap events and liquidity changes.
- `chain`: enum
- `dex`: String (e.g., "Raydium", "Uniswap V3")
- `pair`: String (e.g., "SOL/USDC")
- `side`: enum (Buy, Sell)
- `amount_in`: Decimal
- `amount_out`: Decimal
- `usd_value`: Decimal
- `timestamp`: DateTime

### 3. `MarketInsight` (Unified Output)
Aggregates the above into a human-readable and machine-parseable format.
- `id`: UUID
- `type`: enum (WhaleAlert, DexSignal, TrendChange)
- `summary`: String (LLM-friendly description)
- `data`: OneOf(WhaleMovement, DexFlow)
- `confidence_score`: float (0.0 - 1.0)

## Parallel Fetching Architecture

### Fetcher Traits
Each chain will have a fetcher implementing a common `ChainFetcher` trait:
```rust
async fn fetch_whale_movements(&self) -> Result<Vec<WhaleMovement>>;
async fn fetch_dex_flows(&self) -> Result<Vec<DexFlow>>;
```

### Chain-Specific Implementation
- **Solana**: Priority on Helius API for parsing, with fallback to Quicknode/Alchemy RPC.
- **Ethereum**: Priority on Whale Alert API + Infura/Alchemy RPC.
- **Base/Arbitrum**: Aggregated via DexScreener API + L2 RPCs.

### Aggregation Loop
A background task will poll these fetchers in parallel using `tokio::spawn` or `join_all`, deduplicate signals, and push to the `mcp-gateway` capability bus.

## Implementation Status

### 1. Unified Intelligence Tool
The system is integrated into `MetaMcp` as a core meta-tool:
- `gateway_get_intelligence`: Parallel fetching of whale movements and DEX flows across Solana and Ethereum.

### 2. Fetchers
- **Solana**: Uses Helius Enhanced Transactions API for high-fidelity transfer and swap parsing.
- **Ethereum**: Uses Whale Alert API for large transfers and DexScreener for trending pair flows.

### 3. Manager
The `IntelligenceManager` orchestrates parallel execution via `tokio::spawn` and `mpsc` channels, providing an aggregated feed of `MarketInsight` objects.

## Usage
Add API keys to your `config.yaml`:
```yaml
intelligence:
  enabled: true
  whale_alert_key: "YOUR_KEY"
  helius_key: "YOUR_KEY"
```

Then invoke via MCP:
```json
{
  "method": "tools/call",
  "params": {
    "name": "gateway_get_intelligence",
    "arguments": {}
  }
}
```
