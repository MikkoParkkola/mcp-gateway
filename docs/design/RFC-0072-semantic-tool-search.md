# RFC-0072: Semantic Tool Search

**Status**: Proposed
**Date**: 2026-03-13
**Author**: Mikko Parkkola
**LOC Budget**: ~700-900 (new module + integration; SearchFeedback deferred to follow-up)

---

## 1. Problem Statement

### The Gap

Current `gateway_search_tools` uses substring matching with synonym expansion. It
works well for exact-keyword queries ("gmail", "brave_search") but fails on
**intent-based queries** -- the queries that LLMs actually generate:

| Query | Expected Match | Current Result |
|-------|---------------|----------------|
| "find information about a company" | `sec_edgar_filings`, `yahoo_stock_quote` | 0 results |
| "schedule a meeting" | `calendar_insert`, `calendar_quick_add` | 0 results |
| "check website performance" | `lighthouse_audit`, `pagespeed_check` | 0 results |
| "translate text" | `deepl_translate`, `google_translate` | 0 results (unless synonym group exists) |
| "research a topic" | `brave_search`, `arxiv_search`, `wikipedia_search` | Hits via "research" synonym only |

At 180+ tools today and 500+ target, the synonym table approach does not scale.
Each new tool domain requires manual synonym entries. GPT-5.4 reportedly has
native embedding-based tool search. Our keyword search is the clearest limitation
at this scale.

### Why Keyword Search Degrades at Scale

1. **Vocabulary mismatch**: User queries use different words than tool descriptions.
   The set of possible phrasings is combinatorial; static synonym tables cover <5%.
2. **Cross-domain intent**: "find company info" spans finance, web, and database
   tools. No single keyword connects them.
3. **Schema blindness**: `sec_edgar_filings` has parameters named `ticker`,
   `filing_type`, `date_range` -- all strong semantic signals that substring
   matching ignores.

---

## 2. Architecture Decision

### Recommendation: Option D -- Hybrid Keyword + Semantic Rerank

**Confidence: VERIFIED (analogous systems: Elasticsearch hybrid search, Vespa,
Pinecone hybrid, all prove keyword-first + semantic-rerank outperforms either alone)**

#### Why Not the Others

| Option | Verdict | Reason |
|--------|---------|--------|
| A: ONNX runtime | REJECTED | +30MB binary, ONNX runtime C++ dependency breaks `cargo install`, platform matrix explodes (arm64 macOS, x86 Linux, aarch64 Linux) |
| B: Pre-computed embeddings | PARTIAL ACCEPT | The embedding storage idea is good, but still needs a model -- absorbed into Option D |
| C: SimHash n-gram | REJECTED | SimHash similarity score is 64-bit Hamming -- far too coarse for semantic matching. "schedule meeting" vs "calendar insert" would have ~50% bit overlap (random noise range). SimHash is designed for near-duplicate detection, not semantic similarity. |
| **D: Hybrid** | **ACCEPTED** | Keyword pass is free (already exists), semantic rerank adds precision where it matters. Model runs once at startup (offline) or uses pre-computed vectors. |

#### The Key Insight: Separation of Embedding Generation from Search

The embedding **model** does not need to run inside mcp-gateway at search time.
Tool descriptions change only on startup or hot-reload (tens of events per hour,
not per request). The architecture separates:

1. **Embedding generation** (offline, startup, or hot-reload) -- external process
   or build step writes `embeddings.json`
2. **Similarity computation** (online, per-search) -- pure f32 dot products in
   Rust, zero dependencies

This eliminates the ONNX dependency entirely while delivering full semantic search.

---

## 3. Detailed Design

### 3.1 Architecture Overview

```
                    gateway_search_tools("find company info")
                                |
                    +-----------v-----------+
                    |   Query Processing    |
                    |  lowercase + split    |
                    |  synonym expansion    |
                    +-----------+-----------+
                                |
              +-----------------v-----------------+
              |     Stage 1: Keyword Filter       |
              |  tool_matches_query() -- existing |
              |  Returns ALL matches (no limit)   |
              +--------+------------------------+-+
                       |                        |
                  matches > 0             matches == 0
                       |                        |
              +--------v--------+    +----------v-----------+
              | Stage 2: Rank   |    | Stage 2b: Semantic   |
              | SearchRanker    |    | Full Scan             |
              | (existing)      |    | (see query strategy)  |
              | usage + text    |    | against ALL tools     |
              +--------+--------+    +----------+-----------+
                       |                        |
              +--------v--------+    +----------v-----------+
              | Stage 3: Sem    |    | Return top-K with    |
              | Rerank top-50   |    | "semantic_match"      |
              | (see query      |    | annotation            |
              |  strategy)      |    +----------+-----------+
              +--------+--------+               |
                       |                        |
              +--------v--------+               |
              | Return top-K    |<--------------+
              | (limit param)   |
              +-----------------+

Query embedding strategy (controls Stage 2b and Stage 3):

  Has query_vector param?
    YES -> Use client-provided dense vector (Strategy B)
    NO  -> Has embeddings.json with BoW vocabulary?
             YES -> BoW-vs-BoW TF-IDF cosine similarity (Strategy A, zero-dep)
             NO  -> Keyword-only (graceful degradation, no semantic pass)
```

### 3.2 Embedding Storage

```
~/.mcp-gateway/embeddings.json
```

```json
{
  "model": "gte-small",
  "dimensions": 384,
  "generated_at": "2026-03-13T10:00:00Z",
  "vocabulary": ["10-k", "10-q", "annual", "api", "calendar", "code", ...],
  "embeddings": {
    "brave:brave_search": {
      "vector": [0.0123, -0.0456, ...],
      "bow": {"search": 2, "web": 1, "query": 1, "results": 1},
      "text_hash": "a1b2c3d4"
    },
    "fulcrum:gmail_search": {
      "vector": [0.0789, -0.0321, ...],
      "bow": {"gmail": 2, "search": 1, "email": 1, "message": 1},
      "text_hash": "e5f6g7h8"
    }
  }
}
```

`text_hash` is FNV-1a of the concatenated text that was embedded (tool name +
description + schema field names). On hot-reload, if the hash matches, the
embedding is reused. If it differs, that tool is flagged as "stale" and falls
back to keyword-only until the embedding is regenerated.

### 3.3 Rust Types

```rust
// src/semantic/mod.rs

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Pre-computed embedding vector for a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEmbedding {
    /// Dense f32 vector (dimensionality matches the model used).
    /// Used when the client provides a query_vector (Strategy B).
    pub vector: Vec<f32>,
    /// Sparse bag-of-words: keyword -> term frequency.
    /// Built from tool name, description, and parameter names.
    /// Used for zero-dependency BoW-vs-BoW search (Strategy A).
    #[serde(default)]
    pub bow: HashMap<String, u32>,
    /// FNV-1a hash of the source text that produced this embedding.
    /// Used to detect stale embeddings after description changes.
    pub text_hash: String,
}

/// The embedding store: maps `"server:tool_name"` to its embedding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingStore {
    /// Model identifier (e.g. "gte-small", "bge-micro-v2").
    pub model: String,
    /// Vector dimensionality (e.g. 384 for gte-small).
    pub dimensions: usize,
    /// ISO 8601 timestamp of generation.
    pub generated_at: String,
    /// Shared vocabulary for BoW vectors (sorted, deduped).
    /// Built from all tool descriptions at embedding generation time.
    #[serde(default)]
    pub vocabulary: Vec<String>,
    /// Per-tool embeddings keyed by "server:tool_name".
    pub embeddings: HashMap<String, ToolEmbedding>,
}

/// Runtime semantic search engine.
///
/// Holds both a dense embedding matrix (for client-provided query vectors)
/// and a sparse BoW TF-IDF index (for the zero-dependency default path).
/// Built once at startup from `EmbeddingStore`, rebuilt on hot-reload.
pub struct SemanticIndex {
    /// Tool keys in row order (shared by dense matrix and BoW index).
    keys: Vec<String>,
    /// Contiguous f32 matrix: keys.len() rows x dimensions columns.
    /// Row-major layout for sequential dot-product scans.
    /// Used when a client-provided query_vector is available (Strategy B).
    matrix: Vec<f32>,
    /// Vector dimensionality.
    dimensions: usize,
    /// Text hashes for staleness detection (parallel to `keys`).
    text_hashes: Vec<String>,
    // -- BoW TF-IDF index (Strategy A: zero-dependency default) --
    /// Shared vocabulary: word -> column index.
    bow_vocab: HashMap<String, usize>,
    /// Per-tool sparse TF-IDF vectors (parallel to `keys`).
    /// Each inner HashMap maps vocab index -> TF-IDF weight.
    bow_vectors: Vec<HashMap<usize, f32>>,
    /// IDF weights per vocabulary term (parallel to `bow_vocab` values).
    idf: Vec<f32>,
}

/// A semantic search result with similarity score.
#[derive(Debug, Clone)]
pub struct SemanticMatch {
    /// Tool key ("server:tool_name").
    pub key: String,
    /// Cosine similarity score in [-1.0, 1.0].
    pub similarity: f32,
}

impl SemanticIndex {
    /// Load from an `EmbeddingStore` (deserialized from JSON).
    ///
    /// Normalizes all dense vectors to unit length for cosine similarity via
    /// dot product. Also builds the sparse BoW TF-IDF index from per-tool
    /// keyword bags and the shared vocabulary.
    pub fn from_store(store: &EmbeddingStore) -> Self {
        let dimensions = store.dimensions;
        let mut keys = Vec::with_capacity(store.embeddings.len());
        let mut matrix = Vec::with_capacity(store.embeddings.len() * dimensions);
        let mut text_hashes = Vec::with_capacity(store.embeddings.len());

        // Build vocabulary lookup
        let bow_vocab: HashMap<String, usize> = store.vocabulary.iter()
            .enumerate()
            .map(|(i, w)| (w.clone(), i))
            .collect();
        let vocab_size = store.vocabulary.len();

        // Document frequency counts for IDF
        let mut df = vec![0u32; vocab_size];
        let mut bow_vectors_raw: Vec<HashMap<usize, u32>> = Vec::new();

        for (key, emb) in &store.embeddings {
            if emb.vector.len() != dimensions {
                continue; // skip malformed entries
            }
            let norm = emb.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm < 1e-9 {
                continue; // skip zero vectors
            }
            keys.push(key.clone());
            text_hashes.push(emb.text_hash.clone());
            matrix.extend(emb.vector.iter().map(|x| x / norm));

            // Build sparse BoW vector for this tool
            let mut sparse = HashMap::new();
            for (word, &count) in &emb.bow {
                if let Some(&idx) = bow_vocab.get(word) {
                    sparse.insert(idx, count);
                    df[idx] += 1;
                }
            }
            bow_vectors_raw.push(sparse);
        }

        // Compute IDF: log(N / (1 + df)) for smoothing
        let n = keys.len() as f32;
        let idf: Vec<f32> = df.iter()
            .map(|&d| (n / (1.0 + d as f32)).ln())
            .collect();

        // Convert raw TF counts to TF-IDF weights
        let bow_vectors: Vec<HashMap<usize, f32>> = bow_vectors_raw.into_iter()
            .map(|sparse| {
                sparse.into_iter()
                    .map(|(idx, tf)| (idx, tf as f32 * idf[idx]))
                    .collect()
            })
            .collect();

        Self { keys, matrix, dimensions, text_hashes, bow_vocab, bow_vectors, idf }
    }

    /// Find the top-K tools most similar to a dense query vector (Strategy B).
    ///
    /// Used when the client provides a pre-computed `query_vector`.
    /// `query_vector` must have length == `self.dimensions`. It is
    /// normalized internally. Returns results sorted by descending
    /// similarity, filtered by `min_similarity`.
    ///
    /// Computational cost: O(n * d) where n = tool count, d = dimensions.
    /// At 500 tools x 384 dims = 192K multiply-adds = ~0.1ms on modern CPU.
    pub fn search_dense(
        &self,
        query_vector: &[f32],
        top_k: usize,
        min_similarity: f32,
    ) -> Vec<SemanticMatch> {
        if query_vector.len() != self.dimensions || self.keys.is_empty() {
            return Vec::new();
        }

        // Normalize query
        let norm = query_vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm < 1e-9 {
            return Vec::new();
        }
        let q_norm: Vec<f32> = query_vector.iter().map(|x| x / norm).collect();

        // Compute dot products (cosine similarity on pre-normalized vectors)
        let mut scores: Vec<(usize, f32)> = self.keys.iter().enumerate()
            .map(|(i, _)| {
                let row = &self.matrix[i * self.dimensions..(i + 1) * self.dimensions];
                let dot: f32 = row.iter().zip(q_norm.iter()).map(|(a, b)| a * b).sum();
                (i, dot)
            })
            .filter(|(_, score)| *score >= min_similarity)
            .collect();

        // Partial sort: only need top-K
        scores.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);

        scores.into_iter().map(|(i, sim)| SemanticMatch {
            key: self.keys[i].clone(),
            similarity: sim,
        }).collect()
    }

    /// Find the top-K tools most similar to a text query using BoW TF-IDF
    /// cosine similarity (Strategy A: zero-dependency default).
    ///
    /// Tokenizes the query into words, builds a sparse TF-IDF vector using
    /// the shared vocabulary + IDF weights, then computes cosine similarity
    /// against each tool's BoW vector. Both sides are in the same vector
    /// space, so the similarity scores are meaningful.
    ///
    /// Computational cost: O(n * q) where n = tool count, q = query terms.
    /// Sparse dot product -- typically <10 query terms, <20 tool terms.
    pub fn search_bow(
        &self,
        query_text: &str,
        top_k: usize,
        min_similarity: f32,
    ) -> Vec<SemanticMatch> {
        if self.keys.is_empty() || self.bow_vocab.is_empty() {
            return Vec::new();
        }

        // Tokenize query into BoW
        let words: Vec<&str> = query_text.to_lowercase()
            .split_whitespace()
            .collect();
        let mut query_sparse: HashMap<usize, f32> = HashMap::new();
        for word in &words {
            if let Some(&idx) = self.bow_vocab.get(*word) {
                *query_sparse.entry(idx).or_insert(0.0) += self.idf[idx];
            }
        }
        if query_sparse.is_empty() {
            return Vec::new(); // no vocabulary overlap
        }

        // Normalize query vector
        let q_norm = query_sparse.values().map(|x| x * x).sum::<f32>().sqrt();
        if q_norm < 1e-9 {
            return Vec::new();
        }

        // Sparse cosine similarity against each tool
        let mut scores: Vec<(usize, f32)> = self.bow_vectors.iter().enumerate()
            .map(|(i, tool_bow)| {
                let dot: f32 = query_sparse.iter()
                    .filter_map(|(&idx, &q_w)| tool_bow.get(&idx).map(|&t_w| q_w * t_w))
                    .sum();
                let t_norm = tool_bow.values().map(|x| x * x).sum::<f32>().sqrt();
                let sim = if t_norm < 1e-9 { 0.0 } else { dot / (q_norm * t_norm) };
                (i, sim)
            })
            .filter(|(_, score)| *score >= min_similarity)
            .collect();

        scores.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);

        scores.into_iter().map(|(i, sim)| SemanticMatch {
            key: self.keys[i].clone(),
            similarity: sim,
        }).collect()
    }

    /// Unified search entry point.
    ///
    /// If `query_vector` is provided (Strategy B), uses dense cosine similarity.
    /// Otherwise falls back to BoW TF-IDF similarity (Strategy A).
    pub fn search(
        &self,
        query_text: &str,
        query_vector: Option<&[f32]>,
        top_k: usize,
        min_similarity: f32,
    ) -> Vec<SemanticMatch> {
        if let Some(qv) = query_vector {
            self.search_dense(qv, top_k, min_similarity)
        } else {
            self.search_bow(query_text, top_k, min_similarity)
        }
    }

    /// Check whether a tool's embedding is stale (description changed since
    /// embedding was generated).
    pub fn is_stale(&self, key: &str, current_text_hash: &str) -> bool {
        self.keys.iter().zip(self.text_hashes.iter())
            .find(|(k, _)| k.as_str() == key)
            .map_or(true, |(_, stored_hash)| stored_hash != current_text_hash)
    }

    /// Number of tools indexed.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Load an embedding store from disk.
///
/// Returns `None` if the file does not exist (first run, embeddings not
/// yet generated). Returns `Err` if the file exists but is malformed.
pub fn load_store(path: &Path) -> std::io::Result<Option<EmbeddingStore>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let store: EmbeddingStore = serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(store))
}
```

### 3.4 Query Embedding Strategy

The gateway itself does NOT run a model. There are three query strategies,
evaluated in priority order:

**Strategy A (default, zero-dependency): Enhanced Keyword (BoW TF-IDF) similarity**

> **Honest limitation**: Strategy A (BoW TF-IDF) improves on keyword matching by
> considering term frequency across the tool corpus, but cannot match semantic
> intent (e.g., "schedule a meeting" will not find "calendar_insert" unless
> "schedule" or "meeting" appears in the tool description). For true semantic
> intent matching, enable the optional `semantic-search-embed` feature flag which
> bundles `fastembed-rs` (23MB, BGE-small model) for local neural embeddings at
> <5ms startup cost.

At embedding generation time (CLI tool, Strategy C), the `mcp-gateway embed`
command extracts a keyword bag from each tool's augmented text (tool name,
description, parameter names, enum values) and stores it as a sparse BoW
vector in `embeddings.json` alongside the dense embedding. A shared vocabulary
is built from all tool descriptions.

At search time, the query is tokenized into words against the same vocabulary,
weighted by IDF, and compared to each tool's BoW vector using cosine
similarity. Both query and tool vectors live in the same sparse BoW space,
so the similarity scores are directly meaningful.

This replaces the earlier random-projection approach (QueryProjector), which
was mathematically unsound -- random projection of sparse BoW vectors into a
neural embedding space produces vectors that are not aligned with the dense
tool embeddings, making cosine similarity between them noise.

```rust
// src/semantic/query.rs

/// Build a sparse TF-IDF query vector from text using the shared
/// vocabulary and IDF weights from the embedding store.
///
/// This is NOT a neural embedding -- it is a sparse bag-of-words
/// vector in the same space as the per-tool BoW vectors. Cosine
/// similarity between two BoW TF-IDF vectors is well-defined and
/// meaningful.
///
/// Quality is lower than a true embedding model but sufficient for
/// reranking when combined with keyword pre-filtering, and requires
/// zero external dependencies at search time.
pub fn bow_query_vector(
    query: &str,
    vocab: &HashMap<String, usize>,
    idf: &[f32],
) -> HashMap<usize, f32> {
    let mut sparse = HashMap::new();
    for word in query.to_lowercase().split_whitespace() {
        if let Some(&idx) = vocab.get(word) {
            *sparse.entry(idx).or_insert(0.0) += idf[idx];
        }
    }
    sparse
}
```

**Strategy B (higher quality): Client-provided dense query vector**

For users who want full neural semantic search, the gateway accepts a
pre-computed query vector in the search request:

```json
{
  "query": "find company information",
  "query_vector": [0.0123, -0.0456, ...],
  "limit": 10
}
```

This allows LLM clients to embed the query themselves (many already have
embedding APIs) and pass the vector through. The gateway computes dense
cosine similarity against the pre-computed tool embeddings. The client
should use the same model that generated `embeddings.json` (e.g. gte-small).

When `query_vector` is present, it takes priority over Strategy A.

**Strategy C (companion CLI tool): `mcp-gateway embed`**

A CLI subcommand that generates `embeddings.json` -- including both dense
embeddings AND the BoW vocabulary/vectors -- using a local ONNX model or
an API call. Run once at startup or as a post-config-change hook:

```bash
# Generate embeddings (dense + BoW) for all registered tools
mcp-gateway embed --model gte-small --output ~/.mcp-gateway/embeddings.json

# Or use an API (OpenAI, Cohere, etc.)
mcp-gateway embed --api openai --model text-embedding-3-small
```

The BoW vocabulary and per-tool keyword bags are always generated (zero-cost
side output of the text augmentation step). Dense embeddings require a model.

### 3.5 Scoring Integration

The semantic score integrates multiplicatively with the existing scoring pipeline,
not as a replacement:

```rust
// In ranking/mod.rs -- modified rank() method

/// Extended scoring: text_relevance * (1 + usage_factor) * semantic_boost
///
/// semantic_boost = 1.0 when no semantic index is available (neutral).
/// semantic_boost = 1.0 + (cosine_similarity * SEMANTIC_WEIGHT) when available.
///
/// SEMANTIC_WEIGHT = 0.5 (tunable). This means a perfect semantic match
/// (cosine=1.0) gives a 1.5x boost; a mediocre match (cosine=0.3) gives 1.15x.
/// The multiplicative design ensures semantic similarity cannot promote a
/// tool with zero text relevance -- it only amplifies existing matches.
const SEMANTIC_WEIGHT: f64 = 0.5;

// For zero-result recovery (semantic-only mode):
// When keyword search returns 0 results, semantic search runs against ALL tools.
// Results are returned with score = cosine_similarity * SEMANTIC_ONLY_SCALE.
const SEMANTIC_ONLY_SCALE: f64 = 5.0;
```

### 3.6 Tool Description Augmentation

Before embedding, tool descriptions are enriched with schema signals:

```rust
/// Build the text to embed for a tool.
///
/// Concatenates: tool name (repeated for emphasis) + description +
/// parameter names + enum values from the input schema.
///
/// Example output for `sec_edgar_filings`:
/// "sec_edgar_filings sec_edgar_filings Search SEC EDGAR for company
///  filings including 10-K annual reports and 10-Q quarterly reports.
///  ticker filing_type date_start date_end 10-K 10-Q 8-K S-1"
pub fn build_embedding_text(tool_name: &str, description: &str, schema: &Value) -> String {
    let mut parts = vec![tool_name.to_string(), tool_name.to_string()];
    parts.push(description.to_string());

    // Extract parameter names
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (key, prop) in props {
            parts.push(key.clone());
            // Extract enum values (strong semantic signals)
            if let Some(enums) = prop.get("enum").and_then(Value::as_array) {
                for e in enums {
                    if let Some(s) = e.as_str() {
                        parts.push(s.to_string());
                    }
                }
            }
            // Extract parameter descriptions
            if let Some(desc) = prop.get("description").and_then(Value::as_str) {
                parts.push(desc.to_string());
            }
        }
    }

    parts.join(" ")
}
```

### 3.7 Learning from Invocations

When an LLM searches for "X" and then invokes tool Y, that is a strong signal
that "X" should match Y in the future. This creates a feedback loop:

```rust
// src/semantic/feedback.rs

/// Records (query, invoked_tool) pairs for future search improvement.
///
/// Stored in ~/.mcp-gateway/search_feedback.json.
/// Format: { "query_text": { "server:tool": count } }
///
/// Integration with ranking: when a query matches feedback entries,
/// the associated tools get a feedback_boost of log2(count + 1) * 0.2.
/// This is applied multiplicatively alongside usage_factor.
///
/// **Session teardown**: `SearchFeedback` entries keyed by session_id must be
/// cleaned up via a session disconnect hook. Register
/// `on_session_disconnect(|sid| feedback.remove_session(sid))` in the server
/// lifecycle.
pub struct SearchFeedback {
    /// query_text -> (tool_key -> invocation_count)
    associations: DashMap<String, DashMap<String, AtomicU64>>,
}
```

The feedback loop is recorded in `MetaMcp::invoke_tool` by correlating the most
recent search query (stored per-session) with the invoked tool.

---

## 4. File Changes

### New Files

| File | LOC | Purpose |
|------|-----|---------|
| `src/semantic/mod.rs` | ~300 | `EmbeddingStore`, `SemanticIndex` (dense + BoW), `SemanticMatch`, `load_store()` |
| `src/semantic/query.rs` | ~60 | `bow_query_vector()` -- sparse TF-IDF query construction |
| `src/semantic/augment.rs` | ~80 | `build_embedding_text()`, `build_bow()` -- schema-enriched text + keyword extraction |
| `src/semantic/tests.rs` | ~200 | Unit tests for all semantic modules |

> **Note**: `SearchFeedback` (feedback learning from search-then-invoke pairs) is
> deferred to a follow-up RFC. The feedback types and integration points are
> described in section 3.7 for design context but are not in scope for initial
> implementation.

### Modified Files

| File | Change |
|------|--------|
| `src/lib.rs` | Add `#[cfg(feature = "semantic-search")] pub mod semantic;` |
| `src/ranking/mod.rs` | Add `semantic_boost` to `rank()`, add `SemanticIndex` field to `SearchRanker` |
| `src/gateway/meta_mcp/search.rs` | After keyword search returns 0 results, fall through to semantic full-scan |
| `src/gateway/meta_mcp_helpers.rs` | Add `query_vector` extraction from search args |
| `src/gateway/meta_mcp_tool_defs.rs` | Add `query_vector` optional parameter to `gateway_search_tools` schema |
| `src/config/features.rs` | Add `SemanticSearchConfig` struct |
| `Cargo.toml` | Add `semantic-search` feature flag (no new dependencies for core; optional `ort` for CLI embed command). Add optional `semantic-search-embed` feature flag that bundles `fastembed-rs` (23MB, BGE-small) for local neural embeddings as alternative to BoW. Strategy A becomes "enhanced keyword"; the fastembed path becomes "true semantic." |

### Config Schema Addition

```yaml
# config.yaml
semantic_search:
  enabled: true                              # default: false
  embeddings_path: "~/.mcp-gateway/embeddings.json"  # default
  min_similarity: 0.3                        # minimum cosine threshold
  semantic_weight: 0.5                       # multiplicative boost weight
  feedback:
    enabled: true                            # learn from search+invoke pairs
    path: "~/.mcp-gateway/search_feedback.json"
```

```rust
// In src/config/features.rs

/// Semantic search configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticSearchConfig {
    /// Enable semantic search (requires embeddings.json).
    pub enabled: bool,
    /// Path to pre-computed embeddings file.
    pub embeddings_path: String,
    /// Minimum cosine similarity threshold (0.0-1.0).
    pub min_similarity: f32,
    /// Weight of semantic boost in scoring (0.0-1.0).
    pub semantic_weight: f64,
    /// Feedback learning configuration.
    pub feedback: SemanticFeedbackConfig,
}

impl Default for SemanticSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            embeddings_path: "~/.mcp-gateway/embeddings.json".to_string(),
            min_similarity: 0.3,
            semantic_weight: 0.5,
            feedback: SemanticFeedbackConfig::default(),
        }
    }
}

/// Feedback learning for semantic search.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticFeedbackConfig {
    /// Enable search-to-invoke feedback learning.
    pub enabled: bool,
    /// Path to feedback persistence file.
    pub path: String,
}

impl Default for SemanticFeedbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "~/.mcp-gateway/search_feedback.json".to_string(),
        }
    }
}
```

---

## 5. Performance Analysis

### Memory Budget

| Component | Size at 500 tools |
|-----------|-------------------|
| Embedding matrix (500 x 384 x f32) | 750 KB |
| Key strings (~40 bytes avg) | 20 KB |
| Text hashes | 16 KB |
| Feedback associations (1000 queries x 3 tools) | ~200 KB |
| **Total** | **~1 MB** |

Well within the 50MB constraint. Even at 10,000 tools with 1024-dim embeddings:
10K x 1024 x 4 bytes = 40 MB.

### Latency Budget

| Operation | Time | Notes |
|-----------|------|-------|
| Keyword filter (existing) | <1ms | Unchanged |
| Semantic rerank (50 tools x 384 dims) | <0.1ms | 50 dot products |
| Semantic full scan (500 tools x 384 dims) | <0.5ms | Only on zero-result fallback |
| BoW query vectorization | <0.1ms | Vocabulary lookup + IDF weighting |
| **Total p95** | **<2ms** | Well within 10ms budget |

### Benchmark Methodology

```rust
#[cfg(test)]
mod bench {
    // Synthetic benchmark: 500 tools, 384-dim embeddings
    // Query: random 384-dim vector
    // Measure: search() wall clock via std::time::Instant
    //
    // Expected: <100us for 500-tool scan on Apple M-series
    // Validated: analogous to tool_registry benchmark (O(1) lookup = ~50ns,
    //            500 dot products at 384 dims = ~2000x more work = ~100us)
}
```

---

## 6. What Makes This Beyond Industry Standard

### 6.1 Schema-Augmented Embeddings

Schema-augmented embeddings include parameter names and enum values alongside
tool descriptions -- uncommon in open-source MCP gateways and tool routers.
When `sec_edgar_filings` has parameters `ticker`, `filing_type`, `10-K`,
`10-Q` -- those are embedded too. A query for "annual report" matches via
the `10-K` parameter even if the description never says "annual report".

**Prior art**: OpenAI function calling searches by name/description only.
LangChain tool retrieval embeds descriptions only. Some commercial vector
databases may combine schema signals internally, but this approach is uncommon
in the open-source MCP ecosystem.

### 6.2 Feedback Learning Loop

The search-then-invoke pattern creates a natural supervised signal. When an LLM
searches "schedule meeting" and invokes `calendar_insert`, the gateway learns
that association. Over time, `calendar_insert` rises in results for "schedule
meeting" even if the embedding model does not capture that relationship.

The longer an installation runs, the better its search gets because it
accumulates real query/invocation feedback.

### 6.3 Zero-Dependency Runtime

No ONNX, no Python, no external services. The runtime is pure Rust f32 arithmetic.
The embedding generation is decoupled and optional. This means:

- `cargo install mcp-gateway` just works (no native dependencies)
- Air-gapped deployments work (pre-compute embeddings, ship the JSON)
- CI/CD can generate embeddings in a sidecar step

### 6.4 Graceful Degradation

```
Has embeddings.json?
  YES -> Full hybrid search (keyword + semantic rerank + feedback boost)
  NO  -> Has feedback data?
           YES -> Keyword search + feedback boost (still better than baseline)
           NO  -> Pure keyword search (existing behavior, zero regression)
```

The feature is strictly additive. Disabling `semantic-search` or deleting the
embeddings file returns to exact current behavior. No migration required.

---

## 7. Testing Strategy

### Unit Tests (src/semantic/tests.rs)

1. **SemanticIndex::from_store** -- roundtrip: build index from store, verify
   dimensions, key count, normalized vectors.
2. **SemanticIndex::search** -- known vectors with known cosine similarities;
   verify ranking order and score accuracy to 4 decimal places.
3. **SemanticIndex::search edge cases** -- empty index, zero query vector,
   dimension mismatch, all-below-threshold.
4. **SemanticIndex::is_stale** -- hash match = not stale, hash mismatch = stale,
   missing key = stale.
5. **build_embedding_text** -- verify schema parameters and enum values are
   included; verify tool name is doubled; verify stopwords are not filtered
   (embedding models handle them).
6. **SearchFeedback** -- record association, verify count increment, verify
   persistence roundtrip (save/load).
7. **bow_query_vector** -- deterministic output for same input; empty result for
   out-of-vocabulary query; correct TF-IDF weighting; cosine similarity between
   query BoW and tool BoW is in [0, 1] range for non-negative TF-IDF.

### Integration Tests

8. **search_tools with semantic fallback** -- keyword search returns 0, semantic
   returns relevant tools. Verify `semantic_match: true` annotation in response.
9. **search_tools with semantic rerank** -- keyword search returns 50, semantic
   reranks to promote the most relevant. Verify top-3 are semantically correct.
10. **Hot-reload** -- change a tool description, trigger reload, verify embedding
    is flagged stale, keyword search still works for that tool.
11. **Feature gate** -- compile without `semantic-search` feature, verify all
    existing search tests still pass.

### Property Tests

12. **Cosine similarity is symmetric**: `sim(a, b) == sim(b, a)`.
13. **Self-similarity is 1.0**: `sim(a, a) == 1.0` for any normalized vector.
14. **Score monotonicity**: if keyword score(A) > keyword score(B) and
    semantic_sim(A) >= semantic_sim(B), then final_score(A) > final_score(B).

---

## 8. Migration Path

### Phase 1: Ship the Index (week 1)
- Add `src/semantic/mod.rs` with `SemanticIndex` and `load_store()`.
- Feature-gated behind `semantic-search`.
- No behavioral change without embeddings.json.

### Phase 2: CLI Embed Command (week 2)
- Add `mcp-gateway embed` subcommand.
- Uses `ort` (ONNX Runtime for Rust) behind a feature flag.
- Generates `embeddings.json` from registered tools.

### Phase 3: Wire into Search (week 3)
- Modify `search_tools` to use `SemanticIndex` for reranking.
- Add zero-result semantic fallback.
- Add `query_vector` parameter support.

### Phase 4: Feedback Loop (week 4)
- Add `SearchFeedback` recording in `invoke_tool`.
- Add feedback boost to `rank()`.
- Add persistence.

---

## 9. Risk Register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Embedding model quality varies -- wrong model produces poor results | Medium | High | Default to well-benchmarked model (gte-small, MTEB rank 1 for size). Allow user to specify model. Feedback loop corrects over time. |
| R2 | Pre-computed embeddings go stale after config changes | Medium | Medium | `text_hash` staleness detection. Stale tools fall back to keyword-only. Hot-reload triggers re-embed warning in logs. |
| R3 | BoW TF-IDF similarity is too weak for intent queries with vocabulary mismatch | Medium | Medium | BoW handles exact and stemmed term overlap well. For true semantic intent matching (e.g. "schedule meeting" -> calendar), Strategy B (client-provided dense vector) provides neural-quality results. BoW is the bootstrap path; Strategy B is the upgrade. |
| R4 | Feedback data creates filter bubble (popular tools get more popular) | Low | Medium | Feedback boost is multiplicative and capped (max 2x). Tools with zero feedback still appear via keyword/semantic score. Feedback decays (rolling 30-day window). |
| R5 | embeddings.json file is large for many tools | Low | Low | At 10K tools x 384 dims: ~30MB compressed. Acceptable. For extreme scale, switch to memory-mapped file. |
| R6 | Feature flag complexity | Low | Low | Single `#[cfg(feature = "semantic-search")]` gate. When disabled, zero code paths are affected. |

---

## 10. Interaction with RFC-0073 (Context-Aware Tool Profiles)

When a tool profile is active (RFC-0073), semantic search respects the profile
boundary:

1. **Keyword + semantic rerank (matches > 0)**: Both keyword filtering and
   semantic reranking operate within the active profile's tool set. Tools
   outside the profile are excluded from the candidate set.

2. **Semantic fallback (matches == 0)**: The fallback first searches within
   the active profile. If fewer than 3 results are found within the profile,
   the search expands to the global tool set. Results from outside the active
   profile are annotated with `"outside_profile": true` and
   `"semantic_match": true`.

3. **Profile hints**: When semantic search finds strong matches in a non-active
   profile, the `profile_hint` from RFC-0073 is included in the response,
   guiding the LLM to switch profiles for better coverage.

4. **BoW vocabulary is global**: The shared vocabulary and IDF weights are
   computed across all tools regardless of profiles. This ensures that BoW
   similarity scores are comparable across profile boundaries.

---

## 11. Shared Prerequisites

**Prerequisite**: Implement session disconnect callback in `src/gateway/server.rs` that notifies all per-session state holders. All RFCs adding per-session DashMap entries MUST register a cleanup handler.

---

## 12. ADR: Architecture Decision Record

### ADR-0072: Hybrid Keyword + Semantic Rerank for Tool Search

**Status**: Proposed
**Date**: 2026-03-13
**Deciders**: Mikko Parkkola

#### Context

mcp-gateway's keyword search fails on intent-based queries. With 180+ tools
growing to 500+, the synonym table approach is not sustainable. GPT-5.4 has
native embedding-based tool search.

#### Decision

Implement a hybrid search system that:
1. Uses existing keyword search as the first-pass filter (free, already exists).
2. Reranks keyword results using pre-computed embedding cosine similarity.
3. Falls back to full semantic scan when keyword search returns zero results.
4. Separates embedding generation (offline) from search (online) to avoid
   runtime dependencies.

#### Consequences

**Positive**:
- Zero new runtime dependencies (pure f32 math).
- Graceful degradation (works without embeddings, just keyword).
- Ranking quality can improve over time via feedback learning.
- <2ms p95 latency (within budget).
- Schema-augmented embeddings are uncommon in open-source MCP gateways.

**Negative**:
- Requires an initial embedding generation step (CLI command or external).
- BoW TF-IDF similarity (default path) is lower quality than neural embeddings.
- Adds ~700-900 LOC of new code (SearchFeedback deferred to follow-up).

**Neutral**:
- Feature-gated; opt-in.
- No breaking changes to existing API.
