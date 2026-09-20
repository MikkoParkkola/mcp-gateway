// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::SearchResult;
use super::scoring::name_is_boundary_aligned;

/// Descending sort key for a ranked result.
///
/// Ordering is lexicographic over the fields in declaration order: an exact
/// identifier match wins outright, then the numeric score, then whether the
/// query met the tool name on a token boundary. The boundary flag only breaks
/// ties the score could not, so it never reorders differently-scored results.
struct RankKey {
    /// The tool name is the query, case-insensitively.
    exact_identifier: bool,
    /// Combined relevance and usage score.
    score: f64,
    /// Every query word found in the name met it at a token boundary.
    boundary_aligned: bool,
}

impl RankKey {
    fn new(result: &SearchResult, query_lower: &str, words: &[&str]) -> Self {
        let name_lower = result.tool.to_lowercase();
        Self {
            exact_identifier: name_lower == query_lower,
            score: result.score,
            boundary_aligned: name_is_boundary_aligned(&name_lower, words),
        }
    }

    /// Compare so that the better result sorts first.
    ///
    /// Unorderable scores (`NaN`) compare equal, which preserves the previous
    /// `partial_cmp(..).unwrap_or(Equal)` behaviour for degenerate inputs.
    fn descending(&self, other: &Self) -> std::cmp::Ordering {
        other
            .exact_identifier
            .cmp(&self.exact_identifier)
            .then_with(|| {
                other
                    .score
                    .partial_cmp(&self.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| other.boundary_aligned.cmp(&self.boundary_aligned))
    }
}

/// Sort results by [`RankKey`], computing each key exactly once.
///
/// Decorating avoids rebuilding the lowercase tool name on every comparison,
/// and the stable sort keeps the original order for fully tied results.
pub(super) fn sort_by_rank(
    results: Vec<SearchResult>,
    query_lower: &str,
    words: &[&str],
) -> Vec<SearchResult> {
    let mut keyed: Vec<(RankKey, SearchResult)> = results
        .into_iter()
        .map(|result| (RankKey::new(&result, query_lower, words), result))
        .collect();
    keyed.sort_by(|(a, _), (b, _)| a.descending(b));
    keyed.into_iter().map(|(_, result)| result).collect()
}
