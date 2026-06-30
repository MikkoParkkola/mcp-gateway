/// Return the synonym group for a given word (all lowercase).
///
/// Each word maps to the *other* members of its group. Matches against synonyms
/// score at 0.8x of an exact match to prefer literal terms. Returns an empty
/// slice when the word has no known synonyms.
///
/// # Extending the synonym map
///
/// Add a new `match` arm with the canonical and alternate spellings:
/// ```text
/// "send" | "deliver" | "publish" | "emit" => &["send", "deliver", "publish", "emit"],
/// ```
/// Every word in the group must map to the full group (bidirectional).
#[must_use]
pub fn expand_synonyms(word: &str) -> &'static [&'static str] {
    match word {
        // search group
        "search" | "find" | "discover" | "locate" | "lookup" | "query" => {
            &["search", "find", "discover", "locate", "lookup", "query"]
        }
        // monitor group
        "monitor" | "watch" | "track" | "observe" | "alert" => {
            &["monitor", "watch", "track", "observe", "alert"]
        }
        // extract group
        "extract" | "scrape" | "parse" | "pull" | "fetch" => {
            &["extract", "scrape", "parse", "pull", "fetch"]
        }
        // create group
        "create" | "generate" | "make" | "build" | "produce" => {
            &["create", "generate", "make", "build", "produce"]
        }
        // analyze group
        "analyze" | "examine" | "inspect" | "audit" | "review" => {
            &["analyze", "examine", "inspect", "audit", "review"]
        }
        // batch group
        "batch" | "bulk" | "mass" | "parallel" | "concurrent" => {
            &["batch", "bulk", "mass", "parallel", "concurrent"]
        }
        // entity group
        "entity" | "record" | "item" | "object" | "resource" => {
            &["entity", "record", "item", "object", "resource"]
        }
        // research group
        "research" | "investigate" | "study" | "explore" => {
            &["research", "investigate", "study", "explore"]
        }
        // send group
        "send" | "deliver" | "publish" | "emit" | "notify" => {
            &["send", "deliver", "publish", "emit", "notify"]
        }
        // delete group
        "delete" | "remove" | "purge" | "clear" | "destroy" => {
            &["delete", "remove", "purge", "clear", "destroy"]
        }
        // list group
        "list" | "enumerate" | "browse" | "catalog" | "index" => {
            &["list", "enumerate", "browse", "catalog", "index"]
        }
        // convert group
        "convert" | "transform" | "translate" | "format" | "encode" => {
            &["convert", "transform", "translate", "format", "encode"]
        }
        // execute group
        "execute" | "run" | "invoke" | "call" | "trigger" => {
            &["execute", "run", "invoke", "call", "trigger"]
        }
        // show group
        "show" | "display" | "render" | "print" | "view" => {
            &["show", "display", "render", "print", "view"]
        }
        // check group
        "check" | "validate" | "verify" | "test" | "assert" => {
            &["check", "validate", "verify", "test", "assert"]
        }
        // modify group
        "modify" | "update" | "edit" | "change" | "patch" => {
            &["modify", "update", "edit", "change", "patch"]
        }
        // count group
        "count" | "aggregate" | "summarize" | "total" | "tally" => {
            &["count", "aggregate", "summarize", "total", "tally"]
        }
        // access group
        "access" | "read" | "get" | "retrieve" | "obtain" => {
            &["access", "read", "get", "retrieve", "obtain"]
        }
        // store group
        "store" | "save" | "write" | "persist" | "cache" => {
            &["store", "save", "write", "persist", "cache"]
        }
        // connect group
        "connect" | "link" | "attach" | "join" | "bind" => {
            &["connect", "link", "attach", "join", "bind"]
        }
        _ => &[],
    }
}

/// Score multiplier applied to synonym-expanded matches.
///
/// Exact matches retain their full score; synonym matches are discounted
/// to prefer literal term alignment over semantic expansion.
pub(super) const SYNONYM_MULTIPLIER: f64 = 0.8;

/// Return `true` if `text` contains `word` as a substring, or contains any
/// synonym of `word`. The `synonym_hit` output flag is set to `true` when a
/// synonym (not the word itself) produced the match; callers can apply the
/// `SYNONYM_MULTIPLIER` in that case.
fn text_contains_with_synonyms(text: &str, word: &str) -> (bool, bool) {
    if text.contains(word) {
        return (true, false);
    }
    for syn in expand_synonyms(word) {
        if *syn != word && text.contains(*syn) {
            return (true, true);
        }
    }
    (false, false)
}

/// Keyword-tag scoring: returns `(score, via_synonym)`.
///
/// Tier: `6 + 2N` where N is the number of matched keyword tags.
#[allow(clippy::cast_precision_loss)]
fn keyword_tag_score(desc_lower: &str, words: &[&str]) -> (f64, bool) {
    if !desc_lower.contains("[keywords:") {
        return (0.0, false);
    }
    let exact_kw = count_keyword_matches(desc_lower, words);
    if exact_kw > 0 {
        return (6.0 + (exact_kw as f64) * 2.0, false);
    }
    let syn_kw = count_keyword_matches_with_synonyms(desc_lower, words);
    if syn_kw > 0 {
        (6.0 + (syn_kw as f64) * 2.0, true)
    } else {
        (0.0, false)
    }
}

/// Text-coverage scoring for multi-word queries: returns `(score, via_synonym)`.
///
/// Counts query words found anywhere in `combined` (tool name + description).
/// Tiers: `10+2N` (all N matched), `3+2M` (M of N partial), `0` (no match).
#[allow(clippy::cast_precision_loss)]
fn text_coverage_score(combined: &str, words: &[&str]) -> (f64, bool) {
    if words.len() <= 1 {
        return (0.0, false);
    }
    let exact_matched = words.iter().filter(|w| combined.contains(**w)).count();
    if exact_matched == words.len() {
        return (10.0 + (exact_matched as f64) * 2.0, false);
    }
    let syn_matched = words
        .iter()
        .filter(|w| text_contains_with_synonyms(combined, w).0)
        .count();
    let any_syn = words
        .iter()
        .any(|w| text_contains_with_synonyms(combined, w).1);
    if syn_matched == words.len() {
        (10.0 + (syn_matched as f64) * 2.0, any_syn)
    } else if syn_matched > 0 {
        (3.0 + (syn_matched as f64) * 2.0, any_syn)
    } else {
        (0.0, false)
    }
}

/// Select the winning `(score, via_synonym)` from the three scoring paths.
///
/// Schema scores are never synonym-discounted (field names are exact identifiers).
fn best_coverage_score(kw: (f64, bool), schema: f64, text: (f64, bool)) -> (f64, bool) {
    let (kw_best, kw_syn) = if kw.0 >= text.0 { kw } else { text };
    if schema > kw_best {
        (schema, false)
    } else {
        (kw_best, kw_syn)
    }
}

/// Compute text relevance score for a single result against a pre-lowercased query.
///
/// `words` must be `query.split_whitespace().collect()`; passed in to avoid
/// re-splitting for every result in a batch.
pub(super) fn score_text_relevance(
    tool: &str,
    description: &str,
    query: &str,
    words: &[&str],
) -> f64 {
    let tool_lower = tool.to_lowercase();
    let desc_lower = description.to_lowercase();

    if tool_lower == query {
        return 10.0;
    }

    if words.len() > 1 {
        if words.iter().all(|w| tool_lower.contains(w)) {
            return 15.0;
        }
        let syn_all_in_name = words
            .iter()
            .all(|w| text_contains_with_synonyms(&tool_lower, w).0);
        let any_synonym = words
            .iter()
            .any(|w| text_contains_with_synonyms(&tool_lower, w).1);
        if syn_all_in_name && any_synonym {
            return 15.0 * SYNONYM_MULTIPLIER;
        }
    }

    let combined = format!("{tool_lower} {desc_lower}");
    let (best, via_syn) = best_coverage_score(
        keyword_tag_score(&desc_lower, words),
        schema_field_score(&desc_lower, words),
        text_coverage_score(&combined, words),
    );
    if best > 0.0 {
        return if via_syn {
            best * SYNONYM_MULTIPLIER
        } else {
            best
        };
    }

    if tool_lower.contains(query) {
        return 5.0;
    }
    if words.len() == 1 && is_schema_field_match(&desc_lower, query) {
        return 6.0;
    }
    if desc_lower.contains(query) {
        return 2.0;
    }
    if words.len() == 1 {
        for syn in expand_synonyms(query) {
            if *syn != query {
                if tool_lower.contains(syn) {
                    return 5.0 * SYNONYM_MULTIPLIER;
                }
                if desc_lower.contains(syn) {
                    return 2.0 * SYNONYM_MULTIPLIER;
                }
            }
        }
    }

    0.0
}

/// Extract a bracketed tag section from a lowercased description by its prefix.
pub(super) fn extract_tag_section<'a>(desc_lower: &'a str, prefix: &str) -> Option<&'a str> {
    let marker = format!("[{prefix}:");
    let start = desc_lower.find(marker.as_str())?;
    let after_marker = &desc_lower[start + marker.len()..];
    let end = after_marker.find(']').unwrap_or(after_marker.len());
    Some(&after_marker[..end])
}

/// Check whether `word` appears as a discrete keyword inside the
/// `[keywords: tag1, tag2, ...]` suffix of a lowercased description.
pub(super) fn is_keyword_match(desc_lower: &str, word: &str) -> bool {
    let Some(section) = extract_tag_section(desc_lower, "keywords") else {
        return false;
    };
    section.split(',').any(|tag| {
        let tag = tag.trim();
        tag == word || tag.split('-').any(|part| part == word)
    })
}

/// Check whether `word` appears as a token inside the `[schema: ...]` suffix.
#[must_use]
pub fn is_schema_field_match(desc_lower: &str, word: &str) -> bool {
    let Some(section) = extract_tag_section(desc_lower, "schema") else {
        return false;
    };
    section.split(',').any(|token| token.trim() == word)
}

fn count_schema_field_matches(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_schema_field_match(desc_lower, w))
        .count()
}

#[allow(clippy::cast_precision_loss)]
fn schema_field_score(desc_lower: &str, words: &[&str]) -> f64 {
    if !desc_lower.contains("[schema:") {
        return 0.0;
    }
    let n = count_schema_field_matches(desc_lower, words);
    if n > 0 { 4.0 + (n as f64) * 2.0 } else { 0.0 }
}

/// Check whether `word` or any of its synonyms appears as a keyword tag in the description.
pub(super) fn is_keyword_match_with_synonyms(desc_lower: &str, word: &str) -> bool {
    if is_keyword_match(desc_lower, word) {
        return true;
    }
    expand_synonyms(word)
        .iter()
        .any(|syn| *syn != word && is_keyword_match(desc_lower, syn))
}

fn count_keyword_matches(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_keyword_match(desc_lower, w))
        .count()
}

fn count_keyword_matches_with_synonyms(desc_lower: &str, words: &[&str]) -> usize {
    words
        .iter()
        .filter(|w| is_keyword_match_with_synonyms(desc_lower, w))
        .count()
}
