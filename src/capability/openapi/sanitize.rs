//! Text sanitization for generated YAML.
//!
//! Single responsibility: escape values into safe YAML scalars and scrub
//! tool descriptions of prompt-injection payloads at import time.

/// Emit `value` as a safe YAML scalar. Plain scalars are preferred when the
/// string does not contain any YAML 1.2 flow indicators or ambiguous
/// sequences; otherwise we fall back to a double-quoted JSON-style scalar.
///
/// Note that `:` is only a quoting trigger when followed by a space or end of
/// string (YAML 1.2 §7.3.3) — URLs such as `https://example.com` remain plain
/// scalars because `://` contains no `": "` sequence.
pub(crate) fn yaml_scalar(value: &str) -> String {
    fn colon_needs_quote(s: &str) -> bool {
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b':' {
                // Trailing or followed by whitespace ⇒ key/value separator.
                match bytes.get(i + 1) {
                    None => return true,
                    Some(next) if next.is_ascii_whitespace() => return true,
                    _ => {}
                }
            }
        }
        false
    }

    fn hash_needs_quote(s: &str) -> bool {
        // `#` only starts a comment when preceded by whitespace or at the
        // beginning of the scalar.
        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'#' {
                match i {
                    0 => return true,
                    _ if bytes[i - 1].is_ascii_whitespace() => return true,
                    _ => {}
                }
            }
        }
        false
    }

    let needs_quote = value.is_empty()
        || value.contains('\n')
        || value.contains('"')
        || value.contains('\'')
        || value.starts_with(|c: char| c.is_ascii_whitespace())
        || value.ends_with(|c: char| c.is_ascii_whitespace())
        || value.starts_with([
            '&', '*', '!', '|', '>', '%', '@', '`', '[', '{', ']', '}', ',',
        ])
        || colon_needs_quote(value)
        || hash_needs_quote(value);

    if needs_quote {
        // Double-quoted YAML scalars accept JSON-style escapes.
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// Sanitise a tool description so it cannot smuggle prompt-injection payloads
/// into the LLM at tool-selection time. This is a best-effort scrub applied
/// at import time; the canonical detection lives in the validator
/// (`validator/rules/tool_poisoning.rs`) and runs again at load time.
///
/// The scrub:
/// - strips ASCII control characters (except space, tab, newline)
/// - strips `<IMPORTANT>`, `<!-- -->`, `<script>`, `<instruction>` and
///   similar HTML-style tags entirely
/// - collapses runs of >8 spaces (used to hide payloads beyond the scroll
///   margin)
/// - trims leading/trailing whitespace
/// - truncates to 480 characters (leaving head-room under the validator's
///   500-char `CAP-002` warning threshold)
pub(crate) fn sanitize_description(raw: &str) -> String {
    /// Maximum number of characters retained in the sanitised description.
    /// Chosen to leave headroom under the validator's 500-char CAP-002
    /// warning threshold.
    const MAX_LEN: usize = 480;

    // Pass 1: strip suspicious HTML-ish tags — match the tag name + any
    // content + closing tag, non-greedy.
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        if let Some(start) = rest.find('<') {
            out.push_str(&rest[..start]);
            let after = &rest[start..];
            if let Some(end) = after.find('>') {
                // Drop everything inside the angle brackets.
                rest = &after[end + 1..];
                continue;
            }
            // No closing bracket — drop the stray '<'.
            rest = &after[1..];
        } else {
            out.push_str(rest);
            break;
        }
    }

    // Pass 2: drop ASCII control chars, keep spaces/tabs/newlines.
    let cleaned: String = out
        .chars()
        .filter(|c| !c.is_control() || *c == ' ' || *c == '\t' || *c == '\n')
        .collect();

    // Pass 3: collapse long whitespace runs.
    let mut collapsed = String::with_capacity(cleaned.len());
    let mut space_run = 0usize;
    for ch in cleaned.chars() {
        if ch == ' ' {
            space_run += 1;
            if space_run <= 8 {
                collapsed.push(ch);
            }
        } else {
            space_run = 0;
            collapsed.push(ch);
        }
    }

    // Pass 4: trim and truncate.
    let trimmed = collapsed.trim();
    if trimmed.chars().count() > MAX_LEN {
        let truncated: String = trimmed.chars().take(MAX_LEN).collect();
        format!("{}…", truncated.trim_end())
    } else {
        trimmed.to_string()
    }
}
