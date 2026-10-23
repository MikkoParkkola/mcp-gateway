// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

fn oracle(text: &[char], pattern: &[char], calls: &mut u64, budget: u64) -> Option<bool> {
    *calls += 1;
    if *calls > budget {
        return None;
    }
    match (text.first(), pattern.first()) {
        (None, None) => Some(true),
        (None, Some('*')) => oracle(text, &pattern[1..], calls, budget),
        (None, _) | (Some(_), None) => Some(false),
        (Some(_), Some('*')) => match oracle(text, &pattern[1..], calls, budget) {
            None => None,
            Some(true) => Some(true),
            Some(false) => oracle(&text[1..], pattern, calls, budget),
        },
        (Some(_), Some('?')) => oracle(&text[1..], &pattern[1..], calls, budget),
        (Some(t), Some(p)) => {
            if *t == *p {
                oracle(&text[1..], &pattern[1..], calls, budget)
            } else {
                Some(false)
            }
        }
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

/// MIK-8683 design r3: at most n+1 backtrack phases of at most m+1 main-loop iterations, plus at most m trailing-star skips.
fn bound(n: usize, m: usize) -> u64 {
    ((n + 1) * (m + 1) + m) as u64
}

#[test]
fn a_balanced_star_pattern_stays_within_the_bound() {
    let text: Vec<char> = vec!['a'; 12];
    let mut pattern: Vec<char> = vec!['*'; 12];
    pattern.push('!');
    let (matched, steps) = glob_match_steps(&text, &pattern);
    assert!(
        !matched,
        "balanced star pattern with trailing ! must not match"
    );
    let b = bound(12, 13);
    assert!(
        steps <= b,
        "steps {steps} exceeded bound {b} for n=12, m=13"
    );
}

#[test]
fn a_repeated_prefix_mismatch_stays_within_the_bound() {
    let text: Vec<char> = vec!['a'; 30];
    let pattern: Vec<char> = {
        let mut p = vec!['*'];
        p.extend(std::iter::repeat_n('a', 10));
        p.push('b');
        p
    };
    let (matched, steps) = glob_match_steps(&text, &pattern);
    assert!(!matched, "repeated prefix mismatch must not match");
    let b = bound(30, 12);
    assert!(
        steps <= b,
        "steps {steps} exceeded bound {b} for n=30, m=12"
    );
}

#[test]
fn the_old_matcher_needs_far_more_steps_than_the_bound() {
    for (n, k) in [(8, 8), (10, 10), (12, 12)] {
        let text: Vec<char> = vec!['a'; n];
        let mut pattern: Vec<char> = vec!['*'; k];
        pattern.push('!');
        let mut calls: u64 = 0;
        let result = oracle(&text, &pattern, &mut calls, 100_000_000);
        assert_eq!(
            result,
            Some(false),
            "oracle n={n}, k={k} must be Some(false)"
        );
        let b = bound(n, k + 1);
        assert!(
            calls > 100 * b,
            "oracle n={n}, k={k}: calls {calls} not > 100 * bound {b}"
        );
    }
    let name: Vec<char> = chars("gateway:ab_cdefghi");
    assert_eq!(name.len(), 18);
    let mut pattern: Vec<char> = vec!['*'; 40];
    pattern.push('!');
    let mut calls: u64 = 0;
    let result = oracle(&name, &pattern, &mut calls, 10_000_000);
    assert_eq!(
        result, None,
        "oracle on gateway:ab_cdefghi with 40 stars must exhaust the 10_000_000 budget"
    );
}

#[test]
fn the_matcher_agrees_with_the_old_one_on_a_generated_corpus() {
    fn next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }
    let pat_alphabet: [char; 6] = ['a', 'b', '_', ':', '*', '?'];
    let name_alphabet: [char; 4] = ['a', 'b', '_', ':'];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    let fixed: [(&str, &str); 14] = [
        ("brave_search", "*search"),
        ("brave_search", "brave_*"),
        ("file_read", "file_?ead"),
        ("file_read", "file_??ead"),
        ("", ""),
        ("", "*"),
        ("", "**"),
        ("abc", ""),
        ("a", "?"),
        ("", "?"),
        ("ab", "?"),
        ("ab_cd", "*_*"),
        ("a_cd", "?_*d"),
        ("anything", "**"),
    ];

    for (name, pat) in fixed {
        let name_c = chars(name);
        let pat_c = chars(pat);
        let mut calls: u64 = 0;
        let Some(expected) = oracle(&name_c, &pat_c, &mut calls, 10_000_000) else {
            panic!("oracle budget exhausted for fixed pair ({name:?}, {pat:?})");
        };
        let (matched, _) = glob_match_steps(&name_c, &pat_c);
        assert_eq!(matched, expected, "fixed pair ({name:?}, {pat:?}) mismatch");
    }

    for iter in 0..20_000 {
        let pat_len = (next(&mut state) % 9) as usize;
        let name_len = (next(&mut state) % 11) as usize;
        let mut pattern: Vec<char> = Vec::with_capacity(pat_len);
        for _ in 0..pat_len {
            let idx = (next(&mut state) % 6) as usize;
            pattern.push(pat_alphabet[idx]);
        }
        let mut name: Vec<char> = Vec::with_capacity(name_len);
        for _ in 0..name_len {
            let idx = (next(&mut state) % 4) as usize;
            name.push(name_alphabet[idx]);
        }
        let mut calls: u64 = 0;
        let Some(expected) = oracle(&name, &pattern, &mut calls, 10_000_000) else {
            panic!("oracle budget exhausted at iter {iter} for ({name:?}, {pattern:?})");
        };
        let (matched, steps) = glob_match_steps(&name, &pattern);
        assert_eq!(
            matched, expected,
            "generated pair iter {iter} ({name:?}, {pattern:?}) mismatch"
        );
        let b = bound(name.len(), pattern.len());
        assert!(
            steps <= b,
            "generated pair iter {iter} ({name:?}, {pattern:?}): steps {steps} over bound {b}"
        );
    }
}

#[test]
fn unicode_lowercase_expansion_is_matched_like_the_old_matcher() {
    // (g) "İstanbul" vs "i*"
    let name_lower = "İstanbul".to_lowercase();
    let pat_lower = "i*".to_lowercase();
    let name_c = chars(&name_lower);
    let pat_c = chars(&pat_lower);
    let mut calls: u64 = 0;
    let Some(expected) = oracle(&name_c, &pat_c, &mut calls, 10_000_000) else {
        panic!("oracle budget exhausted for İstanbul / i*");
    };
    assert_eq!(
        tool_name_matches_glob("İstanbul", "i*"),
        expected,
        "İstanbul / i* disagrees with oracle on lowercased inputs"
    );

    // "İ" lowercases to 2 chars; "??" must match, "?" must not — via oracle.
    let dotted_lower = "İ".to_lowercase();
    let dotted_c = chars(&dotted_lower);
    for pat in ["??", "?"] {
        let pat_lowered = pat.to_lowercase();
        let pat_c2 = chars(&pat_lowered);
        let mut calls2: u64 = 0;
        let Some(expected2) = oracle(&dotted_c, &pat_c2, &mut calls2, 10_000_000) else {
            panic!("oracle budget exhausted for İ / {pat}");
        };
        assert_eq!(
            tool_name_matches_glob("İ", pat),
            expected2,
            "İ / {pat} disagrees with oracle on lowercased inputs"
        );
    }
    // Pinned as booleans too, so an edit to the oracle cannot flip them.
    assert_eq!(dotted_c.len(), 2, "lowercased İ is two chars");
    assert!(tool_name_matches_glob("İ", "??"), "İ matches ??");
    assert!(!tool_name_matches_glob("İ", "?"), "İ does not match ?");

    // The pattern side expands too: "İ*" lowercases to three chars.
    let name_c3 = chars(&"i\u{307}stanbul".to_lowercase());
    let pat_c3 = chars(&"İ*".to_lowercase());
    assert_eq!(pat_c3.len(), 3, "lowercased İ* is three chars");
    let mut calls3: u64 = 0;
    let Some(expected3) = oracle(&name_c3, &pat_c3, &mut calls3, 10_000_000) else {
        panic!("oracle budget exhausted for i\u{307}stanbul / İ*");
    };
    assert_eq!(
        tool_name_matches_glob("i\u{307}stanbul", "İ*"),
        expected3,
        "i\u{307}stanbul / İ* disagrees with oracle on lowercased inputs"
    );
    assert!(expected3, "the expanded pattern matches the expanded name");
}

fn bundled_references() -> Vec<String> {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/capabilities"));
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("read_dir on capabilities tree");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    let mut references: Vec<String> = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path).expect("read capability yaml");
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("name:") {
                let value = rest.trim().trim_matches('"').trim_matches('\'').trim();
                if !value.is_empty() {
                    references.push(format!("gateway:{value}").to_lowercase());
                }
                break;
            }
        }
    }
    references
}

#[test]
fn the_ticket_query_stays_within_the_bound_against_every_bundled_name() {
    let mut pattern: Vec<char> = vec!['*'; 40];
    pattern.push('!');
    let references = bundled_references();
    assert!(
        references.len() >= 50,
        "expected at least 50 bundled references, found {}",
        references.len()
    );
    for r in &references {
        let (matched, steps) = glob_match_steps(&chars(r), &pattern);
        assert!(!matched, "ticket query must not match {r}");
        let b = bound(r.chars().count(), 41);
        assert!(
            steps <= b,
            "steps {steps} exceeded bound {b} for {r} against the ticket query"
        );
    }
}

/// The iterative matcher holds no stack frame per star, so a long star run cannot overflow the stack (MIK-8683, found independently by the sec2 review).
#[test]
fn a_256_star_pattern_matches_without_recursion_within_the_bound() {
    let pattern: Vec<char> = vec!['*'; 256];
    let mut pattern_bang: Vec<char> = vec!['*'; 256];
    pattern_bang.push('!');
    for name in ["gateway:ab_cdefghi", ""] {
        let n = name.chars().count();
        let (matched, steps) = glob_match_steps(&chars(name), &pattern);
        assert!(matched, "256 stars must match {name:?}");
        let b = bound(n, 256);
        assert!(
            steps <= b,
            "steps {steps} exceeded bound {b} for {name:?} against 256 stars"
        );
        let (matched, steps) = glob_match_steps(&chars(name), &pattern_bang);
        assert!(!matched, "256 stars + ! must not match {name:?}");
        let b = bound(n, 257);
        assert!(
            steps <= b,
            "steps {steps} exceeded bound {b} for {name:?} against 256 stars + !"
        );
    }
}
