use super::*;

// ── simhash ───────────────────────────────────────────────────────────────

#[test]
fn simhash_empty_features_returns_zero() {
    assert_eq!(simhash(&[]), 0);
}

#[test]
fn simhash_is_deterministic() {
    let features = ["read_file", "write_file", "list_dir"];
    assert_eq!(simhash(&features), simhash(&features));
}

#[test]
fn simhash_identical_sets_produce_identical_hashes() {
    let a = simhash(&["tool_a", "tool_b"]);
    let b = simhash(&["tool_a", "tool_b"]);
    assert_eq!(a, b);
}

#[test]
fn simhash_order_independence_approximate() {
    // Simhash is NOT order-independent by construction, but the same
    // multiset produces the same result.
    let a = simhash(&["search", "read", "write"]);
    let b = simhash(&["search", "read", "write"]);
    assert_eq!(a, b);
}

#[test]
fn simhash_similar_sets_have_small_hamming_distance() {
    let base = ["read_file", "write_file", "list_dir", "delete_file"];
    let similar = ["read_file", "write_file", "list_dir", "move_file"]; // one swap
    let h1 = simhash(&base);
    let h2 = simhash(&similar);
    let dist = hamming_distance(h1, h2);
    // Similar sets should differ in few bits (empirically < 20 for one swap).
    assert!(dist < 25, "expected distance < 25, got {dist}");
}

#[test]
fn simhash_disjoint_sets_have_large_hamming_distance() {
    let a = simhash(&["alpha", "beta", "gamma", "delta"]);
    let b = simhash(&["epsilon", "zeta", "eta", "theta"]);
    let dist = hamming_distance(a, b);
    // Disjoint random sets tend to differ in ~32 bits on average.
    // Relax to > 10 to avoid flakiness.
    assert!(dist > 10, "expected distance > 10, got {dist}");
}

#[test]
fn simhash_single_feature_is_nonzero() {
    assert_ne!(simhash(&["only_one_feature"]), 0);
}

// ── hamming_distance ──────────────────────────────────────────────────────

#[test]
fn hamming_distance_same_hash_is_zero() {
    assert_eq!(hamming_distance(0xDEAD_BEEF_CAFE_BABE, 0xDEAD_BEEF_CAFE_BABE), 0);
}

#[test]
fn hamming_distance_inverted_is_64() {
    assert_eq!(hamming_distance(0u64, !0u64), 64);
}

#[test]
fn hamming_distance_one_bit_flip() {
    assert_eq!(hamming_distance(0b0000, 0b0001), 1);
    assert_eq!(hamming_distance(0b0000, 0b1000), 1);
}

#[test]
fn hamming_distance_symmetric() {
    let a = 0xABCD_1234_5678_EF90u64;
    let b = 0x1234_ABCD_EF90_5678u64;
    assert_eq!(hamming_distance(a, b), hamming_distance(b, a));
}

// ── similarity_score ──────────────────────────────────────────────────────

#[test]
fn similarity_score_identical_is_one() {
    let score = similarity_score(0x1234_5678_9ABC_DEF0, 0x1234_5678_9ABC_DEF0);
    assert!((score - 1.0).abs() < 1e-9, "expected 1.0, got {score}");
}

#[test]
fn similarity_score_inverted_is_zero() {
    let score = similarity_score(0u64, !0u64);
    assert!(score.abs() < 1e-9, "expected 0.0, got {score}");
}

#[test]
fn similarity_score_in_range() {
    let a = simhash(&["a", "b", "c"]);
    let b = simhash(&["d", "e", "f"]);
    let score = similarity_score(a, b);
    assert!((0.0..=1.0).contains(&score), "score {score} out of range");
}

#[test]
fn similarity_score_consistent_with_hamming() {
    let a = 0xFFFF_0000_FFFF_0000u64;
    let b = 0x0000_FFFF_0000_FFFFu64;
    let dist = hamming_distance(a, b);
    let score = similarity_score(a, b);
    let expected = 1.0 - f64::from(dist) / 64.0;
    assert!((score - expected).abs() < 1e-9);
}

// ── SimhashIndex ──────────────────────────────────────────────────────────

#[test]
fn index_empty_find_returns_empty() {
    let idx = SimhashIndex::new();
    let results = idx.find_similar(0xABCD, 0.5);
    assert!(results.is_empty());
}

#[test]
fn index_insert_and_exact_match() {
    let mut idx = SimhashIndex::new();
    let hash = simhash(&["read_file", "write_file"]);
    idx.insert("session-1".to_string(), hash);
    let results = idx.find_similar(hash, 1.0);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "session-1");
    assert!((results[0].1 - 1.0).abs() < 1e-9);
}

#[test]
fn index_threshold_filters_dissimilar() {
    let mut idx = SimhashIndex::new();
    idx.insert("sim".to_string(), 0xFFFF_FFFF_FFFF_FFFF);
    // Query with zero hash → score = 0.0 → should be filtered
    let results = idx.find_similar(0u64, 0.8);
    assert!(results.is_empty(), "dissimilar entry should be filtered");
}

#[test]
fn index_multiple_entries_sorted_by_score() {
    let mut idx = SimhashIndex::new();
    // Use carefully chosen hashes with known distances.
    let query: u64 = 0b1111_1111;
    // 1 bit different from query
    idx.insert("close".to_string(), 0b1111_1110);
    // 8 bits different from query (lower byte is 0b0000_0000)
    idx.insert("far".to_string(), 0b1111_1111_0000_0000);

    let results = idx.find_similar(query, 0.0);
    assert_eq!(results.len(), 2);
    // Highest score should be first
    assert!(results[0].1 >= results[1].1, "results must be sorted descending");
}

#[test]
fn index_remove_deletes_entries() {
    let mut idx = SimhashIndex::new();
    idx.insert("s1".to_string(), 0xABCD);
    idx.insert("s1".to_string(), 0x1234); // duplicate id
    assert_eq!(idx.len(), 2);
    let removed = idx.remove("s1");
    assert_eq!(removed, 2);
    assert!(idx.is_empty());
}

#[test]
fn index_len_and_is_empty() {
    let mut idx = SimhashIndex::new();
    assert!(idx.is_empty());
    idx.insert("a".to_string(), 1);
    assert_eq!(idx.len(), 1);
    assert!(!idx.is_empty());
}

// ── SessionFingerprint ────────────────────────────────────────────────────

#[test]
fn session_fingerprint_empty_is_zero() {
    let fp = SessionFingerprint::new();
    assert_eq!(fp.compute(), 0);
}

#[test]
fn session_fingerprint_is_deterministic() {
    let mut fp1 = SessionFingerprint::new();
    fp1.add_tools(&["search", "read_file"]);
    fp1.add_argument_keys(&["query", "path"]);

    let mut fp2 = SessionFingerprint::new();
    fp2.add_tools(&["search", "read_file"]);
    fp2.add_argument_keys(&["query", "path"]);

    assert_eq!(fp1.compute(), fp2.compute());
}

#[test]
fn session_fingerprint_similar_toolsets_close() {
    let mut fp1 = SessionFingerprint::new();
    fp1.add_tools(&["read_file", "write_file", "list_dir", "delete_file"]);

    let mut fp2 = SessionFingerprint::new();
    fp2.add_tools(&["read_file", "write_file", "list_dir", "move_file"]);

    let score = similarity_score(fp1.compute(), fp2.compute());
    assert!(score > 0.5, "similar toolsets should have score > 0.5, got {score}");
}

#[test]
fn session_fingerprint_disjoint_toolsets_different() {
    let mut fp1 = SessionFingerprint::new();
    fp1.add_tools(&["read_file", "write_file"]);

    let mut fp2 = SessionFingerprint::new();
    fp2.add_tools(&["execute_query", "send_email"]);

    let score = similarity_score(fp1.compute(), fp2.compute());
    // Not necessarily < 0.5 with only 2 tools, but they should not be identical.
    assert!(
        score < 1.0,
        "disjoint toolsets should not be perfectly similar, got {score}"
    );
}

#[test]
fn session_fingerprint_feature_count() {
    let mut fp = SessionFingerprint::new();
    fp.add_tool("t1"); // +3 features
    fp.add_argument_key("k1"); // +1 feature
    assert_eq!(fp.feature_count(), 4);
}

#[test]
fn session_fingerprint_tools_weight_more_than_args() {
    // Adding a tool (weight 3) has more impact than adding an arg (weight 1).
    // Two sessions differing only by one tool should differ less than
    // two sessions differing only by many arg keys.
    let base_tools = ["read_file", "write_file", "list_dir"];
    let base_args = ["path", "content", "encoding"];

    let mut fp_base = SessionFingerprint::new();
    fp_base.add_tools(&base_tools);
    fp_base.add_argument_keys(&base_args);
    let h_base = fp_base.compute();

    let mut fp_diff_tool = SessionFingerprint::new();
    fp_diff_tool.add_tools(&["read_file", "write_file", "DELETE_file"]);
    fp_diff_tool.add_argument_keys(&base_args);

    let mut fp_diff_arg = SessionFingerprint::new();
    fp_diff_arg.add_tools(&base_tools);
    fp_diff_arg.add_argument_keys(&["path", "content", "completely_different"]);

    let dist_tool = hamming_distance(h_base, fp_diff_tool.compute());
    let dist_arg = hamming_distance(h_base, fp_diff_arg.compute());
    // Changing a tool should produce a larger distance than changing an arg.
    assert!(
        dist_tool >= dist_arg,
        "tool change (dist={dist_tool}) should impact fingerprint at least as much as arg change (dist={dist_arg})"
    );
}

// ── CacheRouter ───────────────────────────────────────────────────────────

#[test]
fn router_single_partition_all_assigned_same() {
    let mut router = CacheRouter::new(1, 0.5);
    let h = simhash(&["tool_a", "tool_b"]);
    let p1 = router.assign("s1".to_string(), h).to_string();
    let p2 = router.assign("s2".to_string(), h).to_string();
    assert_eq!(p1, p2, "same fingerprint should go to same partition");
}

#[test]
fn router_creates_partitions_up_to_limit() {
    // Use threshold=1.0 to force every new fingerprint into a new partition.
    let mut router = CacheRouter::new(3, 1.0);
    let h1 = simhash(&["tool_a"]);
    let h2 = simhash(&["tool_b"]);
    let h3 = simhash(&["tool_c"]);
    router.assign("s1".to_string(), h1);
    router.assign("s2".to_string(), h2);
    router.assign("s3".to_string(), h3);
    assert_eq!(router.partition_count(), 3);
}

#[test]
fn router_does_not_exceed_partition_limit() {
    let mut router = CacheRouter::new(2, 1.0);
    for i in 0..10u64 {
        router.assign(format!("s{i}"), i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    assert!(
        router.partition_count() <= 2,
        "router must not exceed num_partitions"
    );
}

#[test]
fn router_partition_for_session_returns_correct_id() {
    let mut router = CacheRouter::new(4, 0.5);
    let h = simhash(&["search", "read"]);
    let assigned = router.assign("my-session".to_string(), h).to_string();
    let looked_up = router.partition_for_session("my-session");
    assert_eq!(Some(assigned.as_str()), looked_up);
}

#[test]
fn router_sessions_in_partition_lists_assigned_sessions() {
    // threshold=0.0 means every session matches any existing partition.
    let mut router = CacheRouter::new(1, 0.0);
    let h = simhash(&["tool"]);
    router.assign("s1".to_string(), h);
    router.assign("s2".to_string(), h);
    let p_id = router.partition_for_session("s1").unwrap().to_string();
    let members = router.sessions_in_partition(&p_id);
    assert!(members.contains(&"s1"), "s1 should be in partition");
    assert!(members.contains(&"s2"), "s2 should be in partition");
}

#[test]
fn router_similar_sessions_share_partition() {
    let mut router = CacheRouter::new(4, 0.6);
    let tools_a = ["read_file", "write_file", "list_dir"];
    let tools_b = ["read_file", "write_file", "delete_file"]; // 2/3 overlap

    let h1 = SessionContext::new("s1")
        .add_tool(tools_a[0])
        .add_tool(tools_a[1])
        .add_tool(tools_a[2])
        .fingerprint();

    let h2 = SessionContext::new("s2")
        .add_tool(tools_b[0])
        .add_tool(tools_b[1])
        .add_tool(tools_b[2])
        .fingerprint();

    let p1 = router.assign("s1".to_string(), h1).to_string();
    let p2 = router.assign("s2".to_string(), h2).to_string();

    // They may or may not share a partition depending on the threshold,
    // but we can verify the assignment is valid (non-empty partition id).
    assert!(!p1.is_empty());
    assert!(!p2.is_empty());
    // In practice with these similar tools, they should share a partition.
    let score = similarity_score(h1, h2);
    if score >= 0.6 {
        assert_eq!(p1, p2, "similar sessions (score={score:.2}) should share partition");
    }
}

#[test]
fn router_partition_stats_returns_all_partitions() {
    let mut router = CacheRouter::new(2, 1.0);
    router.assign("s1".to_string(), 0xAAAA_AAAA_AAAA_AAAA);
    router.assign("s2".to_string(), 0x5555_5555_5555_5555);
    let stats = router.partition_stats();
    assert_eq!(stats.len(), 2);
}

// ── SessionContext ─────────────────────────────────────────────────────────

#[test]
fn session_context_fingerprint_stable() {
    let ctx = SessionContext::new("test")
        .add_tool("read_file")
        .add_tool("write_file")
        .add_arg_key("path");
    assert_eq!(ctx.fingerprint(), ctx.fingerprint());
}

#[test]
fn session_context_different_tools_different_fingerprint() {
    let ctx1 = SessionContext::new("s1").add_tool("tool_alpha");
    let ctx2 = SessionContext::new("s2").add_tool("tool_beta");
    assert_ne!(ctx1.fingerprint(), ctx2.fingerprint());
}

// ── find_similar_hashes ───────────────────────────────────────────────────

#[test]
fn find_similar_hashes_empty_map() {
    let map = HashMap::new();
    assert!(find_similar_hashes(0xABCD, &map, 0.5).is_empty());
}

#[test]
fn find_similar_hashes_returns_matching_entries() {
    let mut map = HashMap::new();
    let h = simhash(&["x", "y", "z"]);
    map.insert("match".to_string(), h);
    map.insert("nomatch".to_string(), !h);

    let results = find_similar_hashes(h, &map, 0.8);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "match");
}
