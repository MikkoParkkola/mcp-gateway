// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Round-2 wire literals, independent of the journal encoder and state helpers.

pub(super) const PENDING_FORWARD_WRONG: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":null,"new_revision":"bbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":{"action":"forward","expect"#,
    r#"ed":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","tried":false},"p"#,
    r#"hase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const PENDING_FORWARD_MATCH: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":null,"new_revision":"bbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":{"action":"forward","expect"#,
    r#"ed":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tried":false},"p"#,
    r#"hase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const PENDING_RESTORE_WRONG: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":null,"new_revision":"bbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":{"action":"restore","expect"#,
    r#"ed":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","tried":false},"p"#,
    r#"hase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const PENDING_RESTORE_MATCH: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":null,"new_revision":"bbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":{"action":"restore","expect"#,
    r#"ed":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tried":false},"p"#,
    r#"hase":"staged","version":2,"writer":null}"#,
)
.as_bytes();

pub(super) const FACT_COMMITTED_WRONG: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":{"committed":"ccccccccccccccccccccc"#,
    r#"ccccccccccccccccccccccccccccccccccccccccccc"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writ"#,
    r#"er":null}"#,
)
.as_bytes();

pub(super) const FACT_COMMITTED_MATCH: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":{"committed":"bbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"writ"#,
    r#"er":null}"#,
)
.as_bytes();

pub(super) const FACT_ROLLED_BACK_WRONG: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":{"rolled_back":"ccccccccccccccccccc"#,
    r#"ccccccccccccccccccccccccccccccccccccccccccccc"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"wr"#,
    r#"iter":null}"#,
)
.as_bytes();

pub(super) const FACT_ROLLED_BACK_MATCH: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":{"rolled_back":"aaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"new_revision":"bbbbbbbbbbbbbbbbbbbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaaaaaaaaaaaaaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged","version":2,"wr"#,
    r#"iter":null}"#,
)
.as_bytes();

macro_rules! decision_journal {
    ($result:literal, $reason:literal, $terminal:literal) => {
        concat!(
            r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"#,
            r#""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_rev"#,
            r#"ision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pendi"#,
            r#"ng":null,"phase":"staged","version":2,"writer":{"decision":{"delivery_stopped":f"#,
            r#"alse,"reason":""#,
            $reason,
            r#"","result":""#,
            $result,
            r#"","settled_by":null,"terminal":""#,
            $terminal,
            r#""},"handed_over":false,"intent":{"attribution":null,"caller_digest":"8db52a270d6"#,
            r#"06fc2078954f3a4f4766037fdf26b170d107b2131f00250db7f35","delivered":true,"parked""#,
            r#":null,"payload_json":[123,34,107,105,110,100,34,58,34,115,101,116,116,108,101,46"#,
            r#",115,97,118,101,34,125],"role":"config_save_intent"},"intent_counter":7,"records"#,
            r#"":[],"token":"writer-1"}}"#,
        )
        .as_bytes()
    };
}

// Design §3.1, §3.2(10), §3.3 and §3.6: rolled_back is valid for both
// writer/not_written and recovery/written. Deferred reasons are never outcomes.
pub(super) const OUTCOME_PAIRS: &[(&str, &str, bool, &[u8])] = &[
    (
        "written",
        "committed",
        true,
        decision_journal!("written", "committed", "outcome"),
    ),
    (
        "written",
        "rolled_back",
        true,
        decision_journal!("written", "rolled_back", "outcome"),
    ),
    (
        "written",
        "kept_new",
        true,
        decision_journal!("written", "kept_new", "outcome"),
    ),
    (
        "written",
        "nothing_pending",
        false,
        decision_journal!("written", "nothing_pending", "outcome"),
    ),
    (
        "written",
        "deleted_during_compute",
        false,
        decision_journal!("written", "deleted_during_compute", "outcome"),
    ),
    (
        "written",
        "compute_refused",
        false,
        decision_journal!("written", "compute_refused", "outcome"),
    ),
    (
        "written",
        "secrets_refused",
        false,
        decision_journal!("written", "secrets_refused", "outcome"),
    ),
    (
        "written",
        "writer_died",
        false,
        decision_journal!("written", "writer_died", "outcome"),
    ),
    (
        "written",
        "panicked",
        false,
        decision_journal!("written", "panicked", "outcome"),
    ),
    (
        "written",
        "operator_abandoned",
        false,
        decision_journal!("written", "operator_abandoned", "outcome"),
    ),
    (
        "written",
        "abandoned",
        false,
        decision_journal!("written", "abandoned", "outcome"),
    ),
    (
        "written",
        "moved",
        false,
        decision_journal!("written", "moved", "outcome"),
    ),
    (
        "written",
        "refused",
        false,
        decision_journal!("written", "refused", "outcome"),
    ),
    (
        "written",
        "renamed_not_durable",
        false,
        decision_journal!("written", "renamed_not_durable", "outcome"),
    ),
    (
        "written",
        "left_to_recovery",
        false,
        decision_journal!("written", "left_to_recovery", "outcome"),
    ),
    (
        "not_written",
        "committed",
        false,
        decision_journal!("not_written", "committed", "outcome"),
    ),
    (
        "not_written",
        "rolled_back",
        true,
        decision_journal!("not_written", "rolled_back", "outcome"),
    ),
    (
        "not_written",
        "kept_new",
        false,
        decision_journal!("not_written", "kept_new", "outcome"),
    ),
    (
        "not_written",
        "nothing_pending",
        true,
        decision_journal!("not_written", "nothing_pending", "outcome"),
    ),
    (
        "not_written",
        "deleted_during_compute",
        true,
        decision_journal!("not_written", "deleted_during_compute", "outcome"),
    ),
    (
        "not_written",
        "compute_refused",
        true,
        decision_journal!("not_written", "compute_refused", "outcome"),
    ),
    (
        "not_written",
        "secrets_refused",
        true,
        decision_journal!("not_written", "secrets_refused", "outcome"),
    ),
    (
        "not_written",
        "writer_died",
        true,
        decision_journal!("not_written", "writer_died", "outcome"),
    ),
    (
        "not_written",
        "panicked",
        true,
        decision_journal!("not_written", "panicked", "outcome"),
    ),
    (
        "not_written",
        "operator_abandoned",
        true,
        decision_journal!("not_written", "operator_abandoned", "outcome"),
    ),
    (
        "not_written",
        "abandoned",
        false,
        decision_journal!("not_written", "abandoned", "outcome"),
    ),
    (
        "not_written",
        "moved",
        true,
        decision_journal!("not_written", "moved", "outcome"),
    ),
    (
        "not_written",
        "refused",
        true,
        decision_journal!("not_written", "refused", "outcome"),
    ),
    (
        "not_written",
        "renamed_not_durable",
        false,
        decision_journal!("not_written", "renamed_not_durable", "outcome"),
    ),
    (
        "not_written",
        "left_to_recovery",
        false,
        decision_journal!("not_written", "left_to_recovery", "outcome"),
    ),
    (
        "unproven",
        "committed",
        false,
        decision_journal!("unproven", "committed", "outcome"),
    ),
    (
        "unproven",
        "rolled_back",
        false,
        decision_journal!("unproven", "rolled_back", "outcome"),
    ),
    (
        "unproven",
        "kept_new",
        false,
        decision_journal!("unproven", "kept_new", "outcome"),
    ),
    (
        "unproven",
        "nothing_pending",
        false,
        decision_journal!("unproven", "nothing_pending", "outcome"),
    ),
    (
        "unproven",
        "deleted_during_compute",
        false,
        decision_journal!("unproven", "deleted_during_compute", "outcome"),
    ),
    (
        "unproven",
        "compute_refused",
        false,
        decision_journal!("unproven", "compute_refused", "outcome"),
    ),
    (
        "unproven",
        "secrets_refused",
        false,
        decision_journal!("unproven", "secrets_refused", "outcome"),
    ),
    (
        "unproven",
        "writer_died",
        false,
        decision_journal!("unproven", "writer_died", "outcome"),
    ),
    (
        "unproven",
        "panicked",
        false,
        decision_journal!("unproven", "panicked", "outcome"),
    ),
    (
        "unproven",
        "operator_abandoned",
        false,
        decision_journal!("unproven", "operator_abandoned", "outcome"),
    ),
    (
        "unproven",
        "abandoned",
        false,
        decision_journal!("unproven", "abandoned", "outcome"),
    ),
    (
        "unproven",
        "moved",
        false,
        decision_journal!("unproven", "moved", "outcome"),
    ),
    (
        "unproven",
        "refused",
        false,
        decision_journal!("unproven", "refused", "outcome"),
    ),
    (
        "unproven",
        "renamed_not_durable",
        false,
        decision_journal!("unproven", "renamed_not_durable", "outcome"),
    ),
    (
        "unproven",
        "left_to_recovery",
        false,
        decision_journal!("unproven", "left_to_recovery", "outcome"),
    ),
];

pub(super) const ABANDONED_PAIRS: &[(&str, &str, bool, &[u8])] = &[
    (
        "written",
        "abandoned",
        false,
        decision_journal!("written", "abandoned", "abandoned"),
    ),
    (
        "written",
        "refused",
        false,
        decision_journal!("written", "refused", "abandoned"),
    ),
    (
        "not_written",
        "abandoned",
        true,
        decision_journal!("not_written", "abandoned", "abandoned"),
    ),
    (
        "not_written",
        "refused",
        false,
        decision_journal!("not_written", "refused", "abandoned"),
    ),
    (
        "unproven",
        "abandoned",
        true,
        decision_journal!("unproven", "abandoned", "abandoned"),
    ),
    (
        "unproven",
        "refused",
        false,
        decision_journal!("unproven", "refused", "abandoned"),
    ),
];

pub(super) const DEFERRED_CONFLICT: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged"#,
    r#"","version":2,"writer":{"decision":{"delivery_stopped":false,"reason":"refused","result""#,
    r#":"not_written","settled_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"at"#,
    r#"tribution":null,"caller_digest":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00"#,
    r#"250db7f35","delivered":true,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,3"#,
    r#"4,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"config_save_intent"},"intent"#,
    r#"_counter":7,"records":[{"attribution":null,"caller_digest":"59f23596631b0dc1ff4c4b8efd51"#,
    r#"f98449606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123"#,
    r#",34,105,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,5"#,
    r#"8,34,108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config"#,
    r#"_write_deferred"},{"attribution":null,"caller_digest":"d570bfed5154dc04c423a51ed0120aa74"#,
    r#"76527604ceeee72a2f4ad4199b7372b","delivered":true,"parked":null,"payload_json":[123,34,1"#,
    r#"05,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,5"#,
    r#"8,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,"#,
    r#"114,101,110,97,109,101,100,95,110,111,116,95,100,117,114,97,98,108,101,34,125],"role":"c"#,
    r#"onfig_write_deferred"},{"attribution":null,"caller_digest":"66bbc117d72dca58cf172aaae9cf"#,
    r#"2995aa2e58c7dd948f2b9f08f027072feed6","delivered":true,"parked":null,"payload_json":[123"#,
    r#",34,105,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,5"#,
    r#"8,34,114,101,102,117,115,101,100,34,44,34,114,101,115,117,108,116,34,58,34,110,111,116,9"#,
    r#"5,119,114,105,116,116,101,110,34,125],"role":"config_write_outcome"}],"token":"writer-1""#,
    r#"}}"#,
)
.as_bytes();

pub(super) const DEFERRED_EQUAL: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged"#,
    r#"","version":2,"writer":{"decision":{"delivery_stopped":false,"reason":"refused","result""#,
    r#":"not_written","settled_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"at"#,
    r#"tribution":null,"caller_digest":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00"#,
    r#"250db7f35","delivered":true,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,3"#,
    r#"4,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"config_save_intent"},"intent"#,
    r#"_counter":7,"records":[{"attribution":null,"caller_digest":"59f23596631b0dc1ff4c4b8efd51"#,
    r#"f98449606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123"#,
    r#",34,105,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,5"#,
    r#"8,34,108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config"#,
    r#"_write_deferred"},{"attribution":null,"caller_digest":"59f23596631b0dc1ff4c4b8efd51f9844"#,
    r#"9606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123,34,1"#,
    r#"05,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,5"#,
    r#"8,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,"#,
    r#"108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config_writ"#,
    r#"e_deferred"},{"attribution":null,"caller_digest":"66bbc117d72dca58cf172aaae9cf2995aa2e58"#,
    r#"c7dd948f2b9f08f027072feed6","delivered":true,"parked":null,"payload_json":[123,34,105,11"#,
    r#"0,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,58,34,"#,
    r#"115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,114,1"#,
    r#"01,102,117,115,101,100,34,44,34,114,101,115,117,108,116,34,58,34,110,111,116,95,119,114,"#,
    r#"105,116,116,101,110,34,125],"role":"config_write_outcome"}],"token":"writer-1"}}"#,
)
.as_bytes();

// Equal payload bytes and caller digest; only the retry attribution differs.
pub(super) const DEFERRED_CONFLICT_ATTRIBUTION: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged"#,
    r#"","version":2,"writer":{"decision":{"delivery_stopped":false,"reason":"refused","result""#,
    r#":"not_written","settled_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"at"#,
    r#"tribution":null,"caller_digest":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00"#,
    r#"250db7f35","delivered":true,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,3"#,
    r#"4,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"config_save_intent"},"intent"#,
    r#"_counter":7,"records":[{"attribution":null,"caller_digest":"59f23596631b0dc1ff4c4b8efd51"#,
    r#"f98449606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123"#,
    r#",34,105,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,5"#,
    r#"8,34,108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config"#,
    r#"_write_deferred"},{"attribution":{"actor":{"credential_kind":"oidc_bearer","principal":""#,
    r#"0123ab45cd67","account":"key-admin","authority":"https://issuer.example","subject":""#,
    r#"operator-7"}},"caller_digest":"59f23596631b0dc1ff4c4b8efd51f9844"#,
    r#"9606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123,34,1"#,
    r#"05,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,5"#,
    r#"8,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,"#,
    r#"108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config_writ"#,
    r#"e_deferred"},{"attribution":null,"caller_digest":"66bbc117d72dca58cf172aaae9cf2995aa2e58"#,
    r#"c7dd948f2b9f08f027072feed6","delivered":true,"parked":null,"payload_json":[123,34,105,11"#,
    r#"0,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,58,34,"#,
    r#"115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,114,1"#,
    r#"01,102,117,115,101,100,34,44,34,114,101,115,117,108,116,34,58,34,110,111,116,95,119,114,"#,
    r#"105,116,116,101,110,34,125],"role":"config_write_outcome"}],"token":"writer-1"}}"#,
)
.as_bytes();

// Equal payload bytes and attribution; only the retry caller digest differs.
pub(super) const DEFERRED_CONFLICT_CALLER_DIGEST: &[u8] = concat!(
    r#"{"attempts":[],"binding":"opaque-log:fixture","fact":"untouched","new_revision":"bbbbbbb"#,
    r#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_revision":"aaaaaaaa"#,
    r#"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pending":null,"phase":"staged"#,
    r#"","version":2,"writer":{"decision":{"delivery_stopped":false,"reason":"refused","result""#,
    r#":"not_written","settled_by":null,"terminal":"outcome"},"handed_over":false,"intent":{"at"#,
    r#"tribution":null,"caller_digest":"8db52a270d606fc2078954f3a4f4766037fdf26b170d107b2131f00"#,
    r#"250db7f35","delivered":true,"parked":null,"payload_json":[123,34,107,105,110,100,34,58,3"#,
    r#"4,115,101,116,116,108,101,46,115,97,118,101,34,125],"role":"config_save_intent"},"intent"#,
    r#"_counter":7,"records":[{"attribution":null,"caller_digest":"59f23596631b0dc1ff4c4b8efd51"#,
    r#"f98449606b979c1eca8a478c25cabd902f67","delivered":true,"parked":null,"payload_json":[123"#,
    r#",34,105,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100"#,
    r#",34,58,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,5"#,
    r#"8,34,108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config"#,
    r#"_write_deferred"},{"attribution":null,"caller_digest":"000000000000000000000000000000000"#,
    r#"0000000000000000000000000000000","delivered":true,"parked":null,"payload_json":[123,34,1"#,
    r#"05,110,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,5"#,
    r#"8,34,115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,"#,
    r#"108,101,102,116,95,116,111,95,114,101,99,111,118,101,114,121,34,125],"role":"config_writ"#,
    r#"e_deferred"},{"attribution":null,"caller_digest":"66bbc117d72dca58cf172aaae9cf2995aa2e58"#,
    r#"c7dd948f2b9f08f027072feed6","delivered":true,"parked":null,"payload_json":[123,34,105,11"#,
    r#"0,116,101,110,116,95,99,111,117,110,116,101,114,34,58,55,44,34,107,105,110,100,34,58,34,"#,
    r#"115,101,116,116,108,101,46,115,97,118,101,34,44,34,114,101,97,115,111,110,34,58,34,114,1"#,
    r#"01,102,117,115,101,100,34,44,34,114,101,115,117,108,116,34,58,34,110,111,116,95,119,114,"#,
    r#"105,116,116,101,110,34,125],"role":"config_write_outcome"}],"token":"writer-1"}}"#,
)
.as_bytes();
