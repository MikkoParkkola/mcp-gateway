// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's one YAML seam (MIK-8425).
//!
//! Every YAML read and write goes through here, so the parser behind it can
//! be replaced in one place. Today the backend is `serde_yaml` 0.9.34. The
//! tree types are re-exported and the parse and write functions delegate,
//! keeping that crate's own behaviour. One function is the seam's own:
//! `to_json`, the tree-to-JSON conversion that `ImportedSkill.extra` uses.
//! A later stage swaps the backend behind this same surface.
//! `tests/fixtures/mik_8425_yaml/` records what the delegating functions must
//! reproduce, and the skills parser and registry tests pin `to_json`.
//! The seam's own `Error` (every function here except `figment_data`)
//! never prints the value that caused it (MIK-8425 B3); `figment_data`
//! returns figment's error, which `config/load_error.rs` (`from_figment`)
//! redacts.
//!
//! This file names nothing under `crate::`. Integration tests compile it
//! directly (`tests/common/yaml.rs`), so tests and the gateway always share
//! one implementation.
#![allow(
    dead_code,
    unused_imports,
    reason = "MIK-8425: consumers are routed through this seam in MIG.1b to MIG.1f; \
              until then parts of it have no caller. Integration-test crates compile their \
              own copy through tests/common/yaml.rs and never call all of it. Delete this \
              allow in MIG.2, when the swap re-examines the surface."
)]

use figment::Provider as _;
use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Map};
use granit_parser::{ErrorKind, Event, Marker, ScanError, TokenType};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};

/// The YAML tree and its mapping. They stay `serde_yaml`'s own until the
/// backend swap, which keeps routing a pure path rename.
pub(crate) use serde_yaml::{Mapping, Value};

/// The adapter's YAML error; its text never carries the value that caused it
/// (MIK-8425 B3, CWE-532), keeps the key path, expected type and line/column.
pub(crate) struct Error(Repr);

/// What an adapter error carries: the backend's own failure, or the guard's
/// refusal (MIK-8639). Both print value-free.
enum Repr {
    /// `serde_yaml`'s error, shown redacted exactly as before the guard.
    Backend(serde_yaml::Error),
    /// The guard's refusal: which limit fired, and for Syntax the wording
    /// plus an optional fixed fix hint.
    Refused {
        limit: Limit,
        what: Option<String>,
        hint: Option<&'static str>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Backend(err) => f.write_str(&redact_message(&err.to_string())),
            Repr::Refused { limit, what, hint } => match limit {
                Limit::Size { len, max } => {
                    write!(f, "YAML refused: {len} bytes, over the {max}-byte limit")
                }
                Limit::Depth { line } => {
                    write!(
                        f,
                        "YAML refused: nesting deeper than 128 levels at line {line}"
                    )
                }
                Limit::Aliases { .. } => f.write_str("YAML refused: more than 64 aliases"),
                Limit::TagDirectives { offset, .. } => {
                    write!(
                        f,
                        "YAML refused: more than 64 %TAG directives at byte {offset}"
                    )
                }
                Limit::Expansion => f.write_str("YAML refused: alias expansion over the limit"),
                Limit::AnchorReuse { offset } => {
                    write!(f, "YAML refused: anchor name reused at byte {offset}")
                }
                Limit::AnchorName { offset } => write!(
                    f,
                    "YAML refused: anchor or alias name outside [A-Za-z0-9_-] at byte {offset}; refused: parsers disagree"
                ),
                Limit::LineBreak { offset } => write!(
                    f,
                    "YAML refused: U+0085, U+2028 or U+2029 line break at byte {offset}; refused: parsers disagree"
                ),
                Limit::Syntax { line, column } => {
                    let what = what.as_deref().unwrap_or("syntax error");
                    if let Some(hint) = hint {
                        write!(
                            f,
                            "YAML refused: {what} at line {line} column {column}; {hint}"
                        )
                    } else {
                        write!(f, "YAML refused: {what} at line {line} column {column}")
                    }
                }
            },
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Backend(err) => f
                .debug_tuple("Error")
                .field(&redact_message(&err.to_string()))
                .finish(),
            // The limit only: never `what`'s source error.
            Repr::Refused { limit, .. } => f.debug_tuple("Error").field(limit).finish(),
        }
    }
}

// No `source()`: a chain printer must not reach serde_yaml's unredacted text.
impl std::error::Error for Error {}

impl Error {
    /// Where the refusal points in the document, if the parser knows.
    pub(crate) fn location(&self) -> Option<Location> {
        match &self.0 {
            Repr::Backend(err) => err.location().map(|at| Location {
                line: at.line(),
                column: at.column(),
            }),
            Repr::Refused { limit, .. } => match limit {
                Limit::Syntax { line, column } => Some(Location {
                    line: *line,
                    column: *column,
                }),
                _ => None,
            },
        }
    }

    /// Why the guard refused the text, when it did.
    pub(crate) fn limit(&self) -> Option<&Limit> {
        match &self.0 {
            Repr::Backend(_) => None,
            Repr::Refused { limit, .. } => Some(limit),
        }
    }

    /// The backend's own failure.
    fn backend(err: serde_yaml::Error) -> Self {
        Self(Repr::Backend(err))
    }

    /// The guard's refusal; `what` carries the Syntax wording and nothing else.
    fn refused(limit: Limit, what: Option<String>) -> Self {
        Self(Repr::Refused {
            limit,
            what,
            hint: None,
        })
    }

    /// The guard's refusal with a fixed fix hint for one Syntax kind.
    fn refused_hint(limit: Limit, what: Option<String>, hint: &'static str) -> Self {
        Self(Repr::Refused {
            limit,
            what,
            hint: Some(hint),
        })
    }
}

/// Why the guard refused a text. Value-free: carries positions and limits, never document bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Limit {
    /// The text is longer than the size gate.
    Size { len: usize, max: usize },
    /// Collections nest deeper than 128 levels; the line where the 129th opens.
    Depth { line: usize },
    /// The stream holds more than 64 alias references.
    Aliases { max: usize },
    /// The input holds more than 64 `%TAG` directives; the byte where the 65th starts.
    TagDirectives { max: usize, offset: usize },
    /// One document's aliases would expand past 64 MiB, or an alias points at an open anchor.
    Expansion,
    /// An anchor name is defined twice in one document; the byte of the reusing `&`.
    AnchorReuse { offset: usize },
    /// An anchor or alias name leaves `[A-Za-z0-9_-]`; the byte of its `&` or `*`.
    AnchorName { offset: usize },
    /// A raw U+0085, U+2028 or U+2029 line break; the byte where it sits.
    LineBreak { offset: usize },
    /// The text is not YAML; the line and column the parser reports.
    Syntax { line: usize, column: usize },
}

/// Where in a YAML document a refusal points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Location {
    line: usize,
    column: usize,
}

impl Location {
    /// The line of the refusal.
    pub(crate) fn line(&self) -> usize {
        self.line
    }

    /// The column of the refusal.
    pub(crate) fn column(&self) -> usize {
        self.column
    }
}

/// What serde puts between a quoted value and the type it wanted.
const EXPECTED: &str = ", expected ";

/// serde's marker before a variant name it did not recognise.
const VARIANT: &str = "unknown variant `";

/// `message` with any value serde quoted in it removed.
///
/// serde's own messages put the value between a fixed marker and the LAST
/// `, expected ` after it; a value may itself contain `, expected `, so the
/// first one is not the end of it. Every other message passes through:
/// libyaml's syntax problems are fixed strings, and the gateway's own refusals
/// name keys, never values.
pub(crate) fn redact_message(message: &str) -> String {
    // The EARLIEST marker is serde's own: a later one can only sit inside the
    // value, so choosing by marker kind first would cut at text the value
    // supplied and keep the value before it.
    let earliest = ["invalid type: ", "invalid value: ", VARIANT]
        .into_iter()
        .filter_map(|marker| message.find(marker).map(|at| (at, marker)))
        .min_by_key(|(at, _)| *at);
    let Some((start, marker)) = earliest else {
        return message.to_owned();
    };
    let from = start + marker.len();
    let tail = &message[from..];
    if marker == VARIANT {
        let rest = tail
            .rfind(EXPECTED)
            .map_or_else(|| location(tail), |cut| &tail[cut..]);
        return format!(
            "{}{}{rest}",
            &message[..start],
            VARIANT.trim_end_matches(" `")
        );
    }
    match tail.rfind(EXPECTED) {
        Some(cut) => format!(
            "{}{}{}",
            &message[..from],
            kind_word(&tail[..cut]),
            &tail[cut..]
        ),
        None => format!("{}a value{}", &message[..from], location(tail)),
    }
}

/// serde's description of a value, cut before the value: `string "x"` is
/// `string`. Only serde's own type words are kept; anything else is
/// verbatim input (serde's `Other`), so it becomes `a value`.
fn kind_word(unexpected: &str) -> &str {
    const SERDE_WORDS: [&str; 16] = [
        "boolean",
        "integer",
        "floating point",
        "character",
        "string",
        "byte array",
        "unit value",
        "Option value",
        "newtype struct",
        "sequence",
        "map",
        "enum",
        "unit variant",
        "newtype variant",
        "tuple variant",
        "struct variant",
    ];
    let word = unexpected
        .find(['"', '`', '[', '\''])
        .map_or(unexpected, |at| &unexpected[..at])
        .trim();
    SERDE_WORDS
        .into_iter()
        .find(|known| *known == word)
        .unwrap_or("a value")
}

/// The YAML parser's trailing ` at line L column C`, kept only when it is exactly
/// that, so no part of a value can ride along.
fn location(tail: &str) -> &str {
    let Some(at) = tail.rfind(" at line ") else {
        return "";
    };
    let suffix = &tail[at..];
    let mut words = suffix.split(' ').skip(1);
    let exact = matches!(
        (words.next(), words.next(), words.next(), words.next(), words.next()),
        (Some("at"), Some("line"), Some(line), Some("column"), Some(column))
            if line.bytes().all(|b| b.is_ascii_digit())
                && column.bytes().all(|b| b.is_ascii_digit())
                && !line.is_empty()
                && !column.is_empty()
    ) && words.next().is_none();
    if exact { suffix } else { "" }
}

/// Largest text the guard lets through: 16 MiB, the protocol-import limit
/// now on every path. A text of exactly this length is accepted.
const MAX_YAML_BYTES: usize = 16 * 1024 * 1024;

/// Deepest nesting the guard lets through, matching `serde_yaml`'s own cap.
const MAX_DEPTH: usize = 128;

/// Most alias references the guard lets through in one stream.
const MAX_ALIASES: usize = 64;

/// Most `%TAG` directives the guard lets through in one input.
const MAX_TAG_DIRECTIVES: usize = 64;

/// Most alias-added bytes the guard lets one document expand to.
const MAX_EXPANSION_BYTES: u64 = 64 * 1024 * 1024;

/// Cost unit of one node towards the expansion cap.
const NODE_COST: u64 = 64;

/// Refuse hostile YAML text before it reaches the backend (MIK-8639).
///
/// The checks run in order: the size gate, the raw line-break scan, the
/// scanner-token pass (directives, names, reuse, syntax) and the event pass
/// (depth, alias count, expansion, syntax). The first refusal wins, and both
/// passes are linear in the input.
fn guard(text: &str) -> Result<(), Error> {
    guard_inner(text).map(|_| ()).map_err(|(err, _)| err)
}

/// The guard result plus the number of parser events and scanner tokens visited.
///
/// Test-only work counter behind the linearity bar; absent from production builds.
#[cfg(test)]
pub(crate) fn guard_work(text: &str) -> (Result<(), Error>, u64) {
    match guard_inner(text) {
        Ok(work) => (Ok(()), work),
        Err((err, work)) => (Err(err), work),
    }
}

/// The guard plus its work count: tokens visited in the scanner pass and
/// events visited in the event pass. On refusal the count covers the work
/// done before the refusal fired.
fn guard_inner(text: &str) -> Result<u64, (Error, u64)> {
    if text.len() > MAX_YAML_BYTES {
        let refused = Error::refused(
            Limit::Size {
                len: text.len(),
                max: MAX_YAML_BYTES,
            },
            None,
        );
        return Err((refused, 0));
    }
    if let Some((offset, _)) = text
        .char_indices()
        .find(|(_, found)| is_disputed_break(*found))
    {
        let refused = Error::refused(Limit::LineBreak { offset }, None);
        return Err((refused, 0));
    }
    let mut work = 0u64;
    if let Err(err) = pass1(text, &mut work) {
        return Err((err, work));
    }
    if let Err(err) = pass2(text, &mut work) {
        return Err((err, work));
    }
    Ok(work)
}

/// Whether `found` is a line break libyaml sees and granit does not. Refusing
/// it fail-closed keeps a granit comment from hiding a libyaml directive.
fn is_disputed_break(found: char) -> bool {
    matches!(found, '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Whether an anchor or alias name sits inside the grammar both parsers read
/// the same way: one or more of `[A-Za-z0-9_-]`.
fn name_in_grammar(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// A refusal pointing at `marker`: the limit built from its byte offset, or a
/// Syntax refusal at its line and column when no byte offset was recorded.
fn at_offset(marker: Marker, make: impl FnOnce(usize) -> Limit) -> Error {
    match marker.byte_offset() {
        Some(offset) => Error::refused(make(offset), None),
        None => Error::refused(
            Limit::Syntax {
                line: marker.line(),
                column: marker.col().saturating_add(1),
            },
            Some(String::from("syntax error")),
        ),
    }
}

/// The fix hint for a quoted value left unclosed or continued with too little indentation.
const QUOTED_INDENT_HINT: &str =
    "close the quote, or indent the continuation lines, or use a block scalar (| or >)";

/// A granit failure as the guard's refusal: its recursion breach is Depth,
/// every other kind is Syntax at the marker's line and 1-based column.
fn map_scan_error(scan: &ScanError) -> Error {
    let marker = scan.marker();
    if matches!(scan.kind(), ErrorKind::RecursionLimitExceeded) {
        return Error::refused(
            Limit::Depth {
                line: marker.line(),
            },
            None,
        );
    }
    let limit = Limit::Syntax {
        line: marker.line(),
        column: marker.col().saturating_add(1),
    };
    let what = syntax_what(scan.kind());
    if matches!(scan.kind(), ErrorKind::InvalidQuotedScalarIndent) {
        return Error::refused_hint(limit, Some(what), QUOTED_INDENT_HINT);
    }
    Error::refused(limit, Some(what))
}

/// The Syntax wording for a granit kind: granit's own Display, except the nine
/// data-carrying kinds and the quoted-indent kind, which get fixed text (the
/// exact `=2.0.0` pin freezes the set). Never echoes document bytes, names
/// or tags.
fn syntax_what(kind: &ErrorKind) -> String {
    match kind {
        ErrorKind::UnexpectedCharacter { .. } => String::from("unexpected character"),
        ErrorKind::Custom(..) => String::from("syntax error"),
        ErrorKind::InputIo { .. } => String::from("input could not be read"),
        ErrorKind::InputDecoding { .. } => String::from("input could not be decoded"),
        ErrorKind::MismatchedFlowCollectionEnd { .. } => String::from("mismatched bracket"),
        ErrorKind::UnclosedFlowCollection { .. } => String::from("unclosed bracket"),
        ErrorKind::InputByteLimitExceeded { .. } => String::from("input too large"),
        ErrorKind::DirectiveByteLimitExceeded { .. }
        | ErrorKind::TooManyReservedDirectiveParams { .. } => String::from("directive too large"),
        ErrorKind::InvalidQuotedScalarIndent => {
            String::from("quoted text is not closed, or continues with too little indentation,")
        }
        other => other.to_string(),
    }
}

/// First pass: scanner tokens. Counts `%TAG` directives, checks anchor and
/// alias names against the grammar both parsers share, and refuses an anchor
/// name reused within one document. Adds the tokens visited to `work`.
fn pass1(text: &str, work: &mut u64) -> Result<(), Error> {
    let scanner = granit_parser::Scanner::new(granit_parser::StrInput::new(text));
    let mut directives = 0usize;
    let mut anchors: HashSet<String> = HashSet::new();
    for item in scanner {
        *work = work.saturating_add(1);
        let token = match item {
            Ok(token) => token,
            Err(scan) => return Err(map_scan_error(&scan)),
        };
        let start = token.span().start;
        let token_type = token.token_type();
        match &token_type {
            TokenType::TagDirective(..) => {
                directives = directives.saturating_add(1);
                if directives > MAX_TAG_DIRECTIVES {
                    return Err(at_offset(start, |offset| Limit::TagDirectives {
                        max: MAX_TAG_DIRECTIVES,
                        offset,
                    }));
                }
            }
            TokenType::Anchor(name) => {
                if !name_in_grammar(name) {
                    return Err(at_offset(start, |offset| Limit::AnchorName { offset }));
                }
                if !anchors.insert(name.to_string()) {
                    return Err(at_offset(start, |offset| Limit::AnchorReuse { offset }));
                }
            }
            TokenType::Alias(name) => {
                if !name_in_grammar(name) {
                    return Err(at_offset(start, |offset| Limit::AnchorName { offset }));
                }
            }
            TokenType::DocumentStart | TokenType::DocumentEnd => {
                anchors.clear();
            }
            _ => {}
        }
    }
    Ok(())
}

/// An open collection in the expansion walk: its cost so far and its anchor id.
struct Frame {
    cost: u64,
    anchor: usize,
}

/// Add `amount` to the innermost open collection, or to the document total
/// when no collection is open. Saturating throughout.
fn add_cost(stack: &mut [Frame], total: &mut u64, amount: u64) {
    match stack.last_mut() {
        Some(frame) => frame.cost = frame.cost.saturating_add(amount),
        None => *total = total.saturating_add(amount),
    }
}

/// The cost of one scalar towards the expansion cap: its bytes plus one node.
fn scalar_cost(value: &str) -> u64 {
    u64::try_from(value.len()).map_or(u64::MAX, |len| len.saturating_add(NODE_COST))
}

/// Second pass: parser events. Refuses nesting past 128 levels, a 65th alias
/// anywhere in the stream, and one document's aliases expanding to 64 MiB.
/// Adds the events visited to `work`.
fn pass2(text: &str, work: &mut u64) -> Result<(), Error> {
    let mut aliases = 0usize;
    let mut expanded = 0u64;
    let mut total = 0u64;
    let mut cost: HashMap<usize, u64> = HashMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    for item in granit_parser::Parser::new_from_str(text) {
        *work = work.saturating_add(1);
        let (event, span) = match item {
            Ok(pair) => pair,
            Err(scan) => return Err(map_scan_error(&scan)),
        };
        match event {
            Event::DocumentStart(..) => {
                expanded = 0;
                total = 0;
                cost.clear();
                stack.clear();
            }
            Event::SequenceStart(_, anchor, _) | Event::MappingStart(_, anchor, _) => {
                stack.push(Frame {
                    cost: NODE_COST,
                    anchor,
                });
                if stack.len() > MAX_DEPTH {
                    let line = span.start.line();
                    return Err(Error::refused(Limit::Depth { line }, None));
                }
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some(frame) = stack.pop() {
                    add_cost(&mut stack, &mut total, frame.cost);
                    if frame.anchor != 0 {
                        cost.insert(frame.anchor, frame.cost);
                    }
                }
            }
            Event::Scalar(value, _, anchor, _) => {
                let single = scalar_cost(&value);
                add_cost(&mut stack, &mut total, single);
                if anchor != 0 {
                    cost.insert(anchor, single);
                }
            }
            Event::Alias(id) => {
                aliases = aliases.saturating_add(1);
                if aliases > MAX_ALIASES {
                    return Err(Error::refused(Limit::Aliases { max: MAX_ALIASES }, None));
                }
                if id != 0 && stack.iter().any(|frame| frame.anchor == id) {
                    return Err(Error::refused(Limit::Expansion, None));
                }
                let single = cost.get(&id).copied().unwrap_or(NODE_COST);
                if expanded.saturating_add(single) >= MAX_EXPANSION_BYTES {
                    return Err(Error::refused(Limit::Expansion, None));
                }
                expanded = expanded.saturating_add(single);
                add_cost(&mut stack, &mut total, single);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse `text` into `T`. A key repeated in a struct or in a `Value` is
/// refused; a key repeated in a map keeps its last value.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    guard(text)?;
    serde_yaml::from_str(text).map_err(Error::backend)
}

/// Parse `text` as figment's `Dict`, the way the config loader reads it: a
/// repeated key keeps its last value at every level.
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    guard(text)?;
    Yaml::from_str(text).map_err(Error::backend)
}

/// The config file's data as figment's YAML provider gives it: the
/// document under its profile, or the provider's own error.
#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    guard(text).map_err(|err| figment::Error::from(err.to_string()))?;
    Yaml::string(text).data()
}

/// Write `value` as YAML.
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    serde_yaml::to_string(value).map_err(Error::backend)
}

/// Convert `value` to a YAML tree.
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    serde_yaml::to_value(value).map_err(Error::backend)
}

/// Read `T` out of a YAML tree.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_yaml::from_value(value).map_err(Error::backend)
}

/// Convert a YAML tree value to a JSON value (MIK-8425).
///
/// Null, bool and string map to themselves. An integer stays a JSON integer
/// over the full `i64` and `u64` range. A finite float stays a JSON float
/// (`1.0` stays `1.0`, not `1`); a non-finite float maps to null. A sequence
/// maps element by element. A tagged node `!t v` maps to the one-entry object
/// `{"!t": v}`, keeping the tag (with its leading `!`) as the key. A mapping
/// maps entry by entry in document order, so a later key that stringifies the
/// same overwrites an earlier one: a string key is kept, a bool key becomes
/// `"true"` or `"false"`, an integer key becomes its decimal string, a finite
/// float key becomes `serde_json`'s float text (`1.0` to `"1.0"`, `1e3` to
/// `"1000.0"`, `-0.0` to `"-0.0"`), and any other key (null, non-finite
/// float, sequence, mapping, tagged) drops its entry.
///
/// MIG.2 re-implements this function over its own tree against the
/// parser/registry tests.
pub(crate) fn to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else {
                n.as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Sequence(seq) => serde_json::Value::Array(seq.iter().map(to_json).collect()),
        Value::Tagged(tagged) => {
            let mut map = serde_json::Map::new();
            map.insert(tagged.tag.to_string(), to_json(&tagged.value));
            serde_json::Value::Object(map)
        }
        Value::Mapping(mapping) => {
            let mut map = serde_json::Map::new();
            for (key, val) in mapping {
                if let Some(key) = json_key(key) {
                    map.insert(key, to_json(val));
                }
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Stringify a YAML mapping key for `to_json`; `None` drops the entry.
fn json_key(key: &Value) -> Option<String> {
    match key {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                let f = n.as_f64()?;
                serde_json::Number::from_f64(f).map(|j| j.to_string())
            }
        }
        _ => None,
    }
}

/// Every document of a multi-document stream, in order, ending after the
/// first refusal. `serde_yaml`'s own stream can keep yielding after a
/// malformed document, so a caller that does not stop grows without bound;
/// this iterator stops for it. There is no document count cap: a long
/// manifest is read in full.
pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    let mut early = guard(text).err();
    let mut stream = serde_yaml::Deserializer::from_str(text);
    let mut refused = early.is_some();
    std::iter::from_fn(move || {
        if let Some(err) = early.take() {
            return Some(Err(err));
        }
        if refused {
            return None;
        }
        let document = stream.next()?;
        let reading = <Value as serde::Deserialize>::deserialize(document).map_err(Error::backend);
        refused = reading.is_err();
        Some(reading)
    })
}
