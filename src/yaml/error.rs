// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The adapter's redacted error and the value-free message rewriting (MIK-8425 B3).

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
    pub(super) fn backend(err: serde_yaml::Error) -> Self {
        Self(Repr::Backend(err))
    }

    /// The guard's refusal; `what` carries the Syntax wording and nothing else.
    pub(super) fn refused(limit: Limit, what: Option<String>) -> Self {
        Self(Repr::Refused {
            limit,
            what,
            hint: None,
        })
    }

    /// The guard's refusal with a fixed fix hint for one Syntax kind.
    pub(super) fn refused_hint(limit: Limit, what: Option<String>, hint: &'static str) -> Self {
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
