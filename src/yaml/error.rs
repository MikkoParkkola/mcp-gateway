// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The adapter's redacted error and the value-free message rewriting (MIK-8425 B3).

/// The adapter's YAML error; its text never carries the value that caused it
/// (MIK-8425 B3, CWE-532), keeps the key path, expected type and line/column.
pub(crate) struct Error(Repr);

/// What an adapter error carries: the backend's own failure, the guard's
/// refusal (MIK-8639), or the replacement backend's own message (MIK-8425
/// MIG.2). All print value-free.
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
    /// The replacement backend's refusal: a fixed wording or a serde
    /// message, and where it points. Printed through `redact_message`, as
    /// `Backend` is.
    Message {
        text: String,
        location: Option<Location>,
        /// Still to learn its place: a serde `custom` message gets the node's
        /// key path and position from the deserializer that sees it, once,
        /// as the replaced backend's `fix_mark` did.
        fixable: bool,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Repr::Backend(err) => f.write_str(&redact_message(&err.to_string())),
            Repr::Message { .. } => f.write_str(&self.message_text()),
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
            Repr::Message { .. } => f.debug_tuple("Error").field(&self.message_text()).finish(),
        }
    }
}

// No `source()`: a chain printer must not reach serde_yaml's unredacted text.
impl std::error::Error for Error {}

impl serde::de::Error for Error {
    /// A serde message, placed by the deserializer that sees it and printed
    /// through `redact_message`, so a quoted value never shows.
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self(Repr::Message {
            text: msg.to_string(),
            location: None,
            fixable: true,
        })
    }
}

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
            Repr::Message { location, .. } => *location,
        }
    }

    /// Why the guard refused the text, when it did.
    pub(crate) fn limit(&self) -> Option<&Limit> {
        match &self.0 {
            Repr::Backend(_) | Repr::Message { .. } => None,
            Repr::Refused { limit, .. } => Some(limit),
        }
    }

    /// The backend's own failure.
    pub(super) fn backend(err: serde_yaml::Error) -> Self {
        Self(Repr::Backend(err))
    }

    /// The replacement backend's own refusal, with no position.
    pub(super) fn message(text: impl Into<String>) -> Self {
        Self(Repr::Message {
            text: text.into(),
            location: None,
            fixable: false,
        })
    }

    /// The replacement backend's own refusal at `line`, `column` (1-based).
    pub(super) fn message_at(text: impl Into<String>, line: usize, column: usize) -> Self {
        Self(Repr::Message {
            text: text.into(),
            location: Some(Location { line, column }),
            fixable: false,
        })
    }

    /// Give a serde message its place, the first time one is offered: the
    /// key path (`.` is the root, printed as nothing) and the node's line
    /// and column. Any other error passes through unchanged.
    pub(super) fn fix_place(mut self, line: usize, column: usize, path: &str) -> Self {
        if let Repr::Message {
            text,
            location,
            fixable,
        } = &mut self.0
            && *fixable
        {
            if path != "." {
                *text = format!("{path}: {text}");
            }
            *location = Some(Location { line, column });
            *fixable = false;
        }
        self
    }

    /// A `Message`'s text as printed: `text at line L column C` when it has
    /// a place, as the replaced backend wrote it, with any value redacted.
    fn message_text(&self) -> String {
        let Repr::Message { text, location, .. } = &self.0 else {
            return String::new();
        };
        // The replaced backend left out a place at the very start.
        let full = match location {
            Some(at) if (at.line, at.column) != (1, 1) => {
                format!("{text} at line {} column {}", at.line, at.column)
            }
            _ => text.clone(),
        };
        redact_message(&full)
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

#[cfg(test)]
mod tests {
    use super::{Error, Location};

    /// The replacement backend's message prints as the replaced backend's
    /// did, place included, and neither `Display` nor `Debug` carries the
    /// value a serde message quotes (B3).
    #[test]
    fn a_backend_message_prints_its_place_and_never_the_value() {
        let error = Error::message_at(
            "port: invalid type: string \"MIK8425-SENTINEL-7f3a\", expected u16",
            3,
            7,
        );
        let shown = error.to_string();
        let debug = format!("{error:?}");
        assert!(shown.ends_with(" at line 3 column 7"), "{shown}");
        assert!(shown.starts_with("port: invalid type: "), "{shown}");
        assert!(!shown.contains("SENTINEL") && !debug.contains("SENTINEL"));
        assert_eq!(error.location(), Some(Location { line: 3, column: 7 }));
        assert_eq!(error.limit(), None);
        let start = Error::message_at("duplicate entry with key \"a\"", 1, 1);
        assert_eq!(start.to_string(), "duplicate entry with key \"a\"");
        assert_eq!(start.location(), Some(Location { line: 1, column: 1 }));
        let bare = Error::message("repetition limit exceeded");
        assert_eq!(bare.to_string(), "repetition limit exceeded");
        assert_eq!(bare.location(), None);
    }

    /// A serde message learns its key path and place once, from the first
    /// node that sees it; a fixed wording never takes one.
    #[test]
    fn a_serde_message_is_placed_once() {
        let error = <Error as serde::de::Error>::custom("invalid type: map, expected a string")
            .fix_place(1, 4, "v")
            .fix_place(9, 9, "outer");
        assert_eq!(
            error.to_string(),
            "v: invalid type: map, expected a string at line 1 column 4"
        );
        let root = <Error as serde::de::Error>::custom("duplicate field `a`").fix_place(1, 1, ".");
        assert_eq!(root.to_string(), "duplicate field `a`");
        let fixed = Error::message("repetition limit exceeded").fix_place(2, 2, "x");
        assert_eq!(fixed.to_string(), "repetition limit exceeded");
        assert_eq!(fixed.location(), None);
    }
}
