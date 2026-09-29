// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! AX-010: Tool Poisoning Detection
//!
//! Detects "tool poisoning attacks" where malicious MCP tool descriptions embed
//! hidden instructions that an LLM follows as if they came from the user.
//!
//! Reference: Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks"
//! <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
//!
//! The rule scans every text field an agent may read during tool selection:
//!   * the top-level tool `description`
//!   * every input-property `description` (e.g. `tools[N].parameters.foo.description`)
//!
//! High-severity patterns cause a `Fail` (reject). Medium-severity patterns cause
//! a `Warn`. Every finding records the exact field path and the matched pattern so
//! that `ValidationResult::issues` can be surfaced to the operator.
//!
//! Field paths use the convention `tools[<name>].description` and
//! `tools[<name>].parameters.<prop>.description` so they line up with how the
//! gateway refers to tool definitions elsewhere.

use super::super::{Severity, ValidationResult};
use super::Rule;
use crate::Result;
use crate::protocol::Tool;
use regex::Regex;
use std::sync::OnceLock;

/// Maximum number of consecutive ASCII spaces allowed before we flag the
/// description as suspiciously padded (used to hide payloads behind the Cursor
/// UI's hidden scrollbar).
const MAX_CONSECUTIVE_SPACES: usize = 40;

/// Descriptions longer than this are flagged as suspiciously verbose. The
/// Invariant Labs poisoned-tool sample wraps a long instruction block in
/// <IMPORTANT> tags; real production tool docs rarely exceed ~1.5K chars.
const MAX_DESCRIPTION_CHARS: usize = 2000;

/// High-severity pattern category.
#[derive(Debug, Clone, Copy)]
enum HighCategory {
    FilesystemPath,
    InstructionEmbed,
    Exfiltration,
}

impl HighCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::FilesystemPath => "filesystem-path",
            Self::InstructionEmbed => "instruction-embed",
            Self::Exfiltration => "exfiltration",
        }
    }
}

/// Medium-severity pattern category.
#[derive(Debug, Clone, Copy)]
enum MediumCategory {
    WhitespacePadding,
    UnicodeControl,
    Oversized,
    InstructionHint,
}

impl MediumCategory {
    const fn label(self) -> &'static str {
        match self {
            Self::WhitespacePadding => "whitespace-padding",
            Self::UnicodeControl => "unicode-control",
            Self::Oversized => "oversized-description",
            Self::InstructionHint => "instruction-hint",
        }
    }
}

/// High-severity literal patterns. Matched case-insensitively as plain
/// substrings against the lowercased description.
const HIGH_LITERAL_PATTERNS: &[(&str, HighCategory)] = &[
    // Filesystem paths / secret locations
    ("~/.ssh", HighCategory::FilesystemPath),
    ("~/.aws", HighCategory::FilesystemPath),
    ("~/.cursor", HighCategory::FilesystemPath),
    ("id_rsa", HighCategory::FilesystemPath),
    ("id_ed25519", HighCategory::FilesystemPath),
    (".env", HighCategory::FilesystemPath),
    ("/etc/passwd", HighCategory::FilesystemPath),
    ("/etc/shadow", HighCategory::FilesystemPath),
    // Instruction-embedding markers
    ("<important>", HighCategory::InstructionEmbed),
    ("</important>", HighCategory::InstructionEmbed),
    ("very very important", HighCategory::InstructionEmbed),
    ("do not mention", HighCategory::InstructionEmbed),
    ("do not tell", HighCategory::InstructionEmbed),
    (
        "before using this tool, read",
        HighCategory::InstructionEmbed,
    ),
    ("sidenote", HighCategory::InstructionEmbed),
    ("side note", HighCategory::InstructionEmbed),
    // Exfiltration markers
    ("upload to", HighCategory::Exfiltration),
    ("send to http", HighCategory::Exfiltration),
];

/// Medium-severity literal patterns: worth a look, not worth withholding.
const MEDIUM_LITERAL_PATTERNS: &[(&str, MediumCategory)] =
    &[("before calling this tool", MediumCategory::InstructionHint)];

/// "Before calling this tool, read/copy/…": the directive shape blocks. The
/// bare phrase is ordinary usage guidance in vendor servers ("before calling
/// this tool, gather the time range") and is a MEDIUM hint (#2356).
fn before_tool_directive_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\bbefore\s+(calling|using)\s+this\s+tool[\s,:;.]+(?:\w+\s+)?(read|include|copy|load|cat|fetch|open)\b",
        )
        .expect("before_tool_directive_re must be a valid regex")
    })
}

/// Return a compiled regex for `curl .* http` style exfiltration commands.
fn curl_http_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bcurl\b[^\n]{0,200}?https?://")
            .expect("curl_http_re must be a valid regex")
    })
}

/// Return a compiled regex for bare `passwd`/`shadow` words (file references),
/// to avoid false-positive matches inside words like `encompasses`.
fn passwd_shadow_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(passwd|shadow)\b").expect("passwd_shadow_re must be a valid regex")
    })
}

/// Return a compiled regex for `base64` next to a verb that moves data.
/// Bare `base64` passes, as do format notes like "decodes base64 input" or
/// "encoded as base64". Known limit: an instruction to encode context into an
/// argument without a movement verb is not caught here.
fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Flag base64 only next to a verb that moves data (send/upload/post/
        // exfil) within ~20 chars. "Encoded as base64" names a format, not a
        // destination, so encode* is not in the set (#2356).
        Regex::new(r"(?i)\b(send|sent|upload|uploaded|post|posted|exfiltrat\w*)[^\n]{0,20}\bbase64\b|\bbase64\b[^\n]{0,20}\b(send|sent|upload|uploaded|post|posted|exfiltrat\w*)\b")
            .expect("base64_re must be a valid regex")
    })
}

/// A finding produced by scanning a single text field.
#[derive(Debug, Clone)]
struct Finding {
    severity: Severity,
    category: &'static str,
    pattern: String,
    field_path: String,
}

/// AX-010: Tool Poisoning Detection
///
/// Scans tool and parameter descriptions for patterns associated with
/// prompt-injection-based tool poisoning attacks.
pub struct ToolPoisoningRule;

#[allow(clippy::unnecessary_literal_bound)]
impl Rule for ToolPoisoningRule {
    fn code(&self) -> &str {
        "AX-010"
    }

    fn name(&self) -> &str {
        "Tool Poisoning Detection"
    }

    fn description(&self) -> &str {
        "Detects prompt-injection payloads hidden in tool or parameter descriptions"
    }

    fn check(&self, tool: &Tool) -> Result<ValidationResult> {
        let mut result = ValidationResult::new(self.code(), self.name(), &tool.name);
        let mut findings: Vec<Finding> = Vec::new();

        // 1. Top-level tool description.
        if let Some(desc) = tool.description.as_deref() {
            let field = format!("tools[{}].description", tool.name);
            scan_text(desc, &field, &mut findings);
        }

        // 2. Per-parameter descriptions.
        if let Some(props) = tool
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object())
        {
            for (prop_name, prop) in props {
                if let Some(desc) = prop.get("description").and_then(|d| d.as_str()) {
                    let field =
                        format!("tools[{}].parameters.{}.description", tool.name, prop_name);
                    scan_text(desc, &field, &mut findings);
                }
            }
        }

        // Aggregate findings into the validation result.
        let mut has_high = false;
        let mut has_medium = false;

        for finding in &findings {
            match finding.severity {
                Severity::Fail => has_high = true,
                Severity::Warn => has_medium = true,
                _ => {}
            }
            result.add_issue(format!(
                "[{}] {}: matched {:?} in {}",
                match finding.severity {
                    Severity::Fail => "HIGH",
                    Severity::Warn => "MEDIUM",
                    _ => "INFO",
                },
                finding.category,
                finding.pattern,
                finding.field_path
            ));
        }

        if has_high {
            result.add_suggestion(
                "Remove the flagged payload. Tool descriptions are read by the agent and \
                 any hidden instructions are executed as if the user sent them.",
            );
        } else if has_medium {
            result.add_suggestion(
                "Review the flagged description. Unusual whitespace, control characters, \
                 or oversized descriptions are common obfuscation techniques, and an \
                 instruction-like hint can steer the agent.",
            );
        }

        let (score, severity) = if has_high {
            (0.0, Severity::Fail)
        } else if has_medium {
            (0.5, Severity::Warn)
        } else {
            (1.0, Severity::Pass)
        };

        result.passed = !has_high && !has_medium;
        Ok(result.with_score(score).with_severity(severity))
    }
}

/// Scan a single text field and push any matches into `findings`.
fn scan_text(text: &str, field_path: &str, findings: &mut Vec<Finding>) {
    let lower = text.to_lowercase();

    // --- HIGH: literal substring patterns ---
    for (pat, category) in HIGH_LITERAL_PATTERNS {
        if lower.contains(pat) {
            findings.push(Finding {
                severity: Severity::Fail,
                category: category.label(),
                pattern: (*pat).to_string(),
                field_path: field_path.to_string(),
            });
        }
    }

    // --- HIGH: passwd/shadow as standalone words ---
    if passwd_shadow_re().is_match(text) {
        findings.push(Finding {
            severity: Severity::Fail,
            category: HighCategory::FilesystemPath.label(),
            pattern: "passwd/shadow".to_string(),
            field_path: field_path.to_string(),
        });
    }

    // --- HIGH: "before calling this tool, <read-like verb>" ---
    if before_tool_directive_re().is_match(text) {
        findings.push(Finding {
            severity: Severity::Fail,
            category: HighCategory::InstructionEmbed.label(),
            pattern: "before calling this tool, <read|include|copy|load|cat|fetch|open>"
                .to_string(),
            field_path: field_path.to_string(),
        });
    }

    // --- HIGH: curl + http(s) exfiltration ---
    if curl_http_re().is_match(text) {
        findings.push(Finding {
            severity: Severity::Fail,
            category: HighCategory::Exfiltration.label(),
            pattern: "curl .* http(s)://".to_string(),
            field_path: field_path.to_string(),
        });
    }

    // --- HIGH: base64 in exfiltration context ---
    if base64_re().is_match(text) {
        findings.push(Finding {
            severity: Severity::Fail,
            category: HighCategory::Exfiltration.label(),
            pattern: "base64 (exfil context)".to_string(),
            field_path: field_path.to_string(),
        });
    }

    // --- MEDIUM: literal hints ---
    for (pat, category) in MEDIUM_LITERAL_PATTERNS {
        if lower.contains(pat) {
            findings.push(Finding {
                severity: Severity::Warn,
                category: category.label(),
                pattern: (*pat).to_string(),
                field_path: field_path.to_string(),
            });
        }
    }

    // --- MEDIUM: whitespace padding ---
    if has_long_space_run(text, MAX_CONSECUTIVE_SPACES) {
        findings.push(Finding {
            severity: Severity::Warn,
            category: MediumCategory::WhitespacePadding.label(),
            pattern: format!("> {MAX_CONSECUTIVE_SPACES} consecutive spaces"),
            field_path: field_path.to_string(),
        });
    }

    // --- MEDIUM: unicode control characters ---
    if let Some(ch) = find_suspicious_control(text) {
        findings.push(Finding {
            severity: Severity::Warn,
            category: MediumCategory::UnicodeControl.label(),
            pattern: format!("U+{:04X}", ch as u32),
            field_path: field_path.to_string(),
        });
    }

    // --- MEDIUM: oversized ---
    if text.chars().count() > MAX_DESCRIPTION_CHARS {
        findings.push(Finding {
            severity: Severity::Warn,
            category: MediumCategory::Oversized.label(),
            pattern: format!("> {MAX_DESCRIPTION_CHARS} chars"),
            field_path: field_path.to_string(),
        });
    }
}

/// Return true if `text` contains `threshold` or more consecutive ASCII spaces.
fn has_long_space_run(text: &str, threshold: usize) -> bool {
    let mut run = 0usize;
    for b in text.bytes() {
        if b == b' ' {
            run += 1;
            if run >= threshold {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Return the first suspicious Unicode control character found, if any.
///
/// We flag:
///   * U+202E RIGHT-TO-LEFT OVERRIDE (and friends U+202A..U+202E, U+2066..U+2069)
///   * U+200B..U+200D zero-width space / joiners
///   * U+FEFF byte-order-mark / zero-width no-break space
///
/// Regular whitespace (tab, CR, LF) and ordinary Unicode letters used by
/// non-English languages are NOT flagged, so legitimate localized descriptions
/// pass cleanly.
fn find_suspicious_control(text: &str) -> Option<char> {
    for ch in text.chars() {
        let cp = ch as u32;
        let bidi_override = (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp);
        let zero_width = (0x200B..=0x200D).contains(&cp) || cp == 0xFEFF;
        if bidi_override || zero_width {
            return Some(ch);
        }
    }
    None
}

#[cfg(test)]
#[path = "tool_poisoning_tests.rs"]
mod tests;
