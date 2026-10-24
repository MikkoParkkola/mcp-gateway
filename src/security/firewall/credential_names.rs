// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Credential families by JSON member name (MIK-8757): which key names hold a
//! credential, and which values of that name count as one. Built in, not
//! configurable; the pagination allow-list keeps continuation tokens.

/// A family of credential-named JSON members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Family {
    /// The generic API-key rule's own names (MIK-8756).
    Generic,
    PrivateKey,
    Authorization,
    Secret,
    Password,
    Token,
}

impl Family {
    /// The finding description for a member of this family.
    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Generic => "Generic API Key in key=value (object member)",
            Self::PrivateKey => "Private Key (object member)",
            Self::Authorization => "Authorization header (object member)",
            Self::Secret => "Client or shared secret (object member)",
            Self::Password => "Password (object member)",
            Self::Token => "OAuth or session token (object member)",
        }
    }
}

/// `key` split into lowercase words: at every non-alphanumeric character, at
/// a lowercase or digit followed by an uppercase letter, and before the last
/// capital of an acronym run that a lowercase letter follows (`HTTPSToken`).
fn words(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();
        let boundary = c.is_ascii_uppercase()
            && prev.is_some_and(|p| {
                p.is_ascii_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase()))
            });
        if boundary && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `key` lowercased with every non-alphanumeric character removed.
fn compact(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Words that, directly before a final `token`/`tokens`/`cursor`, name a
/// pagination or continuation key (`next_page_token`, `$skipToken`).
const PAGINATION: &[&str] = &[
    "page",
    "next",
    "prev",
    "previous",
    "continuation",
    "cursor",
    "sync",
    "resume",
    "start",
    "after",
    "before",
    "marker",
    "pagination",
    "skip",
];

fn is_pagination(w: &[String]) -> bool {
    match w {
        [one] => one == "cursor",
        [.., before, last] => {
            matches!(last.as_str(), "token" | "tokens" | "cursor")
                && PAGINATION.contains(&before.as_str())
        }
        [] => false,
    }
}

/// Word sequences a key may end with, per family, in the order they decide.
const SUFFIXES: &[(Family, &[&str])] = &[
    (Family::Generic, &["secret", "access", "key"]),
    (Family::PrivateKey, &["private", "key"]),
    (Family::PrivateKey, &["signing", "key"]),
    (Family::Authorization, &["authorization"]),
    (Family::Secret, &["client", "secret"]),
    (Family::Secret, &["api", "secret"]),
    (Family::Secret, &["shared", "secret"]),
    (Family::Secret, &["app", "secret"]),
    (Family::Secret, &["consumer", "secret"]),
    (Family::Secret, &["webhook", "secret"]),
    (Family::Secret, &["signing", "secret"]),
    (Family::Secret, &["hmac", "secret"]),
    (Family::Secret, &["jwt", "secret"]),
    (Family::Secret, &["session", "secret"]),
    (Family::Secret, &["previous", "secret"]),
    (Family::Secret, &["current", "secret"]),
    (Family::Password, &["password"]),
    (Family::Password, &["passwd"]),
    (Family::Password, &["passphrase"]),
    (Family::Token, &["token"]),
];

/// Whole-key glued spellings, compared with [`compact`].
const GLUED: &[(Family, &str)] = &[
    (Family::PrivateKey, "privatekey"),
    (Family::Secret, "clientsecret"),
    (Family::Secret, "apisecret"),
    (Family::Token, "accesstoken"),
    (Family::Token, "refreshtoken"),
    (Family::Token, "idtoken"),
    (Family::Token, "authtoken"),
];

/// The family a key names, if any (families 2-6 and family 1's new forms;
/// the caller keeps MIK-8756's own family-1 regex first).
pub(super) fn family_of(key: &str) -> Option<Family> {
    let w = words(key);
    if is_pagination(&w) {
        return None;
    }
    if w.len() == 1 && w[0] == "secret" {
        return Some(Family::Secret);
    }
    let ends = |seq: &[&str]| {
        w.len() >= seq.len()
            && w[w.len() - seq.len()..]
                .iter()
                .zip(seq)
                .all(|(a, b)| a == b)
    };
    // Family 1 by word split: camelCase vendor keys (`openaiApiKey`).
    if ends(&["api", "key"]) || ends(&["secret", "key"]) {
        return Some(Family::Generic);
    }
    if let Some((f, _)) = SUFFIXES.iter().find(|(_, seq)| ends(seq)) {
        return Some(*f);
    }
    let c = compact(key);
    GLUED.iter().find(|(_, g)| *g == c).map(|(f, _)| *f)
}

/// A whole-value placeholder: `${…}`, `{{…}}` or `%(…)s`.
fn placeholder(v: &str) -> bool {
    (v.starts_with("${") && v.ends_with('}') && v[2..v.len() - 1].find('}').is_none())
        || (v.starts_with("{{") && v.ends_with("}}") && v.len() >= 4)
        || (v.starts_with("%(") && v.ends_with(")s"))
}

/// A mask: only `*`, or only `•`.
fn mask(v: &str) -> bool {
    !v.is_empty() && (v.chars().all(|c| c == '*') || v.chars().all(|c| c == '•'))
}

const PLACEHOLDER_WORDS: &[&str] = &[
    "none", "null", "nil", "n/a", "unset", "empty", "redacted", "hidden", "masked",
];

/// Characters an opaque token may hold (Salesforce `!`, percent-encoding,
/// Telegram's `:` and `ghp_`-style `_` included).
fn token_class(v: &str) -> bool {
    v.chars().count() >= 16
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~+/=!%:-_".contains(c))
}

/// Whether `value`, already known to sit under a key of `family`, is a
/// credential of that family. `marker` is the redaction marker, never one.
pub(super) fn value_matches(family: Family, value: &str, marker: &str) -> bool {
    let v = value.trim();
    if v == marker || placeholder(v) || mask(v) {
        return false;
    }
    match family {
        Family::Generic => {
            v.chars().count() >= 20
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c))
        }
        Family::PrivateKey => v.chars().count() >= 32,
        Family::Authorization => {
            let scheme = v.split_once(char::is_whitespace).filter(|(s, rest)| {
                ["basic", "bearer", "token", "negotiate", "apikey"]
                    .contains(&s.to_ascii_lowercase().as_str())
                    && rest.trim_start().chars().count() >= 8
                    && rest
                        .trim_start()
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._~+/=:!%-".contains(c))
            });
            scheme.is_some() || token_class(v)
        }
        Family::Secret => v.chars().count() >= 16 && !stripe_intent_secret(v),
        Family::Password => {
            v.chars().count() >= 4 && !PLACEHOLDER_WORDS.contains(&v.to_ascii_lowercase().as_str())
        }
        Family::Token => token_class(v),
    }
}

/// A Stripe PaymentIntent/SetupIntent client secret, designed for the browser
/// (lead ruling 2026-10-23): `^(pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$`.
fn stripe_intent_secret(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("pi_").or_else(|| v.strip_prefix("seti_")) else {
        return false;
    };
    let Some((id, tail)) = rest.split_once("_secret_") else {
        return false;
    };
    let alnum = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric());
    alnum(id) && alnum(tail)
}
