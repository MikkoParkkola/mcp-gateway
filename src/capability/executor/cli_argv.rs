// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Build a CLI capability's argv from its pinned template and the caller's
//! validated parameters (MIK-7782).
//!
//! Strict on purpose, and deliberately not the REST substitution in
//! `params.rs`: that one re-parses substituted text that looks like JSON and
//! expands `{env.X}`, which is exactly what must never happen to argv. Here a
//! template item is exactly one argv element, a parameter value is never
//! split, never re-parsed, and can only appear where the template put it.

use serde_json::Value;

use crate::capability::definition::{CliArg, CliConfig};
use crate::error::rpc_codes::INVALID_PARAMS;
use crate::{Error, Result};

/// Most items one `each:` element may expand to.
pub(crate) const MAX_EACH_ITEMS: usize = 64;
/// Most bytes all argv elements together may hold.
pub(crate) const MAX_ARGV_BYTES: usize = 128 * 1024;

/// A fully built CLI call: nothing in it is a template any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliInvocation {
    /// The command exactly as the pinned file spells it (resolved at spawn).
    pub command: String,
    /// argv after the program name.
    pub args: Vec<String>,
    /// Bytes for the child's stdin, when the file declares `stdin`.
    pub stdin: Option<String>,
}

/// Build the invocation.
///
/// `input_schema` is the capability's `schema.input`; it is read only for a
/// property's `format: multiline`, the one opt-in for line breaks in an
/// option value.
///
/// # Errors
///
/// `Error::Config` for a template the rules forbid (a file defect, also caught
/// by the validator); a JSON-RPC invalid-params error for a parameter that is
/// missing, of the wrong type, or holds a byte its slot refuses.
pub(crate) fn build_cli_invocation(
    config: &CliConfig,
    params: &Value,
    input_schema: &Value,
) -> Result<CliInvocation> {
    let mut args = Vec::with_capacity(config.args.len());
    let mut after_end_of_options = false;
    for item in &config.args {
        match item {
            CliArg::Literal(template) => {
                args.push(render_element(
                    template,
                    params,
                    input_schema,
                    after_end_of_options,
                )?);
                if template == "--" {
                    after_end_of_options = true;
                }
            }
            CliArg::Conditional(cond) => {
                if present(params, &cond.when) {
                    args.push(render_element(
                        &cond.arg,
                        params,
                        input_schema,
                        after_end_of_options,
                    )?);
                }
            }
            CliArg::Each(each) => push_each(&mut args, each, params, input_schema)?,
            CliArg::Json(json) => {
                let rendered = render_json(&json.value, params)?.unwrap_or(Value::Null);
                let text = serde_json::to_string(&rendered)?;
                let element = format!("{}{text}", json.json);
                refuse_nul(&element, "JSON argument")?;
                args.push(element);
            }
        }
    }
    let total: usize = args.iter().map(String::len).sum();
    if total > MAX_ARGV_BYTES {
        return Err(invalid_params(format!(
            "arguments total {total} bytes, over the {MAX_ARGV_BYTES}-byte limit"
        )));
    }
    let stdin = match &config.stdin {
        Some(template) => Some(render_stdin(template, params)?),
        None => None,
    };
    Ok(CliInvocation {
        command: config.command.clone(),
        args,
        stdin,
    })
}

/// The one `{name}` placeholder in `template`, as (start, end, name).
/// `Ok(None)` when there is none.
///
/// # Errors
///
/// `Error::Config` when the template holds more than one placeholder.
fn single_placeholder(template: &str) -> Result<Option<(usize, usize, &str)>> {
    let mut found = None;
    let mut rest = 0;
    while let Some(open) = template[rest..].find('{').map(|i| i + rest) {
        let Some(close) = template[open..].find('}').map(|i| i + open) else {
            break;
        };
        let name = &template[open + 1..close];
        if is_param_name(name) {
            if found.is_some() {
                return Err(Error::Config(format!(
                    "CLI argument template '{template}' holds more than one placeholder"
                )));
            }
            found = Some((open, close + 1, name));
            rest = close + 1;
        } else {
            // Not a name (`{"q": "{query}"}`): a placeholder may start inside it.
            rest = open + 1;
        }
    }
    Ok(found)
}

fn is_param_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Render one argv element.
fn render_element(
    template: &str,
    params: &Value,
    input_schema: &Value,
    after_end_of_options: bool,
) -> Result<String> {
    let Some((start, end, name)) = single_placeholder(template)? else {
        return Ok(template.to_owned());
    };
    // A value that starts the element could start with '-' and be read as an
    // option. Only an operand after "--" may begin with a parameter; before it,
    // a value must be bound inside a literal such as "--to={to}".
    if start == 0 && !after_end_of_options {
        return Err(Error::Config(format!(
            "CLI argument template '{template}' starts with a parameter before \"--\""
        )));
    }
    let value = required_text(params, name)?;
    refuse_nul(&value, name)?;
    if value.contains(['\n', '\r']) && !is_multiline(input_schema, name) {
        return Err(invalid_params(format!(
            "parameter '{name}' must not contain a line break"
        )));
    }
    Ok(format!("{}{value}{}", &template[..start], &template[end..]))
}

fn push_each(
    args: &mut Vec<String>,
    each: &crate::capability::definition::EachArg,
    params: &Value,
    input_schema: &Value,
) -> Result<()> {
    let bound = each.arg.starts_with("--")
        && each
            .arg
            .find('=')
            .is_some_and(|eq| each.arg.find("{item}").is_some_and(|at| at > eq));
    if !bound || each.arg.matches("{item}").count() != 1 {
        return Err(Error::Config(format!(
            "each: template '{}' must be one bound '--x={{item}}' element",
            each.arg
        )));
    }
    let Some(items) = params.get(&each.each).filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let Some(items) = items.as_array() else {
        return Err(invalid_params(format!(
            "parameter '{}' must be an array",
            each.each
        )));
    };
    if items.len() > MAX_EACH_ITEMS {
        return Err(invalid_params(format!(
            "parameter '{}' has {} items, over the limit of {MAX_EACH_ITEMS}",
            each.each,
            items.len()
        )));
    }
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(invalid_params(format!(
                "parameter '{}' must hold strings",
                each.each
            )));
        };
        refuse_nul(text, &each.each)?;
        if text.contains(['\n', '\r']) && !is_multiline(input_schema, &each.each) {
            return Err(invalid_params(format!(
                "parameter '{}' must not contain a line break",
                each.each
            )));
        }
        args.push(each.arg.replacen("{item}", text, 1));
    }
    Ok(())
}

/// Walk a JSON template. A string that is exactly `"{p}"` becomes p's value
/// with its type kept; `None` (p absent) drops the key or element. A string
/// with text around one placeholder stays a string; serde escapes it.
pub(crate) fn render_json(template: &Value, params: &Value) -> Result<Option<Value>> {
    Ok(match template {
        Value::String(s) => match single_placeholder(s)? {
            Some((0, end, name)) if end == s.len() => {
                params.get(name).filter(|v| !v.is_null()).cloned()
            }
            Some((start, end, name)) => match params.get(name).filter(|v| !v.is_null()) {
                Some(value) => Some(Value::String(format!(
                    "{}{}{}",
                    &s[..start],
                    scalar_text(name, value)?,
                    &s[end..]
                ))),
                None => None,
            },
            None => Some(template.clone()),
        },
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                if let Some(rendered) = render_json(value, params)? {
                    out.insert(key.clone(), rendered);
                }
            }
            Some(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                if let Some(rendered) = render_json(item, params)? {
                    out.push(rendered);
                }
            }
            Some(Value::Array(out))
        }
        other => Some(other.clone()),
    })
}

fn render_stdin(template: &str, params: &Value) -> Result<String> {
    let Some((start, end, name)) = single_placeholder(template)? else {
        return Ok(template.to_owned());
    };
    let value = required_text(params, name)?;
    refuse_nul(&value, name)?;
    Ok(format!("{}{value}{}", &template[..start], &template[end..]))
}

fn present(params: &Value, name: &str) -> bool {
    params.get(name).is_some_and(|v| !v.is_null())
}

fn required_text(params: &Value, name: &str) -> Result<String> {
    match params.get(name).filter(|v| !v.is_null()) {
        Some(value) => scalar_text(name, value),
        None => Err(invalid_params(format!("missing parameter '{name}'"))),
    }
}

fn scalar_text(name: &str, value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(invalid_params(format!(
            "parameter '{name}' must be a string, number or boolean here"
        ))),
    }
}

fn is_multiline(input_schema: &Value, name: &str) -> bool {
    input_schema
        .pointer(&format!("/properties/{name}/format"))
        .and_then(Value::as_str)
        == Some("multiline")
}

fn refuse_nul(value: &str, name: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(invalid_params(format!(
            "parameter '{name}' must not contain a NUL byte"
        )));
    }
    Ok(())
}

fn invalid_params(message: String) -> Error {
    Error::json_rpc(INVALID_PARAMS, message)
}

#[cfg(test)]
#[path = "cli_argv_tests.rs"]
mod tests;
