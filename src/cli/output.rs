//! Terminal output formatting for CLI tool results.
//!
//! Supports three modes:
//! - `json` — raw JSON, pipe-friendly
//! - `table` — aligned columns for human scanning
//! - `plain` — minimal text for scripting

use serde_json::Value;

/// Output format selection for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Compact, machine-readable JSON
    Json,
    /// Human-readable table with aligned columns
    #[default]
    Table,
    /// Minimal plain text, one value per line
    Plain,
}

/// Render a tool invocation result to stdout.
///
/// # Examples
///
/// ```rust
/// use mcp_gateway::cli::output::{OutputFormat, print_tool_result};
/// use serde_json::json;
///
/// let v = json!({"temperature": 22, "unit": "celsius"});
/// print_tool_result(&v, OutputFormat::Plain);
/// ```
pub fn print_tool_result(value: &Value, format: OutputFormat) {
    match format {
        OutputFormat::Json => print_json(value),
        OutputFormat::Table => print_table(value),
        OutputFormat::Plain => print_plain(value),
    }
}

/// Render a list of tool entries (name + description) to stdout.
pub fn print_tool_list(tools: &[(String, String, bool)], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let arr: Vec<_> = tools
                .iter()
                .map(|(name, desc, req_key)| {
                    serde_json::json!({
                        "name": name,
                        "description": desc,
                        "requires_key": req_key
                    })
                })
                .collect();
            print_json(&Value::Array(arr));
        }
        OutputFormat::Plain => {
            for (name, _desc, _req_key) in tools {
                println!("{name}");
            }
        }
        OutputFormat::Table => {
            if tools.is_empty() {
                println!("No tools available.");
                return;
            }
            let name_width = tools.iter().map(|(n, _, _)| n.len()).max().unwrap_or(4).max(4);
            let auth_col = "AUTH";
            println!(
                "{:<width$}  {:<4}  DESCRIPTION",
                "NAME",
                auth_col,
                width = name_width
            );
            println!("{}", "-".repeat(name_width + 4 + 12 + 40));
            for (name, desc, req_key) in tools {
                let auth = if *req_key { "yes" } else { "no" };
                let truncated = truncate_str(desc, 60);
                println!("{name:<name_width$}  {auth:<4}  {truncated}");
            }
        }
    }
}

/// Render a single tool's schema details.
pub fn print_tool_inspect(name: &str, description: &str, schema: &Value, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            let v = serde_json::json!({
                "name": name,
                "description": description,
                "schema": schema
            });
            print_json(&v);
        }
        OutputFormat::Plain | OutputFormat::Table => {
            println!("Name:        {name}");
            println!("Description: {description}");
            println!("Schema:");
            println!(
                "{}",
                serde_json::to_string_pretty(schema).unwrap_or_default()
            );
        }
    }
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn print_json(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
}

fn print_plain(value: &Value) {
    match value {
        Value::String(s) => println!("{s}"),
        Value::Array(arr) => {
            for item in arr {
                print_plain(item);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::String(s) => println!("{k}: {s}"),
                    Value::Number(n) => println!("{k}: {n}"),
                    Value::Bool(b) => println!("{k}: {b}"),
                    Value::Null => println!("{k}: null"),
                    _ => println!("{k}: {}", serde_json::to_string(v).unwrap_or_default()),
                }
            }
        }
        Value::Number(n) => println!("{n}"),
        Value::Bool(b) => println!("{b}"),
        Value::Null => println!("null"),
    }
}

fn print_table(value: &Value) {
    match value {
        Value::Object(map) => {
            let key_width = map.keys().map(String::len).max().unwrap_or(3).max(3);
            for (k, v) in map {
                let display = value_to_display(v);
                println!("{k:<key_width$}  {display}");
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                println!("(empty)");
                return;
            }
            // If array of objects: render as table with columns
            if let Some(Value::Object(first)) = arr.first() {
                let keys: Vec<&str> = first.keys().map(String::as_str).collect();
                let col_widths = column_widths(arr, &keys);
                print_header(&keys, &col_widths);
                for row in arr {
                    if let Value::Object(obj) = row {
                        print_row(obj, &keys, &col_widths);
                    }
                }
            } else {
                for item in arr {
                    print_plain(item);
                }
            }
        }
        _ => print_plain(value),
    }
}

fn value_to_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

fn column_widths(
    rows: &[Value],
    keys: &[&str],
) -> Vec<usize> {
    keys.iter()
        .map(|key| {
            let header_len = key.len();
            let max_val = rows
                .iter()
                .filter_map(|r| r.as_object())
                .map(|obj| value_to_display(obj.get(*key).unwrap_or(&Value::Null)).len())
                .max()
                .unwrap_or(0);
            header_len.max(max_val)
        })
        .collect()
}

fn print_header(keys: &[&str], widths: &[usize]) {
    let header: Vec<String> = keys
        .iter()
        .zip(widths)
        .map(|(k, w)| format!("{:<width$}", k.to_uppercase(), width = w))
        .collect();
    println!("{}", header.join("  "));
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("  "));
}

fn print_row(obj: &serde_json::Map<String, Value>, keys: &[&str], widths: &[usize]) {
    let cols: Vec<String> = keys
        .iter()
        .zip(widths)
        .map(|(k, w)| {
            let val = value_to_display(obj.get(*k).unwrap_or(&Value::Null));
            format!("{:<width$}", truncate_str(&val, *w), width = w)
        })
        .collect();
    println!("{}", cols.join("  "));
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_default_is_table() {
        assert_eq!(OutputFormat::default(), OutputFormat::Table);
    }

    #[test]
    fn truncate_str_short_string_unchanged() {
        // GIVEN: a string shorter than max
        // WHEN: truncating
        // THEN: returned unchanged
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact_length_unchanged() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long_string_truncated_with_ellipsis() {
        // GIVEN: string longer than max
        let result = truncate_str("hello world", 8);
        // THEN: ends with "..." and total length <= max
        assert!(result.ends_with("..."));
        assert!(result.len() <= 8);
    }

    #[test]
    fn value_to_display_converts_all_scalars() {
        assert_eq!(value_to_display(&Value::String("hi".into())), "hi");
        assert_eq!(
            value_to_display(&serde_json::json!(42)),
            "42"
        );
        assert_eq!(value_to_display(&Value::Bool(true)), "true");
        assert_eq!(value_to_display(&Value::Null), "null");
    }

    #[test]
    fn column_widths_uses_max_of_header_and_values() {
        let rows = vec![
            serde_json::json!({"name": "a_very_long_name", "val": "1"}),
            serde_json::json!({"name": "b", "val": "2222"}),
        ];
        let keys = ["name", "val"];
        let widths = column_widths(&rows, &keys);
        assert_eq!(widths[0], "a_very_long_name".len());
        assert_eq!(widths[1], "2222".len());
    }

    #[test]
    fn print_tool_list_empty_shows_message_in_table_mode() {
        // GIVEN / WHEN: called with empty list
        // THEN: does not panic
        print_tool_list(&[], OutputFormat::Table);
    }

    #[test]
    fn print_tool_result_json_does_not_panic() {
        let v = serde_json::json!({"key": "value", "num": 42});
        // THEN: all formats work without panic
        print_tool_result(&v, OutputFormat::Json);
        print_tool_result(&v, OutputFormat::Table);
        print_tool_result(&v, OutputFormat::Plain);
    }

    #[test]
    fn print_tool_result_array_plain() {
        let v = serde_json::json!(["a", "b", "c"]);
        print_tool_result(&v, OutputFormat::Plain);
    }

    #[test]
    fn print_tool_result_nested_array_table() {
        let v = serde_json::json!([
            {"name": "tool_a", "score": 1},
            {"name": "tool_b", "score": 2}
        ]);
        print_tool_result(&v, OutputFormat::Table);
    }
}
