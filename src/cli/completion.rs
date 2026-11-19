// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shell completions from the visible CLI tree and locally loaded capability names.
//!
//! Bash and Zsh use `clap_complete` unchanged; Fish and PowerShell use the tables
//! and argument walkers here. Tool names are captured when the script is generated.
//!
//! # Installation
//!
//! ```text
//! mcp-gateway tool completions bash >> ~/.bashrc
//! mcp-gateway tool completions zsh > ~/.zsh/completions/_mcp-gateway
//! mcp-gateway tool completions fish > ~/.config/fish/completions/mcp-gateway.fish
//! ```
//!
//! In PowerShell, add this line to `$PROFILE`:
//! ```powershell
//! mcp-gateway tool completions powershell | Out-String | Invoke-Expression
//! ```

use clap::{Arg, Command, builder::PossibleValuesParser};

/// The four supported shells, in the order offered by `tool completions`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum CompletionShell {
    /// bash, by `clap_complete`.
    Bash,
    /// zsh, by `clap_complete`.
    Zsh,
    /// fish, by the generator here.
    Fish,
    /// PowerShell, by the generator here.
    Powershell,
}

/// A generated script and the values refused by `completion_safe`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Generated {
    /// The script, as `tool completions` prints it.
    pub script: String,
    /// Refused values in encounter order, reported only at generation time.
    pub left_out: Vec<String>,
}

/// Whether a value is a single inert completion word in Fish and PowerShell.
#[must_use]
pub fn completion_safe(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A visible copy of the real CLI with closed lists and the configuration file hint.
#[must_use]
pub fn completion_tree(tool_names: &[String]) -> Command {
    let root = <crate::cli::Cli as clap::CommandFactory>::command();
    visible_command(&root, "", tool_names)
}

// This CLI invocation generates one script and exits. Clap without its `string`
// feature requires static names; keep these copies for that process lifetime.
fn completion_name(value: &str) -> &'static str {
    Box::leak(value.to_owned().into_boxed_str())
}

/// A fresh copy of `source` holding only what completion reads: names, help, how it takes values, its value list
/// and hint, and the shape flags clap checks when it builds the tree. Relations (`requires`, `conflicts_with`,
/// groups) and aliases are left out: completion never uses them, and a relation may name a hidden argument this
/// copy removes. clap cannot clear a relation on a cloned argument, hence the rebuild.
fn completion_arg(source: &Arg) -> Arg {
    let mut arg = Arg::new(completion_name(source.get_id().as_str()))
        .action(source.get_action().clone())
        .value_parser(source.get_value_parser().clone())
        .value_hint(source.get_value_hint())
        .required(source.is_required_set())
        .global(source.is_global_set())
        .trailing_var_arg(source.is_trailing_var_arg_set())
        .last(source.is_last_set())
        .allow_hyphen_values(source.is_allow_hyphen_values_set());
    if let Some(long) = source.get_long() {
        arg = arg.long(completion_name(long));
    }
    if let Some(short) = source.get_short() {
        arg = arg.short(short);
    }
    if let Some(help) = source.get_help() {
        arg = arg.help(help.clone());
    }
    if let Some(range) = source.get_num_args() {
        arg = arg.num_args(range);
    }
    if let Some(names) = source.get_value_names() {
        arg = arg.value_names(names.iter().map(|name| completion_name(name.as_str())));
    }
    if let Some(index) = source.get_index() {
        arg = arg.index(index);
    }
    arg
}

fn visible_command(source: &Command, path: &str, tools: &[String]) -> Command {
    let mut command = Command::new(completion_name(source.get_name()));
    if let Some(about) = source.get_about() {
        command = command.about(about.clone());
    }
    if let Some(version) = source.get_version().filter(|_| path.is_empty()) {
        command = command.version(completion_name(version));
    }
    for arg in source.get_arguments().filter(|arg| !arg.is_hide_set()) {
        let mut arg = completion_arg(arg);
        if arg.get_long() == Some("config") {
            arg = arg.value_hint(clap::ValueHint::FilePath);
        } else if arg.get_long() == Some("log-level") {
            arg = arg.value_parser(["trace", "debug", "info", "warn", "error"]);
        } else if matches!(path, "tool invoke" | "tool inspect") && arg.get_id() == "tool" {
            arg = arg.value_parser(PossibleValuesParser::new(
                tools.iter().map(|name| completion_name(name)),
            ));
        }
        command = command.arg(arg);
    }
    for sub in source.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        command = command.subcommand(visible_command(
            sub,
            &child_path(path, sub.get_name()),
            tools,
        ));
    }
    command
}

fn child_path(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path} {name}")
    }
}

/// Generate a script, leaving refused Fish/PowerShell values out of its text.
#[must_use]
pub fn generate(shell: CompletionShell, mut tree: Command) -> Generated {
    match shell {
        CompletionShell::Bash | CompletionShell::Zsh => {
            let shell = if shell == CompletionShell::Bash {
                clap_complete::Shell::Bash
            } else {
                clap_complete::Shell::Zsh
            };
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut tree, "mcp-gateway", &mut script);
            Generated {
                script: String::from_utf8(script).expect("clap emits UTF-8"),
                left_out: Vec::new(),
            }
        }
        CompletionShell::Fish => {
            tree.build();
            generate_fish(&tree)
        }
        CompletionShell::Powershell => {
            tree.build();
            generate_powershell(&tree)
        }
    }
}

fn value_kind(arg: &Arg) -> &'static str {
    if !arg.get_action().takes_values() {
        "switch"
    } else if arg.get_num_args().is_some_and(|n| n.min_values() == 0) {
        "optional"
    } else {
        "required"
    }
}

// Help is offered as a subcommand, but its generated descendants describe help
// topics rather than another invocation of the corresponding real command.
fn visit_commands(command: &Command, path: &str, visit: &mut impl FnMut(&Command, &str)) {
    visit(command, path);
    for sub in command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
    {
        visit_commands(sub, &child_path(path, sub.get_name()), visit);
    }
}

fn value_key(arg: &Arg) -> Option<String> {
    arg.get_long()
        .map(|long| format!("--{long}"))
        .or_else(|| arg.get_index().map(|index| (index - 1).to_string()))
}

fn fish_display(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn generate_fish(tree: &Command) -> Generated {
    let mut generated = Generated::default();
    let mut table = String::from("function __fish_mcp_gateway_table\n    printf '%s\\n'");
    let mut lines = String::from("complete -c mcp-gateway -e\n");
    let mut printer = String::from(
        "function __fish_mcp_gateway_values\n    set -l values (begin\n        switch (string join ' ' -- $argv)\n",
    );
    visit_commands(tree, "", &mut |command, path| {
        fish_commands(command, path, &mut table, &mut lines);
        for arg in command.get_arguments().filter(|arg| !arg.is_hide_set()) {
            let mut values = Vec::new();
            for value in arg
                .get_possible_values()
                .iter()
                .filter(|v| !v.is_hide_set())
            {
                if completion_safe(value.get_name()) {
                    values.push(value.get_name().to_owned());
                } else {
                    generated.left_out.push(value.get_name().to_owned());
                }
            }
            fish_argument(arg, path, &values, &mut table, &mut lines);
            if let Some(key) = value_key(arg).filter(|_| !values.is_empty()) {
                let at = child_path(path, &key);
                printer.push_str(&format!(
                    "            case '{at}'\n                printf '%s\\n'"
                ));
                for value in values {
                    printer.push_str(&format!(" '{value}'"));
                }
                printer.push('\n');
            }
        }
    });
    table.push_str("\nend\n\n");
    printer.push_str(FISH_PRINTER_END);
    generated.script = format!("{table}{FISH_WALKER}{FISH_PREDICATE}{printer}{lines}");
    generated
}

fn fish_commands(command: &Command, path: &str, table: &mut String, lines: &mut String) {
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        let name = sub.get_name();
        table.push_str(&format!(" \\\n        '{path}|sub|{name}|'"));
        let at = child_path(path, "0");
        let about = fish_display(
            &sub.get_about()
                .map_or_else(String::new, ToString::to_string),
        );
        lines.push_str(&format!("complete -c mcp-gateway -f -n \"__fish_mcp_gateway_at {at}\" -a '{name}' -d '{about}'\n"));
    }
}

fn fish_argument(arg: &Arg, path: &str, values: &[String], table: &mut String, lines: &mut String) {
    let Some(key) = value_key(arg) else {
        return;
    };
    let at = child_path(path, &key);
    if let Some(long) = arg.get_long() {
        let kind = value_kind(arg);
        table.push_str(&format!(" \\\n        '{path}|flag|--{long}|{kind}'"));
        let short = arg.get_short().map_or_else(String::new, |short| {
            table.push_str(&format!(" \\\n        '{path}|short|-{short}|--{long}'"));
            format!(" -s {short}")
        });
        let help = fish_display(&arg.get_help().map_or_else(String::new, ToString::to_string));
        let condition = child_path("__fish_mcp_gateway_at", path);
        lines.push_str(&format!(
            "complete -c mcp-gateway -n \"{condition}\"{short} -l {long} -d '{help}'"
        ));
        if kind == "required" {
            lines.push_str(" -r");
        }
        if !values.is_empty() {
            lines.push_str(&format!(" -f -a '(__fish_mcp_gateway_values {at})'"));
        } else if arg.get_value_hint() == clap::ValueHint::FilePath && long == "config" {
            lines.push_str(" -F");
        }
        lines.push('\n');
    } else if !values.is_empty() {
        lines.push_str(&format!("complete -c mcp-gateway -f -n \"__fish_mcp_gateway_at {at}\" -a '(__fish_mcp_gateway_values {at})'\n"));
    }
}

const FISH_WALKER: &str = r#"function __fish_mcp_gateway_walk
    set -g __fish_mcp_gateway_path ''
    set -g __fish_mcp_gateway_waiting ''
    set -g __fish_mcp_gateway_index 0
    set -l table (__fish_mcp_gateway_table)
    set -l words (commandline -opc)
    for word in $words[2..-1]
        if test -n "$__fish_mcp_gateway_waiting"
            set -g __fish_mcp_gateway_waiting ''
            continue
        end
        set -l path "$__fish_mcp_gateway_path"
        if test $__fish_mcp_gateway_index -eq 0; and contains -- "$path|sub|$word|" $table
            set -g __fish_mcp_gateway_path (string trim -- "$path $word")
            continue
        end
        if string match -q -- '-*' "$word"
            if string match -rq '^--[^=]+=' -- "$word"
                continue
            end
            set -l option "$word"
            if test (string length -- "$word") -eq 2
                for entry in $table
                    set -l fields (string split '|' -- "$entry")
                    if test "$fields[1]" = "$path"; and test "$fields[2]" = short; and test "$fields[3]" = "$word"
                        set option "$fields[4]"
                        break
                    end
                end
            end
            if contains -- "$path|flag|$option|required" $table
                set -g __fish_mcp_gateway_waiting "$option"
            end
            continue
        end
        set -g __fish_mcp_gateway_index (math $__fish_mcp_gateway_index + 1)
    end
end

"#;

const FISH_PREDICATE: &str = r#"function __fish_mcp_gateway_at
    __fish_mcp_gateway_walk
    set -l index ''
    if test (count $argv) -gt 0; and string match -rq '^[0-9]+$' -- "$argv[-1]"
        set index "$argv[-1]"
        set -e argv[-1]
    end
    set -l path ''
    if test (count $argv) -gt 0
        set path (string join ' ' -- $argv)
    end
    test "$path" = "$__fish_mcp_gateway_path"; or return 1
    set -l word (commandline -ct)
    set -l first (string sub -l 1 -- "$word")
    if contains -- "$first" "'" '"'
        return 1
    end
    if test -n "$index"
        test -z "$__fish_mcp_gateway_waiting"; or return 1
        string match -q -- '-*' "$word"; and return 1
        test "$index" -eq $__fish_mcp_gateway_index
    else
        test -n "$__fish_mcp_gateway_waiting"; or string match -q -- '-*' "$word"
    end
end

"#;

const FISH_PRINTER_END: &str = r#"        end
    end)
    set -l prefix (commandline -ct)
    set prefix (string replace -r '^--[^=]*=' '' -- "$prefix")
    set -l length (string length -- "$prefix")
    for value in $values
        if test "$length" -eq 0; or test (string sub -l "$length" -- "$value") = "$prefix"
            printf '%s\n' "$value"
        end
    end
end

"#;

fn powershell_literal(value: &str) -> String {
    let escaped: String = value
        .chars()
        .flat_map(|c| {
            let quote = matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}');
            std::iter::once(c).chain(quote.then_some(c))
        })
        .collect();
    format!("'{escaped}'")
}

fn powershell_row(table: &mut String, fields: [&str; 5]) {
    let fields = fields.map(powershell_literal).join(", ");
    // Unary comma preserves the row as an array instead of pipeline-unrolling
    // its fields. The inner literal stays on its own line for table readers.
    table.push_str(&format!(
        "        ,@(\n            @({fields})\n        )\n"
    ));
}

fn generate_powershell(tree: &Command) -> Generated {
    let mut generated = Generated::default();
    let mut table = String::from(
        "using namespace System.Management.Automation\n\nRegister-ArgumentCompleter -Native -CommandName 'mcp-gateway' -ScriptBlock {\n    param($wordToComplete, $commandAst, $cursorPosition)\n    $table = @(\n",
    );
    visit_commands(tree, "", &mut |command, path| {
        let path = if path.is_empty() {
            "mcp-gateway".to_owned()
        } else {
            format!("mcp-gateway;{}", path.replace(' ', ";"))
        };
        for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
            let about = sub
                .get_about()
                .map_or_else(String::new, ToString::to_string);
            powershell_row(&mut table, [&path, "sub", sub.get_name(), &about, ""]);
        }
        for arg in command.get_arguments().filter(|arg| !arg.is_hide_set()) {
            powershell_argument(arg, &path, &mut table, &mut generated.left_out);
        }
    });
    table.push_str("    )\n");
    generated.script =
        format!("{table}{POWERSHELL_HELPERS}{POWERSHELL_WALKER}{POWERSHELL_RESULTS}}}\n");
    generated
}

fn powershell_argument(arg: &Arg, path: &str, table: &mut String, left_out: &mut Vec<String>) {
    let Some(key) = value_key(arg) else {
        return;
    };
    if arg.get_long().is_some() {
        let short = arg
            .get_short()
            .map_or_else(String::new, |c| format!("-{c}"));
        let help = arg.get_help().map_or_else(String::new, ToString::to_string);
        powershell_row(table, [path, "flag", &key, &short, value_kind(arg)]);
        powershell_row(table, [path, "help", &key, &help, ""]);
    }
    for value in arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
    {
        let value = value.get_name();
        if !completion_safe(value) {
            left_out.push(value.to_owned());
            continue;
        }
        let text = if value.starts_with(|c: char| c.is_ascii_digit()) {
            format!("'{value}'")
        } else {
            value.to_owned()
        };
        let kind = if arg.get_long().is_some() {
            "val"
        } else {
            "pos"
        };
        powershell_row(table, [path, kind, &key, value, &text]);
    }
}

const POWERSHELL_HELPERS: &str = r#"    function Equal-Ordinal($left, $right) {
        [string]::Equals($left, $right, [StringComparison]::Ordinal)
    }
    function Flag-At($path, $word) {
        foreach ($row in $table) {
            if ((Equal-Ordinal $row[0] $path) -and (Equal-Ordinal $row[1] 'flag')) {
                if ((Equal-Ordinal $row[2] $word) -or
                    ($word.Length -eq 2 -and (Equal-Ordinal $row[3] $word))) {
                    return ,$row
                }
            }
        }
    }
    function Help-At($path, $flag) {
        foreach ($row in $table) {
            if ((Equal-Ordinal $row[0] $path) -and (Equal-Ordinal $row[1] 'help') -and
                (Equal-Ordinal $row[2] $flag)) {
                if ($row[3].Length -gt 0) { return $row[3] }
            }
        }
        return $flag
    }
    function Offer($text, $list, $type, $tip) {
        if ($list.StartsWith($wordToComplete, [StringComparison]::Ordinal)) {
            if ([string]::IsNullOrEmpty($tip)) { $tip = $list }
            [CompletionResult]::new($text, $list, $type, $tip)
        }
    }
"#;

const POWERSHELL_WALKER: &str = r#"    $path = 'mcp-gateway'
    $waiting = ''
    $index = 0
    $start = $cursorPosition - $wordToComplete.Length
    foreach ($element in $commandAst.CommandElements | Select-Object -Skip 1) {
        if ($element.Extent.EndOffset -gt $start) { break }
        $word = $element.Extent.Text
        if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $word = $element.Value
        }
        if ($waiting.Length -gt 0) { $waiting = ''; continue }
        $subcommand = $false
        if ($index -eq 0) {
            foreach ($row in $table) {
                if ((Equal-Ordinal $row[0] $path) -and (Equal-Ordinal $row[1] 'sub') -and
                    (Equal-Ordinal $row[2] $word)) {
                    $subcommand = $true
                    break
                }
            }
        }
        if ($subcommand) { $path += ';' + $word; continue }
        if ($word.StartsWith('-', [StringComparison]::Ordinal)) {
            if ($word.StartsWith('--', [StringComparison]::Ordinal) -and $word.Contains('=')) { continue }
            $flag = Flag-At $path $word
            if ($null -ne $flag -and (Equal-Ordinal $flag[4] 'required')) { $waiting = $flag[2] }
            continue
        }
        $index++
    }
"#;

const POWERSHELL_RESULTS: &str = r#"    $attached = ''
    $option = $waiting
    if ($option.Length -eq 0 -and $wordToComplete.StartsWith('--', [StringComparison]::Ordinal)) {
        $equals = $wordToComplete.IndexOf('=')
        if ($equals -ge 0) {
            $option = $wordToComplete.Substring(0, $equals)
            $attached = $option + '='
        }
    }
    if ($option.Length -gt 0) {
        foreach ($row in $table) {
            if ((Equal-Ordinal $row[0] $path) -and (Equal-Ordinal $row[1] 'val') -and
                (Equal-Ordinal $row[2] $option)) {
                Offer ($attached + $row[4]) ($attached + $row[3]) 'ParameterValue' (Help-At $path $option)
            }
        }
        return
    }
    $flags = $wordToComplete.StartsWith('-', [StringComparison]::Ordinal)
    foreach ($row in $table) {
        if (-not (Equal-Ordinal $row[0] $path)) { continue }
        if ($flags) {
            if (Equal-Ordinal $row[1] 'flag') {
                $tip = Help-At $path $row[2]
                Offer $row[2] $row[2] 'ParameterName' $tip
                if ($row[3].Length -gt 0) { Offer $row[3] $row[3] 'ParameterName' $tip }
            }
        } elseif ($index -eq 0 -and (Equal-Ordinal $row[1] 'sub')) {
            Offer $row[2] $row[2] 'Command' $row[3]
        } elseif ((Equal-Ordinal $row[1] 'pos') -and (Equal-Ordinal $row[2] ([string]$index))) {
            Offer $row[4] $row[3] 'ParameterValue' $row[3]
        }
    }
"#;

/// Write the script, then name each refused value using Rust's escaped debug form.
///
/// # Errors
/// Returns the first stdout or stderr write error.
pub(crate) fn write_completions(
    generated: &Generated,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
) -> std::io::Result<()> {
    stdout.write_all(generated.script.as_bytes())?;
    for value in &generated.left_out {
        writeln!(stderr, "left out of the completion script: {value:?}")?;
    }
    Ok(())
}

#[cfg(tp1)]
#[cfg(test)]
#[cfg(all(
    feature = "runtime-substrate",
    feature = "config-export",
    feature = "discovery"
))]
#[path = "completion_tests.rs"]
mod completion_tests;
