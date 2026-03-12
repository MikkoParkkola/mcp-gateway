//! Shell completion script generation for the `mcp-gateway` CLI.
// String-building from iterators via format! is the clearest approach here.
#![allow(clippy::format_collect_string_iterator)]
//!
//! Generates tab-completion scripts for bash, zsh, and fish from the static
//! command structure and the live capability registry.
//!
//! # Usage
//!
//! ```bash
//! # Install zsh completions
//! mcp-gateway tool completions zsh > ~/.zsh/completions/_mcp-gateway
//!
//! # Install bash completions
//! mcp-gateway tool completions bash >> ~/.bashrc
//!
//! # Install fish completions
//! mcp-gateway tool completions fish > ~/.config/fish/completions/mcp-gateway.fish
//! ```

use clap_complete::Shell;

/// Static subcommands exposed by `mcp-gateway tool`.
const TOOL_SUBCOMMANDS: &[(&str, &str)] = &[
    ("invoke", "Call a tool by name with JSON arguments"),
    ("list", "List all available tools from the capability registry"),
    ("inspect", "Show the input schema for a specific tool"),
    ("completions", "Generate shell completion scripts"),
];

/// Static top-level subcommands.
const TOP_COMMANDS: &[(&str, &str)] = &[
    ("serve", "Start the gateway server"),
    ("cap", "Capability management commands"),
    ("tls", "Certificate lifecycle management"),
    ("init", "Create a new gateway configuration file"),
    ("stats", "Show invocation counts and token savings"),
    ("validate", "Validate capability definitions"),
    ("tool", "Invoke gateway tools directly from the CLI"),
];

/// Generate a completion script for the requested shell.
///
/// `tool_names` are the capability names discovered at runtime; they are
/// injected into the completion as valid values for the `invoke` and
/// `inspect` subcommands.
///
/// # Examples
///
/// ```rust
/// use mcp_gateway::cli::completion::{generate_completion, ShellTarget};
///
/// let script = generate_completion(ShellTarget::Zsh, &["weather_current".to_string()]);
/// assert!(script.contains("_mcp_gateway"));
/// ```
pub fn generate_completion(shell: ShellTarget, tool_names: &[String]) -> String {
    match shell {
        ShellTarget::Bash => generate_bash(tool_names),
        ShellTarget::Zsh => generate_zsh(tool_names),
        ShellTarget::Fish => generate_fish(tool_names),
    }
}

/// Target shell for completion generation.
///
/// Maps from the clap [`Shell`] enum for ergonomic use in tests without
/// requiring `clap_complete` in test code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTarget {
    /// Bourne-again shell (bash)
    Bash,
    /// Z shell (zsh)
    Zsh,
    /// Friendly interactive shell (fish)
    Fish,
}

impl ShellTarget {
    /// Convert from the [`clap_complete`] `Shell` enum.
    #[must_use]
    pub fn from_shell(s: Shell) -> Option<Self> {
        match s {
            Shell::Bash => Some(Self::Bash),
            Shell::Zsh => Some(Self::Zsh),
            Shell::Fish => Some(Self::Fish),
            _ => None,
        }
    }
}

// ── bash ──────────────────────────────────────────────────────────────────────

fn generate_bash(tool_names: &[String]) -> String {
    let tools_list = tool_names.join(" ");
    let top_cmds: String = TOP_COMMANDS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(" ");
    let tool_subcmds: String = TOOL_SUBCOMMANDS
        .iter()
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        r#"# mcp-gateway bash completion
# Source this file or add to ~/.bashrc

_mcp_gateway_completions() {{
    local cur prev words cword
    _init_completion || return

    local top_commands="{top_cmds}"
    local tool_names="{tools_list}"
    local tool_subcommands="{tool_subcmds}"

    case "${{words[1]}}" in
        tool)
            case "${{words[2]}}" in
                invoke|inspect)
                    COMPREPLY=($(compgen -W "$tool_names" -- "$cur"))
                    return
                    ;;
                completions)
                    COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
                    return
                    ;;
                *)
                    COMPREPLY=($(compgen -W "$tool_subcommands" -- "$cur"))
                    return
                    ;;
            esac
            ;;
        cap)
            COMPREPLY=($(compgen -W "validate list import test discover install search registry-list" -- "$cur"))
            return
            ;;
        tls)
            COMPREPLY=($(compgen -W "init-ca issue-server issue-client" -- "$cur"))
            return
            ;;
        *)
            COMPREPLY=($(compgen -W "$top_commands" -- "$cur"))
            ;;
    esac
}}

complete -F _mcp_gateway_completions mcp-gateway
"#
    )
}

// ── zsh ───────────────────────────────────────────────────────────────────────

fn generate_zsh(tool_names: &[String]) -> String {
    let tool_entries: String = tool_names
        .iter()
        .map(|n| format!("        '{n}' \\\n"))
        .collect();

    let top_desc: String = TOP_COMMANDS
        .iter()
        .map(|(n, d)| format!("        '{n}:{d}' \\\n"))
        .collect();

    let tool_sub_desc: String = TOOL_SUBCOMMANDS
        .iter()
        .map(|(n, d)| format!("        '{n}:{d}' \\\n"))
        .collect();

    format!(
        r"#compdef mcp-gateway
# mcp-gateway zsh completion
# Place in a directory in $fpath (e.g. ~/.zsh/completions/_mcp-gateway)

_mcp_gateway() {{
    local context state line
    typeset -A opt_args

    _arguments \
        '(-c --config)'{{-c,--config}}'[Path to configuration file]:file:_files' \
        '(-p --port)'{{-p,--port}}'[Port to listen on]:port:' \
        '--host[Host to bind to]:host:' \
        '--log-level[Log level (trace|debug|info|warn|error)]:level:(trace debug info warn error)' \
        '--log-format[Log format (text|json)]:format:(text json)' \
        '--no-meta-mcp[Disable Meta-MCP mode]' \
        '1:command:->command' \
        '*::args:->args'

    case $state in
        command)
            local -a commands
            commands=(
{top_desc}            )
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                tool)
                    _mcp_gateway_tool
                    ;;
                cap)
                    _mcp_gateway_cap
                    ;;
                tls)
                    _mcp_gateway_tls
                    ;;
            esac
            ;;
    esac
}}

_mcp_gateway_tool() {{
    local state
    _arguments '1:subcommand:->sub' '*::args:->args'
    case $state in
        sub)
            local -a subs
            subs=(
{tool_sub_desc}            )
            _describe 'tool subcommand' subs
            ;;
        args)
            case $words[1] in
                invoke|inspect)
                    local -a tools
                    tools=(
{tool_entries}                    )
                    _describe 'tool name' tools
                    ;;
                completions)
                    _arguments '1:shell:(bash zsh fish)'
                    ;;
            esac
            ;;
    esac
}}

_mcp_gateway_cap() {{
    _arguments '1:subcommand:(validate list import test discover install search registry-list)'
}}

_mcp_gateway_tls() {{
    _arguments '1:subcommand:(init-ca issue-server issue-client)'
}}

_mcp_gateway
"
    )
}

// ── fish ──────────────────────────────────────────────────────────────────────

fn generate_fish(tool_names: &[String]) -> String {
    let tool_completions: String = tool_names
        .iter()
        .map(|n| {
            format!(
                "complete -c mcp-gateway -n '__fish_seen_subcommand_from invoke inspect' -a '{n}'\n"
            )
        })
        .collect();

    let top_completions: String = TOP_COMMANDS
        .iter()
        .map(|(n, d)| {
            format!("complete -c mcp-gateway -n '__fish_use_subcommand' -a '{n}' -d '{d}'\n")
        })
        .collect();

    let tool_sub_completions: String = TOOL_SUBCOMMANDS
        .iter()
        .map(|(n, d)| {
            format!(
                "complete -c mcp-gateway -n '__fish_seen_subcommand_from tool' -a '{n}' -d '{d}'\n"
            )
        })
        .collect();

    format!(
        r"# mcp-gateway fish completion
# Place in ~/.config/fish/completions/mcp-gateway.fish

{top_completions}
{tool_sub_completions}
{tool_completions}
complete -c mcp-gateway -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
complete -c mcp-gateway -s c -l config -d 'Path to configuration file' -r
complete -c mcp-gateway -s p -l port -d 'Port to listen on'
complete -c mcp-gateway -l host -d 'Host to bind to'
complete -c mcp-gateway -l log-level -a 'trace debug info warn error' -d 'Log level'
complete -c mcp-gateway -l log-format -a 'text json' -d 'Log format'
complete -c mcp-gateway -l no-meta-mcp -d 'Disable Meta-MCP mode'
"
    )
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tools() -> Vec<String> {
        vec![
            "weather_current".to_string(),
            "yahoo_stock_quote".to_string(),
            "brave_search".to_string(),
        ]
    }

    #[test]
    fn bash_completion_contains_tool_names() {
        let script = generate_completion(ShellTarget::Bash, &sample_tools());
        assert!(script.contains("weather_current"));
        assert!(script.contains("yahoo_stock_quote"));
        assert!(script.contains("brave_search"));
    }

    #[test]
    fn bash_completion_contains_top_level_commands() {
        let script = generate_completion(ShellTarget::Bash, &[]);
        for (cmd, _) in TOP_COMMANDS {
            assert!(script.contains(cmd), "bash completion missing command: {cmd}");
        }
    }

    #[test]
    fn zsh_completion_contains_tool_names() {
        let script = generate_completion(ShellTarget::Zsh, &sample_tools());
        assert!(script.contains("weather_current"));
        assert!(script.contains("yahoo_stock_quote"));
    }

    #[test]
    fn zsh_completion_contains_compdef_header() {
        let script = generate_completion(ShellTarget::Zsh, &[]);
        assert!(script.starts_with("#compdef mcp-gateway"));
    }

    #[test]
    fn fish_completion_contains_tool_names() {
        let script = generate_completion(ShellTarget::Fish, &sample_tools());
        assert!(script.contains("weather_current"));
        assert!(script.contains("brave_search"));
    }

    #[test]
    fn fish_completion_contains_top_level_commands() {
        let script = generate_completion(ShellTarget::Fish, &[]);
        for (cmd, _) in TOP_COMMANDS {
            assert!(script.contains(cmd), "fish completion missing: {cmd}");
        }
    }

    #[test]
    fn shell_target_from_clap_shell_maps_known_shells() {
        assert_eq!(ShellTarget::from_shell(Shell::Bash), Some(ShellTarget::Bash));
        assert_eq!(ShellTarget::from_shell(Shell::Zsh), Some(ShellTarget::Zsh));
        assert_eq!(ShellTarget::from_shell(Shell::Fish), Some(ShellTarget::Fish));
    }

    #[test]
    fn empty_tool_list_generates_valid_scripts() {
        // GIVEN: no tools registered
        // THEN: all shells produce a non-empty, non-panicking script
        for shell in [ShellTarget::Bash, ShellTarget::Zsh, ShellTarget::Fish] {
            let script = generate_completion(shell, &[]);
            assert!(!script.is_empty());
        }
    }
}
