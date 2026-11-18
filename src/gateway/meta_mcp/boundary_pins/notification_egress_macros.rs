// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Calls written inside a macro body, read from its tokens, for the
//! notification egress pin.

use super::{Body, NEEDLE_TAKERS, SCRUB_CALLS};

/// A parenthesised group's top-level arguments, split on commas.
fn arguments(group: &proc_macro2::Group) -> Vec<Vec<proc_macro2::TokenTree>> {
    let mut args = vec![Vec::new()];
    for tree in group.stream() {
        match &tree {
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => args.push(Vec::new()),
            _ => args.last_mut().expect("one open argument").push(tree),
        }
    }
    args.retain(|arg| !arg.is_empty());
    args
}

fn punct(tree: Option<&proc_macro2::TokenTree>, c: char) -> bool {
    matches!(tree, Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == c)
}

impl Body {
    /// Calls written inside a macro body (`select!`, `matches!`), read from
    /// its tokens: a name followed by a parenthesised group is a call, one
    /// after `.` a method call, each recorded after its arguments.
    pub(super) fn macro_calls(&mut self, stream: proc_macro2::TokenStream) {
        let trees: Vec<proc_macro2::TokenTree> = stream.into_iter().collect();
        let mut i = 0;
        while i < trees.len() {
            let call = match (&trees[i], trees.get(i + 1)) {
                (
                    proc_macro2::TokenTree::Ident(ident),
                    Some(proc_macro2::TokenTree::Group(group)),
                ) if group.delimiter() == proc_macro2::Delimiter::Parenthesis => {
                    Some((ident.to_string(), group))
                }
                _ => None,
            };
            let Some((name, group)) = call else {
                if let proc_macro2::TokenTree::Group(group) = &trees[i] {
                    self.macro_calls(group.stream());
                }
                i += 1;
                continue;
            };
            self.macro_calls(group.stream());
            let args = arguments(group);
            let method = i > 0 && punct(trees.get(i - 1), '.');
            let pathed = i > 0 && punct(trees.get(i - 1), ':');
            let sink_path = i >= 3
                && pathed
                && matches!(&trees[i - 3], proc_macro2::TokenTree::Ident(m) if m == "notification_sink");
            let sink = match name.as_str() {
                "send" | "try_send" if method && args.len() == 1 => Some("send"),
                "send" | "try_send" if pathed && args.len() == 2 => Some("send"),
                "deliver" if method || pathed => Some("deliver"),
                "publish" if sink_path => Some("publish"),
                "publish" if !method && !pathed => Some("bare publish"),
                _ => None,
            };
            if name == "collect"
                && i >= 3
                && pathed
                && matches!(&trees[i - 3], proc_macro2::TokenTree::Ident(m) if m == "notification_sink")
            {
                self.collects += 1;
            }
            // `None` or `Option::None`: the argument's last token, alone or after `::`.
            let none_arg = args.iter().any(|arg| match arg.as_slice() {
                [.., proc_macro2::TokenTree::Ident(n)] if n == "None" => {
                    arg.len() == 1 || punct(arg.get(arg.len() - 2), ':')
                }
                _ => false,
            });
            if none_arg
                && (SCRUB_CALLS.contains(&name.as_str()) || NEEDLE_TAKERS.contains(&name.as_str()))
            {
                self.none_needles.push(name.clone());
            }
            self.calls.push(name);
            if let Some(kind) = sink {
                self.sinks.push((kind, self.calls.len() - 1));
                self.last_send_arg = None;
            }
            i += 2;
        }
    }
}
