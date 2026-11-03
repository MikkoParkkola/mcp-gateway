// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the log-under-lock scan walks loops and matches: what each body holds,
//! and which names the pattern shadows inside it.

use super::{bound_names, is_err_arm};

impl super::Scan<'_> {
    /// `for p in e { .. }`: an acquiring `e` holds `p`, and iterating a map
    /// holds a shard lock, for the whole body.
    pub(super) fn for_loop(&mut self, l: &syn::ExprForLoop, held: &[String]) {
        self.expr(&l.expr, held);
        let mut inner = held.to_vec();
        if self.acquires(&l.expr, held) {
            inner.extend(bound_names(&l.pat));
        }
        // Iterating a map holds a shard lock for the whole body,
        // whatever the pattern binds: `for _ in m` too.
        if self.iterates_dashmap(&l.expr) {
            inner.push("<map iteration>".into());
        }
        self.env.push();
        self.shadow(&l.pat);
        self.block(&l.body, inner);
        self.env.pop();
    }

    /// `while let p = e { .. }`: an acquiring `e` holds `p` in the body.
    pub(super) fn while_loop(&mut self, w: &syn::ExprWhile, held: &[String]) {
        let mut inner = held.to_vec();
        self.env.push();
        if let syn::Expr::Let(l) = &*w.cond {
            self.expr(&l.expr, held);
            if self.acquires(&l.expr, held) {
                inner.extend(bound_names(&l.pat));
            }
            self.shadow(&l.pat);
        } else {
            self.expr(&w.cond, held);
        }
        self.block(&w.body, inner);
        self.env.pop();
    }

    /// `match e { .. }`: an acquiring `e` holds each non-`Err` arm's bindings.
    pub(super) fn match_arms(&mut self, m: &syn::ExprMatch, held: &[String]) {
        self.expr(&m.expr, held);
        let scrutinee_holds = self.acquires(&m.expr, held);
        for arm in &m.arms {
            let mut inner = held.to_vec();
            if scrutinee_holds && !is_err_arm(&arm.pat) {
                inner.extend(bound_names(&arm.pat));
                inner.push("<match scrutinee>".into());
            }
            self.env.push();
            self.shadow(&arm.pat);
            self.expr(&arm.body, &inner);
            self.env.pop();
        }
    }
}
