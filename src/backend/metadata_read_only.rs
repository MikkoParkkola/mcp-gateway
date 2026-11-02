// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which tools the response cache may answer for (MIK-8393, from #3773).

use std::collections::HashSet;
use std::sync::Arc;

use super::Backend;

impl Backend {
    /// Whether `binding`'s slot declared `tool` read-only, as of its last
    /// `tools/list`: the only thing that lets the response cache store or
    /// serve its result (MIK-8393). The same slot resolution the dispatch
    /// uses, as a lookup: a cold slot answers `false`.
    #[must_use]
    pub(crate) fn is_read_only_for(&self, binding: Option<&str>, tool: &str) -> bool {
        self.tools_slot(binding)
            .read_only_declared
            .read()
            .contains(tool)
    }

    /// The shared catalogue with the names whose `readOnlyHint` the server
    /// declared, read under the cache's guard, so both come from one fill:
    /// every writer of the set runs under that guard's write side.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot start or the tools request fails.
    #[cfg(feature = "webui")]
    pub(crate) async fn shared_tools_with_declared_hints(
        &self,
    ) -> crate::Result<(Arc<Vec<crate::protocol::Tool>>, HashSet<String>)> {
        let fetched = self.get_tools_shared().await?;
        let slot = self.tools_slot(None);
        Ok(slot.tools_cache.with_cached(|cached| match cached {
            Some(tools) => (Arc::clone(tools), slot.hint_declared.read().clone()),
            // ponytail: cleared since the fetch, and its labels with it; this
            // answer reads every hint as inferred until the next fill.
            None => (fetched, HashSet::new()),
        }))
    }

    /// An accepted fill's own derived state: its resend and read-only sets
    /// (replaced by a complete fill, only narrowed by a truncated one), and
    /// its descriptor verdicts. Written only from the store callback, so
    /// a fill voided by a mid-fill invalidation writes none of it (F13,
    /// #1441, MIK-8393).
    pub(super) fn store_prepared(
        &self,
        entry: &crate::backend::pool::PooledEntry,
        identity_key: Option<&str>,
        truncated: bool,
        prepared: crate::backend::annotations::PreparedTools,
    ) -> crate::backend::descriptor_gate::PendingLogs {
        // Emptied first and published last: until then no name reads
        // undeclared from a mix of the old and new sets.
        entry.effect_listed.write().clear();
        if truncated {
            // A page the fill never reached may list a name again without
            // the hint, so a truncated fill only narrows: a name keeps a
            // grant it already held while the pages read still declare it.
            // Only a complete fill grants.
            entry
                .resend_permitted
                .write()
                .retain(|tool| prepared.resend_permitted.contains(tool));
            entry
                .read_only_declared
                .write()
                .retain(|tool| prepared.read_only_declared.contains(tool));
        } else {
            *entry.resend_permitted.write() = prepared.resend_permitted;
            *entry.read_only_declared.write() = prepared.read_only_declared;
        }
        *entry.hint_declared.write() = prepared.hint_declared;
        *entry.write_declared.write() = prepared.write_declared;
        // A truncated fill may not have reached a name's other occurrences,
        // so no name it lists reads undeclared.
        *entry.effect_listed.write() = if truncated {
            HashSet::new()
        } else {
            prepared.listed
        };
        let listing = if truncated {
            crate::backend::Listing::Truncated
        } else {
            crate::backend::Listing::Complete
        };
        self.commit_verdicts(identity_key.unwrap_or(""), listing, prepared.verdicts)
    }

    /// Seed the shared slot's read-only set, for fixtures whose subject is the
    /// cache's keying rather than how a declaration is read.
    #[cfg(test)]
    pub(crate) fn set_read_only_declared_for_test(&self, tools: &[&str]) {
        *self.shared_entry().read_only_declared.write() =
            tools.iter().map(|tool| (*tool).to_string()).collect();
    }

    /// A page that is not stored (truncated, or fetched under a caller's own
    /// credential into the shared slot) may still revoke (MIK-8393 r5-r7,
    /// MIK-8399). It revokes when it lists a tool that the slot admits to the
    /// cache without declaring it read-only, or that the slot permits to be
    /// resent without declaring it resend-safe, or lists any tool not
    /// declared read-only while a fill is on the wire. Then the slot's tool
    /// list is invalidated, and each set keeps only the names this page
    /// itself declares safe for it (an idempotent write keeps its retries and
    /// loses its cache admission).
    ///
    /// `listed` is every name the page listed, read before the header and
    /// descriptor gates dropped any; `read_only` and `resend_safe` are the
    /// page's own sets, so a dropped name counts as not safe.
    ///
    /// Invalidating moves the cache generation, so a fill already on the wire
    /// cannot land afterwards and re-grant (`store_if_current`); the next
    /// accepted fill re-derives both sets from a complete list. The slot is
    /// looked up, never created (#2300). A page that revokes nothing costs
    /// nothing.
    pub(in crate::backend) fn revoke_from_page(
        &self,
        key: &crate::backend::PoolKey,
        listed: &[String],
        (read_only, write, hint): (&HashSet<String>, &HashSet<String>, &HashSet<String>),
        resend_safe: &HashSet<String>,
    ) {
        let Some(slot) = self.pool.get(key).map(|slot| Arc::clone(slot.value())) else {
            return;
        };
        // Whether or not it revokes, a page withdraws the effect it contradicts.
        // Under the cache's guard, taken first as every writer of these sets
        // takes it, so no replacement lands between the compare and the
        // retain and makes an agreeing declaration look contradicted.
        let names: HashSet<String> = listed.iter().cloned().collect();
        slot.tools_cache.with_cached(|_| {
            narrow_effect_to_page(&slot, listed, hints(read_only, write, hint, &names));
        });
        // In flight FIRST (MIK-8393 r7): a fill stores its sets before it
        // clears the mark, so with no fill in flight the reads below see
        // whatever the last fill stored.
        let in_flight = slot.tools_cache.fill_in_flight();
        let not_read = || listed.iter().filter(|t| !read_only.contains(*t));
        let revokes = not_read().next().is_some() && in_flight
            || {
                let admitted = slot.read_only_declared.read();
                not_read().any(|t| admitted.contains(t))
            }
            || {
                let permitted = slot.resend_permitted.read();
                listed
                    .iter()
                    .any(|t| !resend_safe.contains(t) && permitted.contains(t))
            };
        if revokes {
            slot.tools_cache.invalidate_then(|| {
                slot.resend_permitted
                    .write()
                    .retain(|t| resend_safe.contains(t));
                // Before the read-only set narrows, so it sees what that clears.
                narrow_effect(&slot, |t| read_only.contains(t), |t| write.contains(t));
                slot.read_only_declared
                    .write()
                    .retain(|t| read_only.contains(t));
            });
        }
    }

    /// The page's names as listed (before any gate dropped one), and its own
    /// read-only and resend-safe sets. Unparseable entries declare nothing
    /// and are dropped; no descriptor verdict is formed (`AlreadyJudged`).
    fn page_sets(
        name: &str,
        pins: &std::collections::BTreeMap<String, String>,
        tools: &[serde_json::Value],
    ) -> PageSets {
        let (mut parsed, _unparseable) = crate::backend::descriptor_gate::parse_listed(tools);
        let listed = parsed.iter().map(|t| t.name.clone()).collect();
        let prepared = crate::backend::prepare_tool_metadata(
            name,
            pins,
            crate::backend::Judging::AlreadyJudged,
            &mut parsed,
        );
        PageSets {
            listed,
            read_only: prepared.read_only_declared,
            write: prepared.write_declared,
            hint: prepared.hint_declared,
            resend_safe: prepared.resend_permitted,
        }
    }

    /// A direct drain that ended without being remembered (an error frame, a
    /// lost transport, the page cap, a cancellation) revokes from the pages
    /// it read, as a page that is not stored does (MIK-8399). Nothing is
    /// stored and no verdict is committed. Pages that listed nothing revoke
    /// nothing.
    pub(crate) fn revoke_from_abandoned_listing(
        &self,
        identity_key: Option<&str>,
        tools: &[serde_json::Value],
    ) {
        if tools.is_empty() {
            return;
        }
        let page = Self::page_sets(&self.name, self.flagged_tool_pins(), tools);
        self.revoke_from_page(
            &self.pool_key_for(identity_key),
            &page.listed,
            (&page.read_only, &page.write, &page.hint),
            &page.resend_safe,
        );
    }

    /// The hook a tools fill hands its single-flight permit (MIK-8399 r3-r5).
    /// If the fill ends without an answer, it narrows `entry`'s sets from the
    /// pages it read: a name those pages list without declaring it safe
    /// leaves the set, and every other name stays. The fill read only a
    /// prefix of the list, so a name it did not reach says nothing. Nothing
    /// is invalidated: the last complete catalogue keeps being served, and
    /// the permit runs this before any newer fill can start.
    pub(in crate::backend) fn abandoned_fill_hook(
        &self,
        entry: Arc<crate::backend::pool::PooledEntry>,
        seen: Arc<parking_lot::Mutex<Vec<serde_json::Value>>>,
    ) -> crate::backend::cached_metadata::AbandonHook {
        let name = self.name.clone();
        let pins = self.flagged_tool_pins().clone();
        Box::new(move || {
            let pages = std::mem::take(&mut *seen.lock());
            if pages.is_empty() {
                return;
            }
            let page = Self::page_sets(&name, &pins, &pages);
            let listed: HashSet<&String> = page.listed.iter().collect();
            entry
                .resend_permitted
                .write()
                .retain(|t| !listed.contains(t) || page.resend_safe.contains(t));
            // A name the pages never listed keeps its effect; a listed one
            // keeps it only where the page declares the same. Before the
            // read-only set narrows, so it reads the slot's effect as it was.
            let names: HashSet<String> = page.listed.iter().cloned().collect();
            let declared = hints(&page.read_only, &page.write, &page.hint, &names);
            narrow_effect_to_page(&entry, &page.listed, declared);
            entry
                .read_only_declared
                .write()
                .retain(|t| !listed.contains(t) || page.read_only.contains(t));
        })
    }

    /// The declared effect of `tool` in `binding`'s slot, as of its last
    /// `tools/list`: the same slot resolution the dispatch uses. A cold slot,
    /// or evidence that cannot say, gives `None`.
    #[must_use]
    pub(crate) fn declared_effect_for(
        &self,
        binding: Option<&str>,
        tool: &str,
    ) -> Option<crate::security::decision_record::Effect> {
        let slot = self.tools_slot(binding);
        let (read_only, write) = (slot.read_only_declared.read(), slot.write_declared.read());
        let (hint, listed) = (slot.hint_declared.read(), slot.effect_listed.read());
        crate::backend::annotations::declared_effect(
            tool,
            crate::backend::annotations::DeclaredHints {
                read_only_declared: &read_only,
                write_declared: &write,
                hint_declared: &hint,
                listed: &listed,
            },
        )
    }
}

/// One page's sets, read before any gate dropped a name.
struct PageSets {
    listed: Vec<String>,
    read_only: HashSet<String>,
    write: HashSet<String>,
    hint: HashSet<String>,
    resend_safe: HashSet<String>,
}

fn hints<'a>(
    read_only_declared: &'a HashSet<String>,
    write_declared: &'a HashSet<String>,
    hint_declared: &'a HashSet<String>,
    listed: &'a HashSet<String>,
) -> crate::backend::annotations::DeclaredHints<'a> {
    crate::backend::annotations::DeclaredHints {
        read_only_declared,
        write_declared,
        hint_declared,
        listed,
    }
}

/// Take out of `entry`'s effect every name in `listed` whose effect on the
/// page (`page`) differs from the slot's, so evidence the page contradicts
/// records no effect rather than either reading. The read-only set is the
/// cache's and is narrowed by the caller.
fn narrow_effect_to_page(
    entry: &crate::backend::pool::PooledEntry,
    listed: &[String],
    page: crate::backend::annotations::DeclaredHints<'_>,
) {
    use crate::backend::annotations::declared_effect;
    let contradicted: HashSet<&String> = {
        // In declared_effect_for's order, every writer holding one at a time.
        let (read_only, write) = (entry.read_only_declared.read(), entry.write_declared.read());
        let (hint, names) = (entry.hint_declared.read(), entry.effect_listed.read());
        let slot = hints(&read_only, &write, &hint, &names);
        listed
            .iter()
            .filter(|t| declared_effect(t, slot) != declared_effect(t, page))
            .collect()
    };
    if contradicted.is_empty() {
        return;
    }
    entry
        .write_declared
        .write()
        .retain(|t| !contradicted.contains(t));
    entry
        .effect_listed
        .write()
        .retain(|t| !contradicted.contains(t));
}

/// Narrow `entry`'s may-write set to the names `keep_write` keeps, and take
/// out of the effect's listed names every name whose read-only or may-write
/// declaration this narrowing clears, so it records no effect rather than
/// reading undeclared. Called before the caller narrows the read-only set,
/// which it reads to find the read-only names `keep_read_only` drops.
fn narrow_effect(
    entry: &crate::backend::pool::PooledEntry,
    keep_read_only: impl Fn(&String) -> bool,
    keep_write: impl Fn(&String) -> bool,
) {
    // One lock at a time, read-only set first: the order declared_effect_for
    // reads them in, so the two cannot deadlock.
    let mut cleared: HashSet<String> = entry
        .read_only_declared
        .read()
        .iter()
        .filter(|t| !keep_read_only(t))
        .cloned()
        .collect();
    {
        let mut write = entry.write_declared.write();
        cleared.extend(write.iter().filter(|t| !keep_write(t)).cloned());
        write.retain(|t| keep_write(t));
    }
    entry.effect_listed.write().retain(|t| !cleared.contains(t));
}

#[cfg(test)]
#[path = "read_only_revoke_tests.rs"]
mod revoke_tests;
