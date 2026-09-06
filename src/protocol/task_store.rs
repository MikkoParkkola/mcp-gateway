// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Ownership and lifetime for the tasks extension.
//!
//! [`Task`] is the record. This is the only thing that knows *whose* it is, and
//! that is the whole reason it exists beside the continuation ledger rather than
//! inside it: a continuation handle is resumed by whoever holds it, while a task
//! id is addressed by a principal who must own it. One store answering both
//! questions would have to answer them differently on the same call.
//!
//! Process-local, deliberately. `docs/design/2026-08-31-task-1-tasks-extension.md`
//! §11.2 gates the shared insert-if-absent store on cluster A's ledger landing —
//! the same replica-affinity problem, inheriting that gate instead of inventing a
//! second answer. Multi-replica, a `tasks/get` routed elsewhere reports the task
//! missing while it runs.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::protocol::tasks::Task;

/// A task plus the principal allowed to see it.
#[derive(Debug, Clone)]
struct Record {
    principal: String,
    task: Task,
}

/// Principal-scoped storage for in-flight tasks.
#[derive(Debug, Default)]
pub struct TaskStore {
    records: Mutex<HashMap<String, Record>>,
}

impl TaskStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a task for `tool`, owned by `principal`, and return its id.
    ///
    /// The id is minted by [`Task::create`] from a v4 UUID, so it is unguessable
    /// — ownership is enforced below regardless, because an unguessable id is a
    /// secret and a secret is not an authorization decision.
    pub fn create(&self, principal: &str, tool: &str) -> String {
        let task = Task::create(tool);
        let id = task.id().to_string();
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id.clone(),
                Record {
                    principal: principal.to_string(),
                    task,
                },
            );
        id
    }

    /// The task, if `principal` owns it.
    ///
    /// **A task owned by someone else answers exactly as an id that never
    /// existed.** Two answers would tell an unrelated caller that a handle is
    /// live and simply not theirs, which is a membership oracle over every
    /// principal's work.
    #[must_use]
    pub fn get(&self, principal: &str, id: &str) -> Option<Task> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .filter(|record| record.principal == principal)
            .map(|record| record.task.clone())
    }

    /// Whether `principal` owns every one of `ids`.
    ///
    /// All-or-nothing: a partially admitted subscription leaks which of the
    /// listed ids exist, which is the oracle [`TaskStore::get`] closes.
    #[must_use]
    pub fn owns_all<'a>(&self, principal: &str, ids: impl IntoIterator<Item = &'a str>) -> bool {
        let records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ids.into_iter()
            .all(|id| records.get(id).is_some_and(|r| r.principal == principal))
    }

    /// Apply `change` to a task the principal owns, reporting whether it was found.
    pub fn update(&self, principal: &str, id: &str, change: impl FnOnce(&mut Task)) -> bool {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = records.get_mut(id).filter(|r| r.principal == principal) else {
            return false;
        };
        change(&mut record.task);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::TaskStore;
    use crate::protocol::tasks::TaskStatus;

    #[test]
    fn a_created_task_resolves_for_its_owner() {
        let store = TaskStore::new();
        let id = store.create("principal-a", "weather.get");
        let task = store.get("principal-a", &id).expect("owner sees its task");
        assert_eq!(task.status(), TaskStatus::Working);
        assert_eq!(task.tool(), "weather.get");
    }

    #[test]
    fn a_foreign_task_answers_as_an_absent_one() {
        let store = TaskStore::new();
        let id = store.create("principal-a", "weather.get");
        assert!(store.get("principal-b", &id).is_none());
        assert!(store.get("principal-b", "task-nonexistent").is_none());
        assert!(!store.owns_all("principal-b", [id.as_str()]));
        assert!(store.owns_all("principal-a", [id.as_str()]));
    }

    #[test]
    fn owns_all_is_all_or_nothing() {
        let store = TaskStore::new();
        let mine = store.create("principal-a", "weather.get");
        assert!(!store.owns_all("principal-a", [mine.as_str(), "task-absent"]));
    }

    #[test]
    fn an_update_reaches_only_the_owners_task() {
        let store = TaskStore::new();
        let id = store.create("principal-a", "weather.get");
        assert!(!store.update("principal-b", &id, |t| t.fail("never")));
        assert!(store.update("principal-a", &id, |t| t.fail("upstream refused")));
        let task = store.get("principal-a", &id).expect("still there");
        assert_eq!(task.status(), TaskStatus::Failed);
    }
}
