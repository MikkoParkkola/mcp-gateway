// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared writer keeps a replaced file's owner, ACL and labels, or
//! refuses before it writes anything.
//!
//! A row that saves as another user re-runs [`child::save`] in a child
//! process under that user, then asserts on the child's one result line and
//! on the files the child left behind.

mod child;
#[cfg(unix)]
mod root;

/// The child's result line starts with this: `saved`, or
/// `refused <ErrorKind> <message>`.
const RESULT: &str = "ACCESS-ROWS-RESULT:";
/// Set in a child: the file it saves.
const CHILD_TARGET: &str = "ACCESS_ROWS_CHILD_TARGET";
/// Set in a child: `private` or `inherit`, the writer's mode for the save.
const CHILD_MODE: &str = "ACCESS_ROWS_CHILD_MODE";
