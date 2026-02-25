//! Built-in transforms for the provider middleware chain.
//!
//! Each transform implements [`crate::provider::Transform`] and can be
//! composed into a [`chain::TransformChain`].
//!
//! # Available Transforms
//!
//! | Transform | Purpose |
//! |-----------|---------|
//! | [`NamespaceTransform`] | Prefix tool names (e.g. `gmail_*`) |
//! | [`FilterTransform`] | Allow/deny tools by exact name or glob pattern |
//! | [`RenameTransform`] | Rename individual tools |
//! | [`ResponseTransform`] | Project/redact response fields |
//!
//! # Transform Pipeline Order
//!
//! Fixed order within a `TransformChain`:
//! `namespace → filter → auth → response`

pub mod chain;
pub mod filter;
pub mod namespace;
pub mod rename;
pub mod response;

pub use filter::FilterTransform;
pub use namespace::NamespaceTransform;
pub use rename::RenameTransform;
pub use response::ResponseTransform;
