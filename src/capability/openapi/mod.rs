//! `OpenAPI` to Capability converter
//!
//! Generates capability YAML definitions from `OpenAPI` specifications.
//! Supports `OpenAPI` 3.0 and 3.1.
//!
//! # Usage
//!
//! ```ignore
//! let converter = OpenApiConverter::new();
//! let capabilities = converter.convert_file("api.yaml")?;
//! for cap in capabilities {
//!     cap.write_to_file("capabilities/")?;
//! }
//! ```

mod auth;

mod convert;

mod generated;

mod model;

mod refs;

mod sanitize;

pub use convert::OpenApiConverter;

pub use generated::{AuthTemplate, CacheTemplate, GeneratedCapability};

#[cfg(test)]
pub(crate) use sanitize::sanitize_description;

#[cfg(test)]
mod tests;
