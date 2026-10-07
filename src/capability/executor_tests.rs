// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `CapabilityExecutor` and `ResponseCache`

use super::*;
use crate::capability::CapabilityExecutionContext;
use crate::capability::response_cache::ResponseCache;
use crate::identity_grants::GrantSubject;
use axum::{
    Json, Router,
    body::Body,
    http::header,
    response::Response as AxumResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[path = "executor_tests/body_content_type.rs"]
mod body_content_type;
#[path = "executor_tests/cache_partitioning.rs"]
mod cache_partitioning;
#[path = "executor_tests/null_body.rs"]
mod null_body;
#[path = "executor_tests/rate_limit_errors.rs"]
mod rate_limit_errors;
#[path = "executor_tests/request_params.rs"]
mod request_params;
#[path = "executor_tests/static_params.rs"]
mod static_params;
