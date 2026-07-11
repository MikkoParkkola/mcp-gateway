// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
pub(crate) mod errors;

pub(crate) use errors::{
    bearer_unauthorized_response, circuit_open_response, forbidden_response, rate_limited_response,
};

#[cfg(test)]
mod tests;
