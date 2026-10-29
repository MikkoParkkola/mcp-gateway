// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The error-kind decision order: first match wins, so an answer whose
//! status and code point at different kinds still gets exactly one. The
//! origin decides `backend`; the code `-32000` alone decides nothing.

use super::{ErrorKind, Origin, RpcError, error_kind};

const fn gateway(code: i32) -> RpcError {
    RpcError {
        code,
        origin: Origin::Gateway,
    }
}

const fn failure(code: i32) -> RpcError {
    RpcError {
        code,
        origin: Origin::BackendFailure,
    }
}

const fn backend(code: i32) -> RpcError {
    RpcError {
        code,
        origin: Origin::Backend,
    }
}

#[test]
fn each_answer_gets_the_first_kind_that_matches() {
    let rows: [(&str, u16, Option<RpcError>, Option<ErrorKind>); 19] = [
        ("success", 200, None, None),
        ("accepted notification", 202, None, None),
        (
            "backend failure the gateway reports",
            200,
            Some(failure(-32000)),
            Some(ErrorKind::Backend),
        ),
        (
            "the gateway's own -32000, a throttle",
            200,
            Some(gateway(-32000)),
            Some(ErrorKind::Request),
        ),
        (
            "a forwarded -32000",
            200,
            Some(backend(-32000)),
            Some(ErrorKind::Backend),
        ),
        (
            "backend's own -32603, forwarded",
            200,
            Some(backend(-32603)),
            Some(ErrorKind::Backend),
        ),
        (
            "backend's own -32602, forwarded",
            200,
            Some(backend(-32602)),
            Some(ErrorKind::Backend),
        ),
        (
            "503 carrying a backend failure",
            503,
            Some(failure(-32000)),
            Some(ErrorKind::Backend),
        ),
        (
            "503 carrying the gateway's own -32000",
            503,
            Some(gateway(-32000)),
            Some(ErrorKind::Internal),
        ),
        ("no credential", 401, None, Some(ErrorKind::Auth)),
        (
            "standard key on an admin route",
            403,
            None,
            Some(ErrorKind::Auth),
        ),
        (
            "403 carrying -32603",
            403,
            Some(gateway(-32603)),
            Some(ErrorKind::Auth),
        ),
        ("500 with no frame", 500, None, Some(ErrorKind::Internal)),
        (
            "503 carrying a request code",
            503,
            Some(gateway(-32602)),
            Some(ErrorKind::Internal),
        ),
        (
            "gateway's own -32603",
            200,
            Some(gateway(-32603)),
            Some(ErrorKind::Internal),
        ),
        (
            "method not found",
            200,
            Some(gateway(-32601)),
            Some(ErrorKind::Request),
        ),
        (
            "400 carrying a parse error",
            400,
            Some(gateway(-32700)),
            Some(ErrorKind::Request),
        ),
        ("404 with no frame", 404, None, Some(ErrorKind::Request)),
        ("429 with no frame", 429, None, Some(ErrorKind::Request)),
    ];
    for (case, status, marker, kind) in rows {
        assert_eq!(error_kind(status, marker), kind, "{case}");
    }
}
