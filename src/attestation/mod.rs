//! Symphony+ sandbox attestation — token injection at sandbox creation (MIK-5223, B1-IDENT).
//!
//! Every sandbox boot receives a signed attestation token issued by the
//! bnaut-attestation platform component.  The gateway is the validation
//! authority: tokens are checked at boot and on every cross-boundary call,
//! and every rejection is recorded in a fixed-capacity audit ring buffer.
//!
//! # Design
//!
//! ```text
//! BnautAttestationSigner   (gateway-embedded client of bnaut-attestation;
//!   │                       HMAC-SHA256 via RustCrypto — no bespoke crypto)
//!   ├── issue()            signed AttestationToken (identity, task UUID,
//!   │                       capability allow-list, RFC-3339 expiry)
//!   └── rotate()           successor token; predecessor enters grace window
//!
//! AttestationValidator     (one per gateway; the single validation point)
//!   ├── validate_boundary_call()  signature → claims → expiry → rotation
//!   ├── audit: AuditRingBuffer    every rejection, with detection latency
//!   └── checkpoint()/restore()    rotation state survives checkpoints (B3)
//!
//! AttestedSandboxLauncher  (fail-closed boot gate, OCI createRuntime hook)
//!   └── boot()             no token = no start; identical flow on
//!                           gVisor (Linux) and Apple containerization (macOS)
//! ```
//!
//! # Rollback
//!
//! The whole gate is controlled by the `SYMPHONY_PLUS_ATTESTATION` env flag:
//! `0` boots sandboxes without a token (still isolated, loses identity
//! attribution); any other value — including unset — enforces fail-closed.

pub mod launcher;
pub mod signer;
pub mod token;
pub mod validator;

pub use launcher::{
    ATTESTATION_FLAG_ENV, AttestationEnforcement, AttestedSandboxLauncher, BootDenial,
    SandboxHandle, SandboxLaunchSpec, Substrate, TOKEN_ENV_VAR,
};
pub use signer::{BnautAttestationSigner, TokenRequest};
pub use token::{AttestationToken, BNAUT_ISSUER, SIGNING_ALGORITHM, TokenClaims};
pub use validator::{
    AttestationAuditRecord, AttestationRejection, AttestationValidator, AuditRingBuffer,
    RetiringToken, RotationCheckpoint,
};
