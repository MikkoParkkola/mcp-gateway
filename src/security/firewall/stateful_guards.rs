// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The firewall's stateful request guards: the tenant guard and its read
//! history, and the call budget. Their state outlives every generation
//! (ADR-029, amended, L3), so they read no policy.

use serde_json::Value;

use super::*;

impl Firewall {
    /// MIK-7116.MIN.1: the tenants a request's `args` name under
    /// `tenant_guard.arg_keys`, whether or not the guard may refuse.
    pub(crate) fn request_tenants(&self, args: &Value) -> std::collections::BTreeSet<String> {
        self.tenant_guard.request_tenants(args)
    }

    /// MIK-7116.MIN.1: the tenants a tool result names (text-JSON included).
    pub(crate) fn response_tenants(&self, result: &Value) -> std::collections::BTreeSet<String> {
        self.tenant_guard.response_tenants(result)
    }

    /// Share `reads` with every other firewall of this process, so one
    /// caller's reads on `/mcp` and `/mcp/{name}` meet in one history.
    #[must_use]
    pub(crate) fn with_reads(mut self, reads: Arc<tenant_reads::ReadHistory>) -> Self {
        self.reads = reads;
        self
    }

    /// The process's cross-tenant read history.
    pub(crate) const fn reads(&self) -> &Arc<tenant_reads::ReadHistory> {
        &self.reads
    }

    /// The tenant guard, for attribution reads that record nothing (MIN.1).
    pub(crate) const fn tenant_guard(&self) -> &tenant_guard::TenantGuard {
        &self.tenant_guard
    }

    /// Cross-tenant data-minimisation guard (MIK-7116.TENANT.1). Pushes a
    /// finding into `findings` for a refused or unattributable call and
    /// returns whether the caller must be force-blocked (unattributable —
    /// no rule may soften an unmeasured call), mirroring `anomaly_blind`.
    pub(super) fn check_tenant_guard(
        &self,
        principal: Option<&str>,
        args: &Value,
        server: &str,
        tool: &str,
        findings: &mut Vec<Finding>,
    ) -> bool {
        match self.tenant_guard.check(principal, args) {
            tenant_guard::TenantVerdict::Allowed => false,
            tenant_guard::TenantVerdict::Refused { distinct, limit } => {
                findings.push(Finding {
                    scan_type: ScanType::CrossTenantReach,
                    severity: crate::security::Severity::High,
                    description: format!(
                        "Cross-tenant reach exceeded: principal touched {distinct} distinct \
                         tenants (limit {limit})"
                    ),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::RequestArgs,
                });
                false
            }
            tenant_guard::TenantVerdict::Unattributable => {
                tracing::warn!(
                    server = server,
                    tool = tool,
                    "MIK-7116.TENANT.1: tenant guard has no principal to key on; \
                     refusing rather than passing the call unmeasured"
                );
                findings.push(Finding {
                    scan_type: ScanType::CrossTenantReach,
                    severity: crate::security::Severity::High,
                    description:
                        "Tenant-scoped call has no authenticated principal to key breadth on; \
                         call refused unmeasured"
                            .to_string(),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::RequestArgs,
                });
                true
            }
        }
    }

    /// Judge one request against the principal-keyed call budget
    /// (MIK-7215.CONTROL.2), pushing a [`Finding`] and returning `true` when
    /// the call must be refused.
    ///
    /// Split out of [`Self::check_request`] to keep that function under the
    /// line-count lint; the two `Refused`/`Unattributable` arms are the whole
    /// control and have no reason to live inline.
    pub(super) fn check_budget(
        &self,
        identity: Option<&str>,
        server: &str,
        tool: &str,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(budget) = self.budget.as_ref() else {
            return false;
        };
        match budget.check(identity, server, tool) {
            budget_guard::BudgetVerdict::Allowed => false,
            budget_guard::BudgetVerdict::Refused { total, limit } => {
                findings.push(Finding {
                    scan_type: ScanType::BudgetExceeded,
                    severity: crate::security::Severity::High,
                    description: format!(
                        "Call budget exceeded: {total} calls in the window (limit {limit})"
                    ),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
                true
            }
            budget_guard::BudgetVerdict::Unattributable => {
                // Same failure shape as an unobservable anomaly check: a
                // budget with nothing to key on cannot protect, so it must
                // say so rather than count it under a key nobody chose. The
                // one deliberate shared key is the keyless session-less
                // caller (MIK-7971), which arrives here as an identity.
                findings.push(Finding {
                    scan_type: ScanType::BudgetExceeded,
                    severity: crate::security::Severity::High,
                    description:
                        "Call budget has no caller identity to key on; call refused unattributed"
                            .to_string(),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
                true
            }
        }
    }
}
