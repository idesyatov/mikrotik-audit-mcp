//! Audit checks: a check declares the read-only command it needs and a pure
//! `evaluate(output) -> Outcome`. Separating I/O from logic keeps every check
//! unit-testable against fixtures without a device (see also Stage 8 evals).

pub mod auth;
pub mod firewall;
pub mod hygiene;
pub mod logging;
mod parse;
pub mod services;
pub mod updates;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
// The full scale is defined up front; not every level is used yet.
#[allow(dead_code)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    Auth,
    Services,
    Firewall,
    Updates,
    Logging,
    NetworkHygiene,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Error,
}

/// A single audit result.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub domain: Domain,
    pub title: &'static str,
    pub severity: Severity,
    pub status: Status,
    pub detail: String,
    pub recommendation: &'static str,
}

/// The verdict a check returns for a given device output.
pub struct Outcome {
    pub status: Status,
    pub detail: String,
}

impl Outcome {
    pub fn pass(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            detail: detail.into(),
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            detail: detail.into(),
        }
    }
}

pub trait Check: Send + Sync {
    /// Stable identifier, e.g. `auth-default-admin`.
    fn id(&self) -> &'static str;
    fn domain(&self) -> Domain;
    fn title(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn recommendation(&self) -> &'static str;
    /// The whitelisted RouterOS command this check needs.
    fn command(&self) -> &'static str;
    /// Pure evaluation of the command's output.
    fn evaluate(&self, output: &str) -> Outcome;
}

/// Every check the auditor runs.
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        // auth
        Box::new(auth::DefaultAdminUser),
        Box::new(auth::UsersWithoutAddressRestriction),
        // services
        Box::new(services::InsecureServiceEnabled),
        Box::new(services::ServicesWithoutAddressRestriction),
        Box::new(services::SshOnDefaultPort),
        Box::new(services::SshStrongCrypto),
        // firewall
        Box::new(firewall::InputChainHasRules),
        Box::new(firewall::InputDefaultDrop),
        Box::new(firewall::InputDropsInvalid),
        // updates
        Box::new(updates::StableReleaseChannel),
        Box::new(updates::RouterboardFirmwareCurrent),
        // logging
        Box::new(logging::RemoteLoggingConfigured),
        Box::new(logging::CriticalTopicsLogged),
        // network hygiene
        Box::new(hygiene::NeighborDiscoveryRestricted),
        Box::new(hygiene::BandwidthServerDisabled),
        Box::new(hygiene::MacServerRestricted),
        Box::new(hygiene::MacWinboxRestricted),
        Box::new(hygiene::DnsNotOpenResolver),
        Box::new(hygiene::UpnpDisabled),
        Box::new(hygiene::RomonDisabled),
    ]
}

#[cfg(test)]
mod registry_tests {
    use super::all_checks;
    use crate::whitelist;

    /// Every command a check issues must pass the read-only whitelist, so a
    /// future whitelist change can never silently break the audit.
    #[test]
    fn all_check_commands_are_whitelisted() {
        for check in all_checks() {
            assert!(
                whitelist::validate(check.command()).is_ok(),
                "check {} uses a non-whitelisted command: {:?}",
                check.id(),
                check.command()
            );
        }
    }

    #[test]
    fn check_ids_are_unique() {
        let checks = all_checks();
        let total = checks.len();
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate check ids");
    }
}
