//! Security scoring: turn findings into a 0–100 score with a per-domain
//! breakdown, under a chosen audit [`Profile`].
//!
//! `S = clamp( Σ(weight_i × domain_score_i) − penalties, 0, 100 )`
//!
//! Each failed check deducts from its domain's score by severity, and High /
//! Critical failures add a *global* penalty so a single severe issue drags the
//! total even when its domain is lightly weighted (otherwise averaging would
//! dilute it). Checks that errored (command didn't run) are excluded.

use serde::{Deserialize, Serialize};

use crate::checks::{Domain, Finding, Severity, Status};

/// Domain weights for a profile. Each set sums to 1.0.
pub type Weights = &'static [(Domain, f64)];

/// Balanced defaults for a home router.
const HOME_WEIGHTS: Weights = &[
    (Domain::Firewall, 0.25),
    (Domain::Auth, 0.20),
    (Domain::Services, 0.20),
    (Domain::NetworkHygiene, 0.15),
    (Domain::Updates, 0.10),
    (Domain::Logging, 0.10),
];

/// Stricter on accounts and audit-trail (auth, logging).
const CORPORATE_WEIGHTS: Weights = &[
    (Domain::Firewall, 0.25),
    (Domain::Auth, 0.25),
    (Domain::Services, 0.15),
    (Domain::NetworkHygiene, 0.10),
    (Domain::Updates, 0.10),
    (Domain::Logging, 0.15),
];

/// Audit profile: selects the domain weighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Home,
    Corporate,
}

impl Profile {
    pub fn weights(self) -> Weights {
        match self {
            Self::Home => HOME_WEIGHTS,
            Self::Corporate => CORPORATE_WEIGHTS,
        }
    }

    /// Parse a profile name (case-insensitive); `None` if unknown.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "home" => Some(Self::Home),
            "corporate" => Some(Self::Corporate),
            _ => None,
        }
    }
}

/// Points a failed check subtracts from its domain's score.
fn deduction(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 0.0,
        Severity::Low => 5.0,
        Severity::Medium => 15.0,
        Severity::High => 30.0,
        Severity::Critical => 50.0,
    }
}

/// Extra global penalty a severe failed check subtracts from the total.
fn penalty(severity: Severity) -> u32 {
    match severity {
        Severity::High => 8,
        Severity::Critical => 20,
        _ => 0,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainScore {
    pub domain: Domain,
    pub weight: f64,
    pub score: u8,
    /// Evaluable (non-errored) checks in the domain.
    pub checks: usize,
    pub failed: usize,
    pub errored: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Score {
    pub total: u8,
    pub profile: Profile,
    /// Weighted sum of domain scores, before penalties.
    pub base: f64,
    pub penalties: u32,
    pub domains: Vec<DomainScore>,
}

/// Compute the score for `findings` under `profile`.
pub fn score(findings: &[Finding], profile: Profile) -> Score {
    let weights = profile.weights();
    let mut domains = Vec::with_capacity(weights.len());
    let mut base = 0.0;
    let mut penalties = 0u32;

    for &(domain, weight) in weights {
        let in_domain = findings.iter().filter(|f| f.domain == domain);

        let mut checks = 0usize;
        let mut failed = 0usize;
        let mut errored = 0usize;
        let mut deducted = 0.0;

        for f in in_domain {
            match f.status {
                Status::Error => errored += 1,
                Status::Pass => checks += 1,
                Status::Fail => {
                    checks += 1;
                    failed += 1;
                    deducted += deduction(f.severity);
                    penalties += penalty(f.severity);
                }
            }
        }

        let domain_score = (100.0 - deducted).clamp(0.0, 100.0);
        base += weight * domain_score;

        domains.push(DomainScore {
            domain,
            weight,
            score: domain_score.round() as u8,
            checks,
            failed,
            errored,
        });
    }

    let total = (base - f64::from(penalties)).clamp(0.0, 100.0).round() as u8;

    Score {
        total,
        profile,
        base,
        penalties,
        domains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(domain: Domain, severity: Severity, status: Status) -> Finding {
        Finding {
            id: "test",
            domain,
            title: "test",
            severity,
            status,
            detail: String::new(),
            recommendation: "",
        }
    }

    #[test]
    fn profile_weights_sum_to_one() {
        for profile in [Profile::Home, Profile::Corporate] {
            let sum: f64 = profile.weights().iter().map(|&(_, w)| w).sum();
            assert!((sum - 1.0).abs() < 1e-9, "{profile:?} weights sum to {sum}");
        }
    }

    #[test]
    fn parse_profile() {
        assert_eq!(Profile::parse("home"), Some(Profile::Home));
        assert_eq!(Profile::parse("CORPORATE"), Some(Profile::Corporate));
        assert_eq!(Profile::parse("nope"), None);
        assert_eq!(Profile::default(), Profile::Home);
    }

    #[test]
    fn all_pass_is_100() {
        let findings = vec![
            finding(Domain::Firewall, Severity::High, Status::Pass),
            finding(Domain::Auth, Severity::Medium, Status::Pass),
        ];
        assert_eq!(score(&findings, Profile::Home).total, 100);
    }

    #[test]
    fn empty_is_100() {
        assert_eq!(score(&[], Profile::Home).total, 100);
    }

    #[test]
    fn single_high_failure_applies_domain_and_penalty() {
        // Firewall (weight 0.25) with one High fail: domain 70, base = 100 - 0.25*30 = 92.5,
        // minus penalty 8 → 84.5 → 85 (other domains have no findings → score 100).
        let findings = vec![finding(Domain::Firewall, Severity::High, Status::Fail)];
        let s = score(&findings, Profile::Home);
        assert_eq!(s.penalties, 8);
        assert_eq!(s.total, 85);
        let fw = s
            .domains
            .iter()
            .find(|d| d.domain == Domain::Firewall)
            .unwrap();
        assert_eq!(fw.score, 70);
        assert_eq!(fw.failed, 1);
    }

    #[test]
    fn corporate_weights_auth_more_than_home() {
        // A single Medium auth failure costs more under corporate (auth 0.25 vs 0.20).
        let findings = vec![finding(Domain::Auth, Severity::Medium, Status::Fail)];
        let home = score(&findings, Profile::Home).total;
        let corp = score(&findings, Profile::Corporate).total;
        assert_eq!(home, 97);
        assert_eq!(corp, 96);
        assert!(corp < home);
    }

    #[test]
    fn domain_score_clamps_at_zero() {
        let findings = vec![
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::Critical, Status::Fail),
        ];
        let s = score(&findings, Profile::Home);
        let h = s
            .domains
            .iter()
            .find(|d| d.domain == Domain::NetworkHygiene)
            .unwrap();
        assert_eq!(h.score, 0);
    }

    #[test]
    fn errored_checks_do_not_deduct() {
        let findings = vec![finding(Domain::Auth, Severity::Critical, Status::Error)];
        let s = score(&findings, Profile::Home);
        assert_eq!(s.total, 100);
        assert_eq!(s.penalties, 0);
        let a = s.domains.iter().find(|d| d.domain == Domain::Auth).unwrap();
        assert_eq!(a.errored, 1);
        assert_eq!(a.failed, 0);
    }

    #[test]
    fn total_never_below_zero() {
        let findings: Vec<Finding> = [
            Domain::Firewall,
            Domain::Auth,
            Domain::Services,
            Domain::NetworkHygiene,
            Domain::Updates,
            Domain::Logging,
        ]
        .into_iter()
        .flat_map(|d| {
            std::iter::repeat_with(move || finding(d, Severity::Critical, Status::Fail)).take(5)
        })
        .collect();
        assert_eq!(score(&findings, Profile::Home).total, 0);
    }
}
