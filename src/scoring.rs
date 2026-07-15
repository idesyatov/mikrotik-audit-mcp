//! Security scoring: turn findings into a 0–100 score with a per-domain
//! breakdown.
//!
//! `S = clamp( Σ(weight_i × domain_score_i) − penalties, 0, 100 )`
//!
//! Each failed check deducts from its domain's score by severity, and High /
//! Critical failures add a *global* penalty so a single severe issue drags the
//! total even when its domain is lightly weighted (otherwise averaging would
//! dilute it). Checks that errored (command didn't run) are excluded.

use serde::Serialize;

use crate::checks::{Domain, Finding, Severity, Status};

/// Domain weights for the score. Sum to 1.0. Made profile-dependent in Stage 6.
pub type Weights = &'static [(Domain, f64)];

pub const DEFAULT_WEIGHTS: Weights = &[
    (Domain::Firewall, 0.25),
    (Domain::Auth, 0.20),
    (Domain::Services, 0.20),
    (Domain::NetworkHygiene, 0.15),
    (Domain::Updates, 0.10),
    (Domain::Logging, 0.10),
];

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
    /// Weighted sum of domain scores, before penalties.
    pub base: f64,
    pub penalties: u32,
    pub domains: Vec<DomainScore>,
}

/// Compute the score for `findings` under `weights`.
pub fn score(findings: &[Finding], weights: Weights) -> Score {
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
    fn all_pass_is_100() {
        let findings = vec![
            finding(Domain::Firewall, Severity::High, Status::Pass),
            finding(Domain::Auth, Severity::Medium, Status::Pass),
        ];
        assert_eq!(score(&findings, DEFAULT_WEIGHTS).total, 100);
    }

    #[test]
    fn empty_is_100() {
        assert_eq!(score(&[], DEFAULT_WEIGHTS).total, 100);
    }

    #[test]
    fn single_high_failure_applies_domain_and_penalty() {
        // Firewall (weight 0.25) with one High fail: domain 70, base = 100 - 0.25*30 = 92.5,
        // minus penalty 8 → 84.5 → 85 (other domains have no findings → score 100).
        let findings = vec![finding(Domain::Firewall, Severity::High, Status::Fail)];
        let s = score(&findings, DEFAULT_WEIGHTS);
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
    fn domain_score_clamps_at_zero() {
        // Three High fails in one domain: 90 deduction, then a Critical → clamps at 0.
        let findings = vec![
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::High, Status::Fail),
            finding(Domain::NetworkHygiene, Severity::Critical, Status::Fail),
        ];
        let s = score(&findings, DEFAULT_WEIGHTS);
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
        let s = score(&findings, DEFAULT_WEIGHTS);
        assert_eq!(s.total, 100);
        assert_eq!(s.penalties, 0);
        let a = s.domains.iter().find(|d| d.domain == Domain::Auth).unwrap();
        assert_eq!(a.errored, 1);
        assert_eq!(a.failed, 0);
    }

    #[test]
    fn total_never_below_zero() {
        // Pile on failures across domains; total must clamp to 0, not go negative.
        let findings: Vec<Finding> = DEFAULT_WEIGHTS
            .iter()
            .flat_map(|&(d, _)| {
                std::iter::repeat_with(move || finding(d, Severity::Critical, Status::Fail)).take(5)
            })
            .collect();
        assert_eq!(score(&findings, DEFAULT_WEIGHTS).total, 0);
    }
}
