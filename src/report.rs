//! Rendering of an audit result, shared by the MCP tool and the CLI.

use serde::Serialize;

use crate::checks::{Finding, Status};
use crate::scoring::Score;

/// Human-readable summary: the score line plus one line per failed check.
pub fn text(target: &str, score: &Score, findings: &[Finding]) -> String {
    let count = |s: Status| findings.iter().filter(|f| f.status == s).count();
    let mut out = format!(
        "Audit of {:?} [{:?} profile]: score {}/100 — {} passed, {} failed, {} errored (of {} checks).\n",
        target,
        score.profile,
        score.total,
        count(Status::Pass),
        count(Status::Fail),
        count(Status::Error),
        findings.len()
    );
    for f in findings.iter().filter(|f| f.status == Status::Fail) {
        out.push_str(&format!(
            "- [{:?}] {} ({}): {}\n",
            f.severity, f.title, f.id, f.detail
        ));
    }
    out
}

#[derive(Serialize)]
struct Report<'a> {
    target: &'a str,
    score: &'a Score,
    findings: &'a [Finding],
}

/// Machine-readable `{ target, score, findings }`.
pub fn json(
    target: &str,
    score: &Score,
    findings: &[Finding],
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&Report {
        target,
        score,
        findings,
    })
}
