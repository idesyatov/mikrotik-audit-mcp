//! Audit engine: run each check's command once (cached), then evaluate.

use std::collections::HashMap;

use crate::checks::{all_checks, Finding, Status};
use crate::ssh::{SshConfig, SshError};

/// Run every check against `ssh` and collect findings.
///
/// Device-level failures (auth, connection, timeout) abort the whole audit.
/// A per-command remote failure (ssh connected but the command errored) is
/// recorded as an `Error` finding for the checks that needed it; the rest run.
pub async fn run_audit(ssh: &SshConfig) -> Result<Vec<Finding>, SshError> {
    let checks = all_checks();

    // Snap each distinct command exactly once.
    let mut outputs: HashMap<&'static str, Result<String, String>> = HashMap::new();
    for check in &checks {
        let cmd = check.command();
        if outputs.contains_key(cmd) {
            continue;
        }
        match ssh.run(cmd).await {
            Ok(out) => {
                outputs.insert(cmd, Ok(out.stdout));
            }
            Err(SshError::RemoteCommand { code, stderr }) => {
                outputs.insert(
                    cmd,
                    Err(format!("remote command failed (code {code:?}): {stderr}")),
                );
            }
            Err(device_level) => return Err(device_level),
        }
    }

    let findings = checks
        .iter()
        .map(|check| match &outputs[check.command()] {
            Ok(output) => {
                let outcome = check.evaluate(output);
                Finding {
                    id: check.id(),
                    domain: check.domain(),
                    title: check.title(),
                    severity: check.severity(),
                    status: outcome.status,
                    detail: outcome.detail,
                    recommendation: check.recommendation(),
                }
            }
            Err(err) => Finding {
                id: check.id(),
                domain: check.domain(),
                title: check.title(),
                severity: check.severity(),
                status: Status::Error,
                detail: err.clone(),
                recommendation: check.recommendation(),
            },
        })
        .collect();

    Ok(findings)
}
