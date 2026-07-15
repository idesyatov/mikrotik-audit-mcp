//! Logging-domain checks.

use super::parse::parse_kv_lines;
use super::{Check, Domain, Outcome, Severity};

/// No logging action ships logs to a remote syslog target.
pub struct RemoteLoggingConfigured;

impl Check for RemoteLoggingConfigured {
    fn id(&self) -> &'static str {
        "logging-remote-configured"
    }
    fn domain(&self) -> Domain {
        Domain::Logging
    }
    fn title(&self) -> &'static str {
        "No remote logging configured"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Ship logs off-box: add a logging action with target=remote and a syslog server."
    }
    fn command(&self) -> &'static str {
        "/system logging action print terse"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if parse_kv_lines(output, "target")
            .iter()
            .any(|t| t == "remote")
        {
            Outcome::pass("A remote logging action is configured.")
        } else {
            Outcome::fail("No logging action targets a remote syslog server.")
        }
    }
}

/// Security-relevant topics are not being logged.
pub struct CriticalTopicsLogged;

impl Check for CriticalTopicsLogged {
    fn id(&self) -> &'static str {
        "logging-critical-topics"
    }
    fn domain(&self) -> Domain {
        Domain::Logging
    }
    fn title(&self) -> &'static str {
        "Critical topics not logged"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Add logging rules for the `error`, `critical` and `warning` topics."
    }
    fn command(&self) -> &'static str {
        "/system logging print terse"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let logged = parse_kv_lines(output, "topics").join(",");
        if ["critical", "error", "warning"]
            .iter()
            .any(|t| logged.contains(t))
        {
            Outcome::pass("Security-relevant topics are logged.")
        } else {
            Outcome::fail("No rules log error/critical/warning topics.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn remote_logging_flagged() {
        let with_remote =
            " 0 name=\"memory\" target=memory\n 1 name=\"papertrail\" target=remote\n";
        let without = " 0 name=\"memory\" target=memory\n 1 name=\"disk\" target=disk\n";
        assert_eq!(
            RemoteLoggingConfigured.evaluate(with_remote).status,
            Status::Pass
        );
        assert_eq!(
            RemoteLoggingConfigured.evaluate(without).status,
            Status::Fail
        );
    }

    #[test]
    fn critical_topics_flagged() {
        let good = " 0 topics=info action=memory\n 1 topics=error,critical action=memory\n";
        let bad = " 0 topics=info action=memory\n";
        assert_eq!(CriticalTopicsLogged.evaluate(good).status, Status::Pass);
        assert_eq!(CriticalTopicsLogged.evaluate(bad).status, Status::Fail);
    }
}
