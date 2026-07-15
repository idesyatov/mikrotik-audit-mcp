//! Services-domain checks (`/ip service`).

use super::parse::parse_services;
use super::{Check, Domain, Outcome, Severity};

const SERVICE_CMD: &str = "/ip service print detail";

/// Cleartext / unencrypted management services.
const INSECURE: &[&str] = &["telnet", "ftp", "www", "api"];

/// An unencrypted management service is enabled.
pub struct InsecureServiceEnabled;

impl Check for InsecureServiceEnabled {
    fn id(&self) -> &'static str {
        "services-insecure-enabled"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "Insecure service enabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Disable cleartext services (telnet/ftp/www/api); use ssh and the encrypted (-ssl) variants."
    }
    fn command(&self) -> &'static str {
        SERVICE_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let enabled: Vec<String> = parse_services(output)
            .into_iter()
            .filter(|s| !s.disabled && INSECURE.contains(&s.name.as_str()))
            .map(|s| s.name)
            .collect();
        if enabled.is_empty() {
            Outcome::pass("No cleartext management services enabled.")
        } else {
            Outcome::fail(format!(
                "Enabled cleartext services: {}.",
                enabled.join(", ")
            ))
        }
    }
}

/// Enabled services reachable from any source address.
pub struct ServicesWithoutAddressRestriction;

impl Check for ServicesWithoutAddressRestriction {
    fn id(&self) -> &'static str {
        "services-no-address"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "Services without source-address restriction"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Set `address=` on each enabled service to limit it to management networks."
    }
    fn command(&self) -> &'static str {
        SERVICE_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let open: Vec<String> = parse_services(output)
            .into_iter()
            .filter(|s| !s.disabled && s.address.trim().is_empty())
            .map(|s| s.name)
            .collect();
        if open.is_empty() {
            Outcome::pass("All enabled services are address-restricted.")
        } else {
            Outcome::fail(format!(
                "Services reachable from any address: {}.",
                open.join(", ")
            ))
        }
    }
}

/// SSH is served on the default port 22.
pub struct SshOnDefaultPort;

impl Check for SshOnDefaultPort {
    fn id(&self) -> &'static str {
        "services-ssh-default-port"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "SSH on the default port"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Move SSH off port 22 to reduce automated scanning noise (defence in depth, not a substitute for access control)."
    }
    fn command(&self) -> &'static str {
        SERVICE_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let on_default = parse_services(output)
            .into_iter()
            .any(|s| s.name == "ssh" && !s.disabled && s.port == Some(22));
        if on_default {
            Outcome::fail("SSH is enabled on the default port 22.")
        } else {
            Outcome::pass("SSH is not on the default port (or is disabled).")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    const VULNERABLE: &str = r#"Flags: X - disabled, I - invalid
 0     name="telnet" port=23 address=""
 1     name="ftp" port=21 address=""
 2     name="www" port=80 address=""
 3     name="ssh" port=22 address=""
"#;

    const HARDENED: &str = r#"Flags: X - disabled, I - invalid
 0   X name="telnet" port=23 address=""
 1   X name="ftp" port=21 address=""
 2   X name="www" port=80 address=""
 3     name="ssh" port=2222 address="192.168.88.0/24"
"#;

    #[test]
    fn insecure_services_flagged() {
        assert_eq!(
            InsecureServiceEnabled.evaluate(VULNERABLE).status,
            Status::Fail
        );
        assert_eq!(
            InsecureServiceEnabled.evaluate(HARDENED).status,
            Status::Pass
        );
    }

    #[test]
    fn open_services_flagged() {
        assert_eq!(
            ServicesWithoutAddressRestriction
                .evaluate(VULNERABLE)
                .status,
            Status::Fail
        );
        assert_eq!(
            ServicesWithoutAddressRestriction.evaluate(HARDENED).status,
            Status::Pass
        );
    }

    #[test]
    fn ssh_default_port_flagged() {
        assert_eq!(SshOnDefaultPort.evaluate(VULNERABLE).status, Status::Fail);
        assert_eq!(SshOnDefaultPort.evaluate(HARDENED).status, Status::Pass);
    }
}
