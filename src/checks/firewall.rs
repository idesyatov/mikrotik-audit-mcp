//! Firewall-domain checks (`/ip firewall filter`).
//!
//! Best-effort structural checks: a device with no input rules is wide open, a
//! missing default-drop leaves input default-accept, and a missing invalid-drop
//! lets malformed conntrack traffic through. Deeper rule-order analysis is out
//! of scope here.

use super::parse::parse_firewall_rules;
use super::{Check, Domain, Outcome, Severity};

const FILTER_CMD: &str = "/ip firewall filter print terse";

fn enabled_input_rules(output: &str) -> Vec<super::parse::FirewallRule> {
    parse_firewall_rules(output)
        .into_iter()
        .filter(|r| !r.disabled && r.chain == "input")
        .collect()
}

/// The input chain has no rules at all (factory-open device).
pub struct InputChainHasRules;

impl Check for InputChainHasRules {
    fn id(&self) -> &'static str {
        "firewall-input-has-rules"
    }
    fn domain(&self) -> Domain {
        Domain::Firewall
    }
    fn title(&self) -> &'static str {
        "Input chain has no firewall rules"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Add an input firewall policy (accept established/related, drop invalid, then drop)."
    }
    fn command(&self) -> &'static str {
        FILTER_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if enabled_input_rules(output).is_empty() {
            Outcome::fail("The input chain has no enabled rules; the router is unprotected.")
        } else {
            Outcome::pass("The input chain has firewall rules.")
        }
    }
}

/// The input chain has no catch-all drop (default-accept remains).
pub struct InputDefaultDrop;

impl Check for InputDefaultDrop {
    fn id(&self) -> &'static str {
        "firewall-input-default-drop"
    }
    fn domain(&self) -> Domain {
        Domain::Firewall
    }
    fn title(&self) -> &'static str {
        "Input chain lacks a default-drop"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "End the input chain with a catch-all `action=drop` so the policy is deny-by-default."
    }
    fn command(&self) -> &'static str {
        FILTER_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let has_drop = enabled_input_rules(output)
            .iter()
            .any(|r| r.action == "drop" || r.action == "reject");
        if has_drop {
            Outcome::pass("The input chain has a drop/reject rule.")
        } else {
            Outcome::fail("The input chain has no drop/reject rule; default policy is accept.")
        }
    }
}

/// The input chain does not drop invalid connections.
pub struct InputDropsInvalid;

impl Check for InputDropsInvalid {
    fn id(&self) -> &'static str {
        "firewall-input-drop-invalid"
    }
    fn domain(&self) -> Domain {
        Domain::Firewall
    }
    fn title(&self) -> &'static str {
        "Input chain does not drop invalid connections"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Add `/ip firewall filter add chain=input connection-state=invalid action=drop`."
    }
    fn command(&self) -> &'static str {
        FILTER_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let drops_invalid = enabled_input_rules(output)
            .iter()
            .any(|r| r.action == "drop" && r.connection_state.contains("invalid"));
        if drops_invalid {
            Outcome::pass("The input chain drops invalid connections.")
        } else {
            Outcome::fail("No rule drops connection-state=invalid on input.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    const HARDENED: &str = r#" 0 chain=input action=accept connection-state=established,related
 1 chain=input action=drop connection-state=invalid
 2 chain=input action=accept protocol=icmp
 3 chain=input action=drop
"#;

    const OPEN: &str = r#" 0 chain=forward action=accept
"#;

    const NO_INVALID: &str = r#" 0 chain=input action=accept connection-state=established,related
 1 chain=input action=drop
"#;

    #[test]
    fn detects_empty_input_chain() {
        assert_eq!(InputChainHasRules.evaluate(OPEN).status, Status::Fail);
        assert_eq!(InputChainHasRules.evaluate(HARDENED).status, Status::Pass);
    }

    #[test]
    fn detects_missing_default_drop() {
        assert_eq!(InputDefaultDrop.evaluate(OPEN).status, Status::Fail);
        assert_eq!(InputDefaultDrop.evaluate(HARDENED).status, Status::Pass);
    }

    #[test]
    fn detects_missing_invalid_drop() {
        assert_eq!(InputDropsInvalid.evaluate(NO_INVALID).status, Status::Fail);
        assert_eq!(InputDropsInvalid.evaluate(HARDENED).status, Status::Pass);
    }
}
