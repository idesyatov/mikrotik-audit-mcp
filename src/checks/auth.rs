//! Authentication-domain checks.

use super::parse::parse_users;
use super::{Check, Domain, Outcome, Severity};

const USER_CMD: &str = "/user print detail";

/// The built-in `admin` account still exists and is enabled.
pub struct DefaultAdminUser;

impl Check for DefaultAdminUser {
    fn id(&self) -> &'static str {
        "auth-default-admin"
    }
    fn domain(&self) -> Domain {
        Domain::Auth
    }
    fn title(&self) -> &'static str {
        "Default 'admin' user present"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Create a dedicated administrative account, then remove or rename the default 'admin' user."
    }
    fn command(&self) -> &'static str {
        USER_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let admin_enabled = parse_users(output)
            .into_iter()
            .any(|u| u.name == "admin" && !u.disabled);
        if admin_enabled {
            Outcome::fail("The default 'admin' user exists and is enabled.")
        } else {
            Outcome::pass("No enabled default 'admin' user.")
        }
    }
}

/// Users that may log in from any source address (no `address=` restriction).
pub struct UsersWithoutAddressRestriction;

impl Check for UsersWithoutAddressRestriction {
    fn id(&self) -> &'static str {
        "auth-user-no-address"
    }
    fn domain(&self) -> Domain {
        Domain::Auth
    }
    fn title(&self) -> &'static str {
        "Users without source-address restriction"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Restrict each user with an `address=` allow-list of management networks."
    }
    fn command(&self) -> &'static str {
        USER_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let open: Vec<String> = parse_users(output)
            .into_iter()
            .filter(|u| !u.disabled && u.address.trim().is_empty())
            .map(|u| u.name)
            .collect();
        if open.is_empty() {
            Outcome::pass("All enabled users are address-restricted.")
        } else {
            Outcome::fail(format!(
                "Users reachable from any address: {}.",
                open.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    const OPEN_ADMIN: &str = r#"Flags: X - disabled
 0   name="admin" group=full address=""
 1   name="auditor" group=read address="192.168.88.0/24"
"#;

    const HARDENED: &str = r#"Flags: X - disabled
 0 X name="admin" group=full address=""
 1   name="auditor" group=full address="192.168.88.0/24"
"#;

    #[test]
    fn default_admin_flagged_when_enabled() {
        assert_eq!(DefaultAdminUser.evaluate(OPEN_ADMIN).status, Status::Fail);
        // Disabled admin is acceptable.
        assert_eq!(DefaultAdminUser.evaluate(HARDENED).status, Status::Pass);
    }

    #[test]
    fn open_users_flagged() {
        assert_eq!(
            UsersWithoutAddressRestriction.evaluate(OPEN_ADMIN).status,
            Status::Fail
        );
        assert_eq!(
            UsersWithoutAddressRestriction.evaluate(HARDENED).status,
            Status::Pass
        );
    }
}
