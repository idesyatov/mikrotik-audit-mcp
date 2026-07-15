//! Updates-domain checks.

use super::parse::parse_settings;
use super::{Check, Domain, Outcome, Severity};

/// The RouterOS update channel is not a stable one.
pub struct StableReleaseChannel;

impl Check for StableReleaseChannel {
    fn id(&self) -> &'static str {
        "updates-stable-channel"
    }
    fn domain(&self) -> Domain {
        Domain::Updates
    }
    fn title(&self) -> &'static str {
        "Non-stable release channel"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Use the `stable` (or `long-term`) channel: /system package update set channel=stable."
    }
    fn command(&self) -> &'static str {
        "/system package update print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        match parse_settings(output).get("channel").map(String::as_str) {
            Some("stable") | Some("long-term") => Outcome::pass("Update channel is stable."),
            Some(other) => Outcome::fail(format!("Update channel is '{other}', not stable.")),
            None => Outcome::pass("No update channel reported."),
        }
    }
}

/// The RouterBOARD firmware is behind the version bundled with RouterOS.
pub struct RouterboardFirmwareCurrent;

impl Check for RouterboardFirmwareCurrent {
    fn id(&self) -> &'static str {
        "updates-routerboard-firmware"
    }
    fn domain(&self) -> Domain {
        Domain::Updates
    }
    fn title(&self) -> &'static str {
        "RouterBOARD firmware outdated"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Upgrade the bootloader: /system routerboard upgrade, then reboot."
    }
    fn command(&self) -> &'static str {
        "/system routerboard print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let s = parse_settings(output);
        // Non-RouterBOARD platforms (CHR/x86) don't have firmware to update.
        if s.get("routerboard").map(String::as_str) == Some("no") {
            return Outcome::pass("Not a RouterBOARD device; no firmware to update.");
        }
        match (s.get("current-firmware"), s.get("upgrade-firmware")) {
            (Some(cur), Some(up)) if cur != up => {
                Outcome::fail(format!("Firmware {cur} is behind the available {up}."))
            }
            _ => Outcome::pass("RouterBOARD firmware is current."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn channel_flagged() {
        assert_eq!(
            StableReleaseChannel.evaluate("channel: stable\n").status,
            Status::Pass
        );
        assert_eq!(
            StableReleaseChannel
                .evaluate("channel: development\n")
                .status,
            Status::Fail
        );
    }

    #[test]
    fn firmware_flagged() {
        let outdated = "routerboard: yes\ncurrent-firmware: 7.14\nupgrade-firmware: 7.15.3\n";
        let current = "routerboard: yes\ncurrent-firmware: 7.15.3\nupgrade-firmware: 7.15.3\n";
        assert_eq!(
            RouterboardFirmwareCurrent.evaluate(outdated).status,
            Status::Fail
        );
        assert_eq!(
            RouterboardFirmwareCurrent.evaluate(current).status,
            Status::Pass
        );
        assert_eq!(
            RouterboardFirmwareCurrent
                .evaluate("routerboard: no\n")
                .status,
            Status::Pass
        );
    }
}
