//! Network-hygiene checks: discovery, mac-access, open resolver, UPnP, RoMON.

use super::parse::parse_settings;
use super::{Check, Domain, Outcome, Severity};

/// `true` if a settings key equals `want` (case-insensitive).
fn setting_is(output: &str, key: &str, want: &str) -> bool {
    parse_settings(output)
        .get(key)
        .is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// Neighbor discovery runs on every interface (`discover-interface-list=all`).
pub struct NeighborDiscoveryRestricted;

impl Check for NeighborDiscoveryRestricted {
    fn id(&self) -> &'static str {
        "hygiene-neighbor-discovery"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "Neighbor discovery on all interfaces"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Limit discovery to management interfaces: /ip neighbor discovery-settings set discover-interface-list=<mgmt>."
    }
    fn command(&self) -> &'static str {
        "/ip neighbor discovery-settings print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "discover-interface-list", "all") {
            Outcome::fail("Neighbor discovery is enabled on all interfaces.")
        } else {
            Outcome::pass("Neighbor discovery is restricted.")
        }
    }
}

/// The UDP/TCP bandwidth-test server is enabled.
pub struct BandwidthServerDisabled;

impl Check for BandwidthServerDisabled {
    fn id(&self) -> &'static str {
        "hygiene-bandwidth-server"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "Bandwidth-test server enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Disable it: /tool bandwidth-server set enabled=no."
    }
    fn command(&self) -> &'static str {
        "/tool bandwidth-server print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "enabled", "yes") {
            Outcome::fail("The bandwidth-test server is enabled.")
        } else {
            Outcome::pass("The bandwidth-test server is disabled.")
        }
    }
}

/// Telnet-over-MAC (`mac-server`) is reachable on all interfaces.
pub struct MacServerRestricted;

impl Check for MacServerRestricted {
    fn id(&self) -> &'static str {
        "hygiene-mac-server"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "MAC-server on all interfaces"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Restrict or disable it: /tool mac-server set allowed-interface-list=none."
    }
    fn command(&self) -> &'static str {
        "/tool mac-server print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "allowed-interface-list", "all") {
            Outcome::fail("MAC-server (telnet over MAC) is allowed on all interfaces.")
        } else {
            Outcome::pass("MAC-server is restricted.")
        }
    }
}

/// MAC-Winbox is reachable on all interfaces.
pub struct MacWinboxRestricted;

impl Check for MacWinboxRestricted {
    fn id(&self) -> &'static str {
        "hygiene-mac-winbox"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "MAC-Winbox on all interfaces"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Restrict it: /tool mac-server mac-winbox set allowed-interface-list=<mgmt>."
    }
    fn command(&self) -> &'static str {
        "/tool mac-server mac-winbox print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "allowed-interface-list", "all") {
            Outcome::fail("MAC-Winbox is allowed on all interfaces.")
        } else {
            Outcome::pass("MAC-Winbox is restricted.")
        }
    }
}

/// The router answers DNS for anyone (`allow-remote-requests=yes`).
pub struct DnsNotOpenResolver;

impl Check for DnsNotOpenResolver {
    fn id(&self) -> &'static str {
        "hygiene-dns-open-resolver"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "DNS answers remote requests"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Set allow-remote-requests=no, or restrict UDP/TCP 53 on input to trusted networks."
    }
    fn command(&self) -> &'static str {
        "/ip dns print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "allow-remote-requests", "yes") {
            Outcome::fail("DNS allow-remote-requests is enabled (possible open resolver).")
        } else {
            Outcome::pass("DNS does not answer remote requests.")
        }
    }
}

/// UPnP is enabled (auto port-forwarding from the LAN).
pub struct UpnpDisabled;

impl Check for UpnpDisabled {
    fn id(&self) -> &'static str {
        "hygiene-upnp"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "UPnP enabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Disable it unless required: /ip upnp set enabled=no."
    }
    fn command(&self) -> &'static str {
        "/ip upnp print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "enabled", "yes") {
            Outcome::fail("UPnP is enabled (LAN hosts can open port forwards).")
        } else {
            Outcome::pass("UPnP is disabled.")
        }
    }
}

/// RoMON (layer-2 management overlay) is enabled.
pub struct RomonDisabled;

impl Check for RomonDisabled {
    fn id(&self) -> &'static str {
        "hygiene-romon"
    }
    fn domain(&self) -> Domain {
        Domain::NetworkHygiene
    }
    fn title(&self) -> &'static str {
        "RoMON enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Disable it unless used: /tool romon set enabled=no."
    }
    fn command(&self) -> &'static str {
        "/tool romon print"
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if setting_is(output, "enabled", "yes") {
            Outcome::fail("RoMON is enabled.")
        } else {
            Outcome::pass("RoMON is disabled.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn enabled_flag_checks() {
        assert_eq!(
            BandwidthServerDisabled.evaluate("enabled: yes\n").status,
            Status::Fail
        );
        assert_eq!(
            BandwidthServerDisabled.evaluate("enabled: no\n").status,
            Status::Pass
        );
        assert_eq!(UpnpDisabled.evaluate("enabled: yes\n").status, Status::Fail);
        assert_eq!(RomonDisabled.evaluate("enabled: no\n").status, Status::Pass);
    }

    #[test]
    fn interface_list_checks() {
        assert_eq!(
            NeighborDiscoveryRestricted
                .evaluate("discover-interface-list: all\n")
                .status,
            Status::Fail
        );
        assert_eq!(
            NeighborDiscoveryRestricted
                .evaluate("discover-interface-list: none\n")
                .status,
            Status::Pass
        );
        assert_eq!(
            MacServerRestricted
                .evaluate("allowed-interface-list: all\n")
                .status,
            Status::Fail
        );
        assert_eq!(
            MacWinboxRestricted
                .evaluate("allowed-interface-list: mgmt\n")
                .status,
            Status::Pass
        );
    }

    #[test]
    fn dns_open_resolver_flagged() {
        assert_eq!(
            DnsNotOpenResolver
                .evaluate("allow-remote-requests: yes\n")
                .status,
            Status::Fail
        );
        assert_eq!(
            DnsNotOpenResolver
                .evaluate("allow-remote-requests: no\n")
                .status,
            Status::Pass
        );
    }
}
