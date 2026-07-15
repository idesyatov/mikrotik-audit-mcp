//! Tolerant parsers for RouterOS output (targeting RouterOS 7).
//!
//! Pure functions over text captured via SSH, so checks are unit-tested against
//! fixtures without a device (and feed Stage 8 evals). Two shapes appear:
//!   - list rows (`name="x" port=23`) — [`parse_services`], [`parse_users`],
//!     [`parse_firewall_rules`], [`parse_kv_lines`] (from `print terse`);
//!   - settings (`allow-remote-requests: no`) — [`parse_settings`].

use std::collections::HashMap;

/// One `/ip service` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub disabled: bool,
    pub port: Option<u16>,
    pub address: String,
}

/// One `/user` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub disabled: bool,
    pub group: String,
    pub address: String,
}

/// One `/ip firewall filter` rule (from `print terse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub chain: String,
    pub action: String,
    pub connection_state: String,
    pub disabled: bool,
}

/// Extract `key=value` from a line: quoted (`key="v"`) or bare (`key=v`).
fn field(line: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let idx = line.find(&pat)?;
    let rest = &line[idx + pat.len()..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

/// A RouterOS row is "disabled" when its flag column (before `anchor`) has `X`.
fn is_disabled(line: &str, anchor: usize) -> bool {
    line[..anchor].split_whitespace().any(|t| t == "X")
}

pub fn parse_services(output: &str) -> Vec<Service> {
    output
        .lines()
        .filter_map(|line| {
            let name_idx = line.find("name=")?;
            Some(Service {
                name: field(line, "name")?,
                disabled: is_disabled(line, name_idx),
                port: field(line, "port").and_then(|p| p.parse().ok()),
                address: field(line, "address").unwrap_or_default(),
            })
        })
        .collect()
}

pub fn parse_users(output: &str) -> Vec<User> {
    output
        .lines()
        .filter_map(|line| {
            let name_idx = line.find("name=")?;
            Some(User {
                name: field(line, "name")?,
                disabled: is_disabled(line, name_idx),
                group: field(line, "group").unwrap_or_default(),
                address: field(line, "address").unwrap_or_default(),
            })
        })
        .collect()
}

pub fn parse_firewall_rules(output: &str) -> Vec<FirewallRule> {
    output
        .lines()
        .filter_map(|line| {
            let chain_idx = line.find("chain=")?;
            Some(FirewallRule {
                chain: field(line, "chain")?,
                action: field(line, "action").unwrap_or_default(),
                connection_state: field(line, "connection-state").unwrap_or_default(),
                disabled: is_disabled(line, chain_idx),
            })
        })
        .collect()
}

/// Collect the value of `key` from every line that has it (list output).
pub fn parse_kv_lines(output: &str, key: &str) -> Vec<String> {
    output.lines().filter_map(|line| field(line, key)).collect()
}

/// Parse `key: value` settings output into a lowercased-key map.
pub fn parse_settings(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        map.insert(key.to_ascii_lowercase(), v.trim().to_string());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICES: &str = r#"Flags: X - disabled, I - invalid
 0   X name="telnet" port=23 address=""
 1     name="ftp" port=21 address=""
 2     name="www" port=80 address=""
 3     name="ssh" port=22 address="192.168.88.0/24"
 4   X name="www-ssl" port=443 address=""
 5     name="winbox" port=8291 address=""
"#;

    const USERS: &str = r#"Flags: X - disabled
 0   name="admin" group=full address=""
 1   name="auditor" group=read address="192.168.88.0/24"
"#;

    const FIREWALL: &str = r#" 0 chain=input action=accept connection-state=established,related
 1 chain=input action=drop connection-state=invalid
 2 X chain=input action=accept protocol=icmp
 3 chain=input action=drop
"#;

    const DNS_SETTINGS: &str = r#"                          servers: 8.8.8.8
            allow-remote-requests: no
               max-udp-packet-size: 4096
"#;

    #[test]
    fn parses_services() {
        let svc = parse_services(SERVICES);
        assert_eq!(svc.len(), 6);
        let ssh = svc.iter().find(|s| s.name == "ssh").unwrap();
        assert!(!ssh.disabled);
        assert_eq!(ssh.port, Some(22));
        assert_eq!(ssh.address, "192.168.88.0/24");
        assert!(svc.iter().find(|s| s.name == "telnet").unwrap().disabled);
    }

    #[test]
    fn parses_users() {
        let users = parse_users(USERS);
        assert_eq!(users.len(), 2);
        assert_eq!(
            users.iter().find(|u| u.name == "admin").unwrap().address,
            ""
        );
    }

    #[test]
    fn parses_firewall_rules() {
        let rules = parse_firewall_rules(FIREWALL);
        assert_eq!(rules.len(), 4);
        assert!(rules
            .iter()
            .any(|r| r.chain == "input" && r.action == "drop" && r.connection_state == "invalid"));
        // The icmp accept rule is disabled.
        assert!(rules.iter().any(|r| r.disabled));
    }

    #[test]
    fn parses_kv_lines() {
        let targets = parse_kv_lines(
            " 0 name=\"memory\" target=memory\n 1 name=\"remote\" target=remote\n",
            "target",
        );
        assert_eq!(targets, vec!["memory".to_string(), "remote".to_string()]);
    }

    #[test]
    fn parses_settings() {
        let s = parse_settings(DNS_SETTINGS);
        assert_eq!(
            s.get("allow-remote-requests").map(String::as_str),
            Some("no")
        );
        assert_eq!(s.get("servers").map(String::as_str), Some("8.8.8.8"));
    }
}
