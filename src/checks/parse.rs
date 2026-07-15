//! Tolerant parsers for RouterOS `print detail` output.
//!
//! These operate on plain text captured over SSH and are pure, so checks built
//! on them are unit-tested against fixtures without a device (and feed Stage 8
//! evals). The assumed shape is the `print detail` form:
//!
//! ```text
//! Flags: X - disabled, I - invalid
//!  0   X name="telnet" port=23 address=""
//!  1     name="ssh" port=22 address="192.168.88.0/24"
//! ```

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

/// A RouterOS row is "disabled" when its flag column (before `name=`) has `X`.
fn is_disabled(line: &str, name_idx: usize) -> bool {
    line[..name_idx].split_whitespace().any(|t| t == "X")
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

    #[test]
    fn parses_services() {
        let svc = parse_services(SERVICES);
        assert_eq!(svc.len(), 6);

        let telnet = svc.iter().find(|s| s.name == "telnet").unwrap();
        assert!(telnet.disabled);
        assert_eq!(telnet.port, Some(23));

        let ssh = svc.iter().find(|s| s.name == "ssh").unwrap();
        assert!(!ssh.disabled);
        assert_eq!(ssh.port, Some(22));
        assert_eq!(ssh.address, "192.168.88.0/24");

        let www = svc.iter().find(|s| s.name == "www").unwrap();
        assert!(!www.disabled);
        assert_eq!(www.address, "");
    }

    #[test]
    fn parses_users() {
        let users = parse_users(USERS);
        assert_eq!(users.len(), 2);

        let admin = users.iter().find(|u| u.name == "admin").unwrap();
        assert_eq!(admin.group, "full");
        assert_eq!(admin.address, "");

        let auditor = users.iter().find(|u| u.name == "auditor").unwrap();
        assert_eq!(auditor.address, "192.168.88.0/24");
    }
}
