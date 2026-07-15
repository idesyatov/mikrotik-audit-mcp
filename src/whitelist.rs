//! Read-only command whitelist for MikroTik RouterOS.
//!
//! This is the core of the read-only guarantee: every command sent to a device
//! is validated here first. Anything that could modify configuration — or chain
//! / inject a second command — is rejected before it ever leaves the process.
//!
//! The design is deliberately conservative (deny by default):
//!   1. a positive character set, so shell/CLI metacharacters that could chain
//!      or inject a command (`; & | ` $ < > " ' ( )` …) can never appear;
//!   2. the command must be absolute (start with `/`);
//!   3. no configuration-changing verb may appear anywhere;
//!   4. no `file=` argument (that would write a file on the device);
//!   5. at least one read-only action (`print`/`export`/`monitor`/`get`).
//!
//! Wired into an MCP tool in Stage 3.
#![allow(dead_code)]

use std::error::Error;
use std::fmt;

/// Read-only RouterOS actions the auditor is allowed to invoke.
const READONLY_ACTIONS: &[&str] = &["print", "export", "monitor", "monitor-traffic", "get"];

/// Configuration-changing (or otherwise stateful) verbs. Any of these anywhere
/// in the command is a hard reject.
const WRITE_VERBS: &[&str] = &[
    "add",
    "set",
    "remove",
    "unset",
    "enable",
    "disable",
    "move",
    "reset",
    "reset-configuration",
    "import",
    "edit",
    "comment",
    "make-static",
    "upgrade",
    "downgrade",
    "install",
    "reboot",
    "shutdown",
    "run",
    "start",
    "stop",
    "restart",
    "create",
    "delete",
    "clear",
    "flush",
    "release",
    "renew",
    "generate-key",
    "sign",
    "revoke",
    "deauthorize",
];

/// Characters permitted in a command. A positive character set (not a denylist)
/// guarantees no metacharacter that could chain or inject a command can appear.
fn is_allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " /-_.=,:@".contains(c)
}

#[derive(Debug, PartialEq, Eq)]
pub enum WhitelistError {
    /// The command is empty.
    Empty,
    /// A character outside the permitted set was found.
    IllegalCharacter(char),
    /// The command does not start with `/`.
    NotAbsolute,
    /// A configuration-changing verb was found.
    ForbiddenVerb(String),
    /// A `file=` argument was found (would write a file on the device).
    WritesToFile,
    /// No read-only action (`print`/`export`/`monitor`/`get`) was found.
    NotReadOnly,
}

impl fmt::Display for WhitelistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty command"),
            Self::IllegalCharacter(c) => write!(f, "illegal character {c:?} in command"),
            Self::NotAbsolute => write!(f, "command must start with '/'"),
            Self::ForbiddenVerb(v) => write!(f, "forbidden configuration verb {v:?}"),
            Self::WritesToFile => write!(f, "'file=' would write to the device; not read-only"),
            Self::NotReadOnly => write!(f, "no read-only action (print/export/monitor/get)"),
        }
    }
}

impl Error for WhitelistError {}

/// Validate that `command` is a read-only RouterOS command safe to send.
pub fn validate(command: &str) -> Result<(), WhitelistError> {
    let cmd = command.trim();
    if cmd.is_empty() {
        return Err(WhitelistError::Empty);
    }
    if let Some(c) = cmd.chars().find(|c| !is_allowed_char(*c)) {
        return Err(WhitelistError::IllegalCharacter(c));
    }
    if !cmd.starts_with('/') {
        return Err(WhitelistError::NotAbsolute);
    }

    // No token may write to a file (`file=…`) — that mutates device storage.
    if cmd
        .split_whitespace()
        .any(|t| t.to_ascii_lowercase().starts_with("file="))
    {
        return Err(WhitelistError::WritesToFile);
    }

    // Words: split on whitespace and '/' so both `/ip firewall filter print`
    // and `/ip/firewall/filter/print` are inspected the same way.
    let words: Vec<String> = cmd
        .split(|c: char| c.is_whitespace() || c == '/')
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect();

    if let Some(verb) = words.iter().find(|w| WRITE_VERBS.contains(&w.as_str())) {
        return Err(WhitelistError::ForbiddenVerb(verb.clone()));
    }
    if !words.iter().any(|w| READONLY_ACTIONS.contains(&w.as_str())) {
        return Err(WhitelistError::NotReadOnly);
    }

    Ok(())
}

/// Convenience predicate: `true` iff [`validate`] accepts `command`.
pub fn is_allowed(command: &str) -> bool {
    validate(command).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_common_readonly_commands() {
        for cmd in [
            "/system resource print",
            "/ip firewall filter print",
            "/ip firewall filter print detail where action=drop",
            "/ip service print",
            "/user print",
            "/log print",
            "/export",
            "/system resource get",
            "/interface monitor-traffic ether1 once",
            "/ip/firewall/filter/print",  // slash-separated form
            "  /system resource print  ", // surrounding whitespace is trimmed
        ] {
            assert!(is_allowed(cmd), "should allow: {cmd}");
        }
    }

    #[test]
    fn rejects_write_verbs() {
        for (cmd, verb) in [
            ("/ip firewall filter add chain=input action=drop", "add"),
            ("/ip service set telnet disabled=yes", "set"),
            ("/user remove admin", "remove"),
            ("/system reboot", "reboot"),
            ("/system reset-configuration", "reset-configuration"),
            ("/system script run cleanup", "run"),
        ] {
            assert_eq!(
                validate(cmd),
                Err(WhitelistError::ForbiddenVerb(verb.to_string())),
                "cmd: {cmd}"
            );
        }
    }

    #[test]
    fn rejects_command_chaining_and_injection() {
        for cmd in [
            "/ip firewall filter print; /user add name=x",
            "/interface print && reboot",
            "/log print | cat",
            "/system resource print `id`",
            "/system resource print $(id)",
            "/export > /file",
            "/log print \"topics=error\"",
        ] {
            assert!(
                matches!(validate(cmd), Err(WhitelistError::IllegalCharacter(_))),
                "should reject via charset: {cmd}"
            );
        }
    }

    #[test]
    fn rejects_file_writes() {
        assert_eq!(
            validate("/export file=backup"),
            Err(WhitelistError::WritesToFile)
        );
        assert_eq!(
            validate("/log print file=log"),
            Err(WhitelistError::WritesToFile)
        );
    }

    #[test]
    fn rejects_non_absolute_and_empty() {
        assert_eq!(validate(""), Err(WhitelistError::Empty));
        assert_eq!(validate("   "), Err(WhitelistError::Empty));
        assert_eq!(
            validate("system resource print"),
            Err(WhitelistError::NotAbsolute)
        );
    }

    #[test]
    fn rejects_commands_without_readonly_action() {
        // No print/export/monitor/get and no forbidden verb — still denied.
        assert_eq!(validate("/ping 8.8.8.8"), Err(WhitelistError::NotReadOnly));
        assert_eq!(
            validate("/system identity"),
            Err(WhitelistError::NotReadOnly)
        );
    }
}
