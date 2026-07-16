//! Stage 8 evals: run every check and the scoring engine against captured
//! RouterOS output stored under `tests/fixtures/<scenario>/`, asserting the
//! expected per-check status and per-profile score.
//!
//! This guards against regressions in parsing, check logic and scoring on
//! realistic device output — without a live router. A fixture directory holds
//! one `<command-slug>.txt` per distinct command (see [`command_slug`]) and an
//! `expected.json` describing the outcome; the runner discovers every fixture,
//! so adding a scenario needs no code change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::audit::{self, Outputs};
use crate::checks::{all_checks, Status};
use crate::scoring::{score, Profile};

/// A fixture's expected results.
#[derive(Deserialize)]
struct Expected {
    /// What the scenario represents (documentation only).
    #[allow(dead_code)]
    description: String,
    /// check id -> expected status ("pass" | "fail" | "error").
    findings: HashMap<String, String>,
    /// profile name -> expected total score.
    scores: HashMap<String, u8>,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Turn a RouterOS command into the fixture filename holding its output, e.g.
/// `/ip service print detail` -> `ip_service_print_detail.txt`. Every
/// non-alphanumeric run becomes `_`; the mapping is unique across all commands.
fn command_slug(command: &str) -> String {
    let slug: String = command
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{}.txt", slug.trim_matches('_'))
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Error => "error",
    }
}

fn run_scenario(scenario: &Path, name: &str) {
    let expected: Expected = serde_json::from_str(
        &std::fs::read_to_string(scenario.join("expected.json"))
            .unwrap_or_else(|e| panic!("[{name}] read expected.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("[{name}] parse expected.json: {e}"));

    // Load the captured output for each distinct command the checks need.
    let mut outputs: Outputs = HashMap::new();
    for check in all_checks() {
        let cmd = check.command();
        if outputs.contains_key(cmd) {
            continue;
        }
        let file = scenario.join(command_slug(cmd));
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("[{name}] read {}: {e}", file.display()));
        outputs.insert(cmd, Ok(text));
    }

    let findings = audit::evaluate(&outputs);

    // The fixture must pin exactly the checks the audit produces — no more, no less.
    assert_eq!(
        findings.len(),
        expected.findings.len(),
        "[{name}] expected.findings pins {} checks, audit produced {}",
        expected.findings.len(),
        findings.len()
    );

    for f in &findings {
        let want = expected
            .findings
            .get(f.id)
            .unwrap_or_else(|| panic!("[{name}] no expectation for check '{}'", f.id));
        assert_eq!(
            status_name(f.status),
            want,
            "[{name}] check '{}': expected {want}, got {} — {}",
            f.id,
            status_name(f.status),
            f.detail
        );
    }

    for (profile_name, &want) in &expected.scores {
        let profile = Profile::parse(profile_name)
            .unwrap_or_else(|| panic!("[{name}] unknown profile '{profile_name}'"));
        let got = score(&findings, profile).total;
        assert_eq!(
            got, want,
            "[{name}] {profile_name} score: expected {want}, got {got}"
        );
    }
}

#[test]
fn fixtures_match_expected_findings_and_scores() {
    let dir = fixtures_dir();
    let mut scenarios = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        run_scenario(&path, &name);
        scenarios += 1;
    }
    assert!(scenarios > 0, "no fixtures found in {}", dir.display());
}

#[test]
fn command_slugs_are_unique() {
    let mut slugs: Vec<String> = all_checks()
        .iter()
        .map(|c| command_slug(c.command()))
        .collect();
    let total_commands = {
        let mut cmds: Vec<&str> = all_checks().iter().map(|c| c.command()).collect();
        cmds.sort_unstable();
        cmds.dedup();
        cmds.len()
    };
    slugs.sort_unstable();
    slugs.dedup();
    assert_eq!(
        slugs.len(),
        total_commands,
        "command_slug collides: {} distinct commands map to {} slugs",
        total_commands,
        slugs.len()
    );
}
