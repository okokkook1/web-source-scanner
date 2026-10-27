use std::sync::atomic::AtomicBool;
use web_source_scanner::{model::*, osv};

fn package() -> PackageInfo {
    PackageInfo {
        file: "packages.config".into(),
        id: "Newtonsoft.Json".into(),
        version: "12.0.1".into(),
        line: 4,
    }
}

const SAMPLE: &str = r#"{
  "vulns": [
    {
      "id": "GHSA-5crp-9r3c-p9vr",
      "summary": "Newtonsoft.Json Denial of Service",
      "details": "Stack overflow when parsing deeply nested JSON.",
      "aliases": ["CVE-2024-21907"],
      "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-755"]},
      "affected": [
        {
          "package": {"name": "Newtonsoft.Json", "ecosystem": "NuGet"},
          "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}
          ]
        }
      ]
    }
  ]
}"#;

#[test]
fn parses_severity_alias_fixed_version_and_location() {
    let findings = osv::parse_response(SAMPLE, &package()).unwrap();
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.rule_id, "DEP-OSV-GHSA-5crp-9r3c-p9vr");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.file, "packages.config");
    assert_eq!(f.start_line, 4);
    assert!(f.title.contains("Newtonsoft.Json 12.0.1"));
    assert!(f.recommendation.contains("13.0.1"), "{}", f.recommendation);
    assert!(f.evidence.contains("CVE-2024-21907"), "{}", f.evidence);
    assert!(
        f.references.iter().any(|r| r.contains("CVE-2024-21907")),
        "{:?}",
        f.references
    );
    assert_eq!(f.cwe, vec!["CWE-755"]);
    assert!(f.limitations.contains("未確認"));
}

#[test]
fn unknown_severity_defaults_to_medium() {
    let raw = r#"{"vulns":[{"id":"OSV-1","summary":"x","affected":[]}]}"#;
    let findings = osv::parse_response(raw, &package()).unwrap();
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].recommendation.contains("查閱"));
}

#[test]
fn empty_or_missing_vulns_is_not_an_error() {
    assert!(osv::parse_response("{}", &package()).unwrap().is_empty());
    assert!(
        osv::parse_response(r#"{"vulns": []}"#, &package())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn invalid_json_is_reported_as_an_error() {
    assert!(osv::parse_response("<html>blocked</html>", &package()).is_err());
}

#[test]
fn query_body_uses_the_nuget_ecosystem() {
    let body = osv::query_body("Newtonsoft.Json", "12.0.1");
    assert!(body.contains("\"name\":\"Newtonsoft.Json\""), "{body}");
    assert!(body.contains("\"ecosystem\":\"NuGet\""), "{body}");
    assert!(body.contains("\"version\":\"12.0.1\""), "{body}");
}

#[test]
#[ignore = "requires network access to api.osv.dev and curl.exe"]
fn live_lookup_returns_a_known_advisory() {
    let outcome = osv::lookup(&[package()], &AtomicBool::new(false), 20);
    assert_eq!(outcome.status.status, "complete", "{:?}", outcome.status);
    assert!(!outcome.findings.is_empty(), "expected a known advisory");
    assert!(
        outcome
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("DEP-OSV-"))
    );
}
