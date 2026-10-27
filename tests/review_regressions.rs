use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
};
use web_source_scanner::{
    model::*,
    rules::{analyze_source, redact},
    scan::run_scan,
};

#[test]
fn xml_entity_quoted_passwords_never_leak_through_connectionstring_evidence() {
    for quotes in [
        ("&quot;", "&quot;"),
        ("&apos;", "&apos;"),
        ("&#34;", "&#34;"),
        ("&#x22;", "&#x22;"),
    ] {
        let input = format!(
            "<add name=\"DB\" connectionString=\"Server=.;Password={}topSecret123{};User Id=a\"/>",
            quotes.0, quotes.1
        );
        assert!(
            !redact(&input).contains("topSecret123"),
            "{}",
            redact(&input)
        );
        let file = SourceFile {
            relative: "web.config".into(),
            text: input,
            extension: "config".into(),
            encoding: "UTF-8".into(),
        };
        for f in analyze_source(&file) {
            assert!(!f.evidence.contains("topSecret123"));
        }
    }
    assert!(!redact(r#"<add key="Api&#75;ey" value="topSecret123"/>"#).contains("topSecret123"));
}

#[test]
fn malformed_xml_and_attributes_are_partial_not_clean() {
    for xml in [
        r#"<configuration></wrong><compilation debug="true"/>"#,
        r#"<configuration><compilation debug="true" debug="false"/></configuration>"#,
        r#"<configuration>"#,
        r#"<packages><package id="Demo" version="1.0"/></wrong>"#,
    ] {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("web.config"), xml).unwrap();
        let r = run_scan(
            ScanOptions::new(d.path()),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        );
        assert_eq!(r.state, ScanState::Partial, "{xml}");
        assert_eq!(r.files[0].local, "partial");
        assert!(r.warnings.iter().any(|s| s.contains("XML")));
    }
}

#[test]
fn xml_entities_in_security_settings_are_decoded_before_comparison() {
    let f = SourceFile {
        relative: "web.config".into(),
        text: r#"<compilation debug="tr&#117;e"/>"#.into(),
        extension: "config".into(),
        encoding: "UTF-8".into(),
    };
    assert!(
        analyze_source(&f)
            .iter()
            .any(|f| f.rule_id == "CONFIG-DEBUG")
    );
}

#[test]
fn imported_dependency_report_does_not_fabricate_local_package_coverage() {
    let d = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("packages.config"),
        r#"<packages><package id="Demo" version="1.0"/></packages>"#,
    )
    .unwrap();
    let path = external.path().join("report.json");
    fs::write(&path,r#"{"dependencies":[],"scanInfo":{"engineVersion":"12.1.0","dataSource":[{"name":"NVD","timestamp":"2026-10-01"}]},"projectInfo":{"reportDate":"2026-10-02"}}"#).unwrap();
    let mut o = ScanOptions::new(d.path());
    o.dependency_report = Some(path);
    let r = run_scan(o, Arc::new(AtomicBool::new(false)), |_| {});
    let dep = r
        .engines
        .iter()
        .find(|e| e.name == "Dependency-Check")
        .unwrap();
    assert_eq!(dep.scanned, 0);
    assert_eq!(dep.status, "imported_unverified");
    assert_eq!(dep.version, "12.1.0");
    assert_eq!(r.state, ScanState::Partial);
    let meta = serde_json::to_value(dep).unwrap();
    assert_eq!(meta["metadata"]["report_date"], "2026-10-02");
    assert_eq!(
        meta["metadata"]["database_sources"][0]["timestamp"],
        "2026-10-01"
    );
}
