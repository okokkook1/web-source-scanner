use std::{path::Path, process::Command, sync::atomic::AtomicBool};
use web_source_scanner::{engine::*, model::*};
fn file() -> SourceFile {
    SourceFile {
        relative: "網站/A.cs".into(),
        text: "class A {\nstring password=\"secret12345\";\n}".into(),
        extension: "cs".into(),
        encoding: "UTF-16LE".into(),
    }
}

#[test]
fn engine_json_maps_mirror_to_original_unicode_file_and_masks_evidence() {
    let json = r#"{"version":"1.182.1","results":[{"check_id":"ENGINE-SQL-TAINT","path":"C:/work/mirror/網站/A.cs","start":{"line":2},"end":{"line":2},"extra":{"dataflow_trace":{}}}],"errors":[],"paths":{"scanned":["C:/work/mirror/網站/A.cs"]}}"#;
    let r = parse_semgrep(json, &[file()], Path::new("C:/work/mirror")).unwrap();
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].file, "網站/A.cs");
    assert_eq!(r.findings[0].start_line, 2);
    assert!(!r.findings[0].evidence.contains("secret12345"));
    assert_eq!(r.scanned, vec!["網站/A.cs"]);
}

#[test]
fn engine_errors_and_unknown_paths_are_not_clean_success() {
    assert!(parse_semgrep("{}", &[], Path::new("mirror")).is_err());
    assert!(parse_semgrep("not json", &[], Path::new("mirror")).is_err());
    let r=parse_semgrep(r#"{"version":"x","results":[],"errors":[{"error_type":"ParseError","location":{"path":"A.cs","start":{"line":2}}}],"paths":{"scanned":["A.cs"]}}"#,&[file()],Path::new("mirror")).unwrap();
    assert_eq!(r.status.status, "partial");
    assert!(!r.status.errors.is_empty());
    let r=parse_semgrep(r#"{"version":"x","results":[{"check_id":"ENGINE-SQL-TAINT","path":"../outside.cs","start":{"line":1},"end":{"line":1}}],"errors":[],"paths":{"scanned":[]}}"#,&[file()],Path::new("mirror")).unwrap();
    assert!(r.findings.is_empty());
    assert!(!r.status.errors.is_empty());
}

#[test]
fn dependency_report_retains_cve_package_and_source_reference() {
    let r=import_dependency_check(r#"{"dependencies":[{"fileName":"packages.config","packages":[{"id":"pkg:nuget/Example@1.0"}],"vulnerabilities":[{"name":"CVE-2026-1234","severity":"HIGH","description":"demo","references":[{"url":"https://example.com/advisory"}]}]}]}"#).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].category, Category::Security);
    assert!(r[0].title.contains("CVE-2026-1234"));
    assert!(r[0].description.contains("pkg:nuget/Example@1.0"));
    assert!(import_dependency_check("{}").is_err());
}

#[test]
fn child_nonzero_and_large_output_do_not_deadlock() {
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-Command",
        "[Console]::Out.Write(('x' * 100000)); exit 7",
    ]);
    let r = run_process(cmd, &AtomicBool::new(false), 10).unwrap();
    assert_eq!(r.code, 7);
    assert_eq!(r.stdout.len(), 100000);
}

#[test]
fn cancellation_and_timeout_terminate_running_process() {
    for (cancel, timeout) in [(true, 10), (false, 1)] {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 20"]);
        let before = std::time::Instant::now();
        let r = run_process(cmd, &AtomicBool::new(cancel), timeout).unwrap();
        assert!(before.elapsed().as_secs() < 8);
        assert_eq!(r.cancelled, cancel);
        assert_eq!(r.timed_out, !cancel);
    }
}
