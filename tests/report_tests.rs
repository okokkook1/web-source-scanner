use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
};
use web_source_scanner::{model::*, report::export_report, scan::run_scan};
fn report() -> ScanReport {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("A.cs"),
        "class A{string password=\"privateSecret321\";void F(){Thread.Sleep(1);}}",
    )
    .unwrap();
    let mut opts = ScanOptions::new(d.path());
    opts.engine = Some(d.path().join("no.exe"));
    let mut r = run_scan(opts, Arc::new(AtomicBool::new(false)), |_| {});
    r.findings[0].title = "=HYPERLINK(\"evil\")".into();
    r.findings[0].description = "<script>alert(1)</script> & \"x\"\nnext".into();
    r.findings[0].evidence = "password=\"privateSecret321\"".into();
    r
}
#[test]
fn independent_exports_include_both_categories_and_metadata() {
    let r = report();
    let out = tempfile::tempdir().unwrap();
    let files = export_report(&r, out.path(), None).unwrap();
    assert_eq!(files.len(), 7);
    let a: serde_json::Value = serde_json::from_slice(
        &fs::read(out.path().join("security-vulnerabilities.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(a["schema_version"], "1.0");
    assert!(
        a["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["category"] == "security")
    );
    let b: serde_json::Value = serde_json::from_slice(
        &fs::read(out.path().join("code-quality-performance.json")).unwrap(),
    )
    .unwrap();
    assert!(
        b["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["category"] == "quality_performance")
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.path().join("scan-summary.json")).unwrap()).unwrap();
    assert!(summary.get("engines").is_some());
    assert!(summary.get("findings").is_none());
}
#[test]
fn html_is_escaped_and_csv_formula_cells_are_safe_and_all_reports_redact_secrets() {
    let out = tempfile::tempdir().unwrap();
    export_report(&report(), out.path(), None).unwrap();
    let html = fs::read_to_string(out.path().join("security-vulnerabilities.html")).unwrap();
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("https://cdn"));
    let csv = fs::read(out.path().join("security-vulnerabilities.csv")).unwrap();
    assert!(csv.starts_with(&[239, 187, 191]));
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("\"'=HYPERLINK(\"\"evil\"\")\""));
    for file in fs::read_dir(out.path()).unwrap() {
        let s = fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(!s.contains("privateSecret321"));
    }
}
#[test]
fn selected_category_and_empty_category_still_produce_valid_reports() {
    let mut r = report();
    r.findings
        .retain(|f| f.category == Category::QualityPerformance);
    let out = tempfile::tempdir().unwrap();
    let files = export_report(&r, out.path(), Some(Category::Security)).unwrap();
    assert_eq!(files.len(), 4);
    assert!(!out.path().join("code-quality-performance.csv").exists());
    let json: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(out.path().join("security-vulnerabilities.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(json["findings"].as_array().unwrap().len(), 0);
}
#[test]
fn cannot_export_into_original_source_tree() {
    let source = tempfile::tempdir().unwrap();
    let mut r = report();
    r.root = source.path().to_string_lossy().into_owned();
    assert!(export_report(&r, &source.path().join("reports"), None).is_err());
    assert!(!source.path().join("reports").exists());
}

#[test]
fn exporting_twice_to_the_same_folder_replaces_the_previous_reports() {
    let r = report();
    let out = tempfile::tempdir().unwrap();
    let first = export_report(&r, out.path(), None).unwrap();
    let second = export_report(&r, out.path(), None).unwrap();
    assert_eq!(first.len(), 7);
    assert_eq!(second.len(), 7);
    let html = fs::read_to_string(out.path().join("security-vulnerabilities.html")).unwrap();
    assert!(html.contains("網站原始碼檢查報告"));
}

#[test]
fn html_keeps_external_engine_database_dates_and_provenance() {
    let mut r = report();
    r.engines[1].metadata = serde_json::json!({"report_date":"2026-10-02","database_sources":[{"name":"NVD","timestamp":"2026-10-01"}]});
    let out = tempfile::tempdir().unwrap();
    export_report(&r, out.path(), None).unwrap();
    let html = fs::read_to_string(out.path().join("security-vulnerabilities.html")).unwrap();
    assert!(html.contains("2026-10-01"));
    assert!(html.contains("2026-10-02"));
}
