use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
};
use web_source_scanner::{model::*, scan::run_scan};
#[test]
fn missing_engine_is_partial_and_scan_does_not_modify_source() {
    let d = tempfile::tempdir().unwrap();
    let text = "class A{void F(){Thread.Sleep(1);}}";
    fs::write(d.path().join("A.cs"), text).unwrap();
    let mut opts = ScanOptions::new(d.path());
    opts.engine = Some(d.path().join("missing.exe"));
    let r = run_scan(opts, Arc::new(AtomicBool::new(false)), |_| {});
    assert_eq!(r.state, ScanState::Partial);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(fs::read_to_string(d.path().join("A.cs")).unwrap(), text);
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    assert!(r.engines.iter().any(|e| e.status == "missing"));
}
#[test]
fn cancelled_and_invalid_root_have_distinct_final_states() {
    let d = tempfile::tempdir().unwrap();
    let r = run_scan(
        ScanOptions::new(d.path()),
        Arc::new(AtomicBool::new(true)),
        |_| {},
    );
    assert_eq!(r.state, ScanState::Cancelled);
    let r = run_scan(
        ScanOptions::new(d.path().join("missing")),
        Arc::new(AtomicBool::new(false)),
        |_| {},
    );
    assert_eq!(r.state, ScanState::Failed);
}
#[test]
fn mode_filters_findings_and_package_inventory_is_not_a_vulnerability_scan() {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("A.cs"),
        "class A {string password=\"secret123\"; void F(){Thread.Sleep(1);}}",
    )
    .unwrap();
    fs::write(
        d.path().join("packages.config"),
        "<packages><package id=\"Demo\" version=\"1.0\" /></packages>",
    )
    .unwrap();
    let mut opts = ScanOptions::new(d.path());
    opts.mode = Some(Category::QualityPerformance);
    opts.engine = Some(d.path().join("absent.exe"));
    let r = run_scan(opts, Arc::new(AtomicBool::new(false)), |_| {});
    assert!(
        r.findings
            .iter()
            .all(|f| f.category == Category::QualityPerformance)
    );
    assert_eq!(r.packages.len(), 1);
    assert_eq!(r.packages[0].id, "Demo");
    assert!(
        r.engines
            .iter()
            .any(|e| e.name == "Dependency-Check" && e.status == "not_requested")
    );
}
