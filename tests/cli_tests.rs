use std::{fs, process::Command};
#[test]
fn cli_rejects_unknown_arguments_and_invalid_mode() {
    let exe = env!("CARGO_BIN_EXE_web-source-scanner");
    assert!(
        !Command::new(exe)
            .arg("--unknown-option")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !Command::new(exe)
            .args(["--mode", "invalid"])
            .output()
            .unwrap()
            .status
            .success()
    );
}
#[test]
fn cli_exports_separate_reports_and_reports_partial_exit_status() {
    let source = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("A.cs"),
        "class A{string password=\"secret12345\";void F(){Thread.Sleep(1);}}",
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_web-source-scanner"))
        .arg("--scan")
        .arg(source.path())
        .arg("--output")
        .arg(out.path())
        .args(["--mode", "quality"])
        .arg("--engine")
        .arg(source.path().join("missing.exe"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(
        &fs::read(out.path().join("code-quality-performance.json")).unwrap(),
    )
    .unwrap();
    assert!(!value["findings"].as_array().unwrap().is_empty());
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["category"] == "quality_performance")
    );
}
