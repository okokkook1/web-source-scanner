use std::{
    fs,
    sync::{Arc, atomic::AtomicBool},
};
use web_source_scanner::{engine::detect_engine, model::*, scan::run_scan};
#[test]
#[ignore = "requires a real native Windows Semgrep engine"]
fn real_engine_scans_utf16_mirror_preserves_lines_and_does_not_touch_original() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("中文 目錄");
    fs::create_dir_all(&target).unwrap();
    let text = "class A {\r\nvoid F(){\r\nvar user=Request.QueryString[\"x\"];\r\nvar sql=\"SELECT \"+user;\r\nvar cmd=new SqlCommand(sql,connection);\r\n}\r\n}";
    let mut bytes = vec![255, 254];
    for u in text.encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    fs::write(target.join("A.cs"), &bytes).unwrap();
    let mut opts = ScanOptions::new(&target);
    opts.engine = Some(detect_engine().expect("native engine installed"));
    let r = run_scan(opts, Arc::new(AtomicBool::new(false)), |_| {});
    let sql = r
        .findings
        .iter()
        .find(|f| f.rule_id == "ENGINE-SQL-TAINT")
        .unwrap_or_else(|| {
            panic!(
                "actual taint finding missing; engines: {:?}, errors: {:?}",
                r.engines, r.errors
            )
        });
    assert_eq!(sql.start_line, 5);
    assert_eq!(sql.file, "A.cs");
    assert_eq!(r.engines[0].scanned, 1);
    assert_eq!(r.engines[0].status, "complete");
    assert_eq!(fs::read(target.join("A.cs")).unwrap(), bytes);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
}
