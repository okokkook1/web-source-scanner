use std::{fs, sync::atomic::AtomicBool};
use web_source_scanner::{model::*, source::*};

fn options(root: &std::path::Path) -> ScanOptions {
    ScanOptions {
        root: root.into(),
        mode: None,
        excludes: vec![],
        engine: None,
        dependency_check: None,
        dependency_report: None,
        timeout_secs: 60,
        max_file_bytes: 2_000_000,
        osv: false,
    }
}

#[test]
fn decodes_utf8_bom_and_utf16_with_original_line_breaks() {
    assert_eq!(
        decode(b"\xef\xbb\xbfhello\r\nworld").unwrap().text,
        "hello\r\nworld"
    );
    let mut bytes = vec![255, 254];
    for u in "網站資料\r\n測試".encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    assert_eq!(decode(&bytes).unwrap().text, "網站資料\r\n測試");
    let mut bytes = vec![254, 255];
    for u in "hello\n站".encode_utf16() {
        bytes.extend(u.to_be_bytes());
    }
    assert_eq!(decode(&bytes).unwrap().text, "hello\n站");
}

#[test]
fn decodes_big5_but_rejects_binary_and_invalid_encodings() {
    let (bytes, _, _) = encoding_rs::BIG5.encode("網站資料");
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.text, "網站資料");
    assert_eq!(decoded.encoding, "Big5");
    assert!(decode(b"MZ\0\0\0\x01").is_err());
    assert!(decode(&[255, 254, 97]).is_err());
}

#[test]
fn inventories_unicode_sources_and_excludes_validation_and_vendors() {
    let dir = tempfile::tempdir().unwrap();
    for p in [
        "網站資料/App.Website/A.cs",
        "網站資料/App.Website/Views/a.cshtml",
        "網站資料/App.Website/scripts/app.js",
        "網站資料/App.Website/scripts/jquery.min.js",
        "網站資料/App.Website/App.Website.csproj",
        "validation-copy/A.cs",
        "網站資料/packages/a.cs",
        "網站資料/bin/x.cs",
        "網站資料/Model/Generated/X.generated.cs",
    ] {
        let path = dir.path().join(p);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "// 測試").unwrap();
    }
    let result = inventory(&options(dir.path()), &AtomicBool::new(false));
    assert_eq!(result.files.len(), 4, "{:?}", result.files);
    assert!(
        result
            .files
            .iter()
            .any(|f| f.relative == "網站資料/App.Website/scripts/app.js")
    );
    assert!(result.warnings.iter().any(|s| s.contains("web.config")));
    assert!(!result.excluded.is_empty());
}

#[test]
fn respects_extra_exclusions_and_limits_and_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.cs"), "class A {}").unwrap();
    fs::write(dir.path().join("b.cs"), "class B {}").unwrap();
    let mut opts = options(dir.path());
    opts.excludes.push("a.cs".into());
    opts.max_file_bytes = 2;
    let result = inventory(&opts, &AtomicBool::new(false));
    assert!(result.files.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(inventory(&opts, &AtomicBool::new(true)).cancelled);
    opts.root = dir.path().join("missing");
    assert!(!inventory(&opts, &AtomicBool::new(false)).errors.is_empty());
}
