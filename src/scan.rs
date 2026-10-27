use crate::model::*;
use crate::{engine::*, flow, osv, rules::*, source::inventory};
use quick_xml::{Reader, events::Event};
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn line_of(text: &str, byte: usize) -> usize {
    text.as_bytes()[..byte.min(text.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn packages(files: &[SourceFile]) -> Vec<PackageInfo> {
    let mut result = vec![];
    for file in files
        .iter()
        .filter(|f| f.relative.to_lowercase().ends_with("packages.config"))
    {
        let mut reader = Reader::from_str(&file.text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(e) | Event::Empty(e)) if e.name().as_ref() == b"package" => {
                    let line = line_of(&file.text, reader.buffer_position() as usize);
                    let attrs = e
                        .attributes()
                        .flatten()
                        .map(|a| {
                            (
                                String::from_utf8_lossy(a.key.as_ref()).into_owned(),
                                a.decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map(|v| v.into_owned())
                                .unwrap_or_default(),
                            )
                        })
                        .collect::<std::collections::HashMap<_, _>>();
                    if let (Some(id), Some(version)) = (attrs.get("id"), attrs.get("version")) {
                        result.push(PackageInfo {
                            file: file.relative.clone(),
                            id: id.clone(),
                            version: version.clone(),
                            line,
                        });
                    }
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
        }
    }
    result
}

pub fn run_scan(
    options: ScanOptions,
    cancel: Arc<AtomicBool>,
    progress: impl Fn(Progress),
) -> ScanReport {
    let started = chrono::Local::now();
    progress(Progress {
        stage: "列舉".into(),
        message: "辨識來源、排除套件與重複版本".into(),
        done: 0,
        total: 0,
    });
    let inv = inventory(&options, &cancel);
    let mut report = ScanReport {
        schema_version: "1.0".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        rule_version: "2026.10.28.2".into(),
        scan_id: started.format("%Y%m%d-%H%M%S-%f").to_string(),
        root: options.root.to_string_lossy().into_owned(),
        started_at: started.to_rfc3339(),
        finished_at: String::new(),
        state: ScanState::Complete,
        mode: options.mode,
        technologies: inv.technologies,
        enumerated: inv.enumerated,
        files: vec![],
        excluded: inv.excluded,
        warnings: inv.warnings,
        errors: inv.errors,
        engines: vec![],
        packages: packages(&inv.files),
        findings: vec![],
    };
    report
        .warnings
        .push("掃描結果僅為靜態分析；零命中不代表網站安全，效能線索需實際量測。".into());
    if inv.files.iter().any(|f| f.extension == "cshtml") {
        report
            .warnings
            .push("Razor 僅進行混合樣板專用規則；未建立完整 C# 語意模型。".into());
    }
    for (i, file) in inv.files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.state = ScanState::Cancelled;
            break;
        }
        progress(Progress {
            stage: "本機檢查".into(),
            message: file.relative.clone(),
            done: i + 1,
            total: inv.files.len(),
        });
        let xml_errors = if matches!(file.extension.as_str(), "config" | "csproj") {
            xml_diagnostics(&file.text)
        } else {
            vec![]
        };
        let bad =
            file.extension == "cs" && csharp_parse_has_errors(&file.text) || !xml_errors.is_empty();
        if bad {
            if !xml_errors.is_empty() {
                for diagnostic in xml_errors {
                    report.warnings.push(format!(
                        "{}：{}，本機分析／套件盤點可能不完整",
                        file.relative, diagnostic
                    ));
                }
            } else {
                report.warnings.push(format!(
                    "{}：C# 語法樹有解析錯誤，本機分析可能不完整",
                    file.relative
                ));
            }
            report.state = ScanState::Partial;
        }
        report.findings.extend(
            analyze_source(file)
                .into_iter()
                .filter(|f| options.mode.is_none_or(|m| f.category == m)),
        );
        report.files.push(FileCoverage {
            file: file.relative.clone(),
            encoding: file.encoding.clone(),
            local: if bad { "partial" } else { "complete" }.into(),
            semgrep: if matches!(file.extension.as_str(), "cs" | "js") {
                "pending"
            } else {
                "not_supported"
            }
            .into(),
        });
    }
    let csharp_files = inv.files.iter().filter(|f| f.extension == "cs").count();
    let mut flow_status = EngineStatus {
        metadata: serde_json::Value::Null,
        name: "Rust 跨檔案資料流".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        status: "not_applicable".into(),
        eligible: csharp_files,
        scanned: 0,
        errors: vec![],
        limitations: "以方法名稱解析呼叫鏈的啟發式分析；不含型別推導、介面／委派與動態分派解析。"
            .into(),
    };
    if csharp_files > 0 && options.mode != Some(Category::QualityPerformance) {
        if cancel.load(Ordering::Relaxed) {
            flow_status.status = "cancelled".into();
        } else {
            progress(Progress {
                stage: "跨檔案資料流".into(),
                message: format!("以方法摘要追蹤 {csharp_files} 個 C# 檔案的呼叫鏈"),
                done: 0,
                total: csharp_files,
            });
            let outcome = flow::analyze(&inv.files);
            report.warnings.extend(outcome.warnings);
            report.findings.extend(
                outcome
                    .findings
                    .into_iter()
                    .filter(|f| options.mode.is_none_or(|m| f.category == m)),
            );
            flow_status.scanned = outcome.files;
            flow_status.status = if outcome.methods == 0 {
                "not_applicable"
            } else {
                "complete"
            }
            .into();
            flow_status.metadata = serde_json::json!({
                "methods": outcome.methods,
                "files": outcome.files,
            });
        }
    }
    report.engines.push(flow_status);
    let engine_files = inv
        .files
        .iter()
        .filter(|f| matches!(f.extension.as_str(), "cs" | "js"))
        .cloned()
        .collect::<Vec<_>>();
    let engine_path = options.engine.clone().or_else(detect_engine);
    if !cancel.load(Ordering::Relaxed) && !engine_files.is_empty() {
        progress(Progress {
            stage: "引擎分析".into(),
            message: format!("Semgrep CE：{} 個 C#／JavaScript 檔案", engine_files.len()),
            done: 0,
            total: engine_files.len(),
        });
        let failure = |status: &str, error: String| EngineStatus {
            metadata: serde_json::Value::Null,
            name: "Semgrep CE Core".into(),
            version: String::new(),
            status: status.into(),
            eligible: engine_files.len(),
            scanned: 0,
            errors: vec![error],
            limitations: "無跨檔案分析；引擎不可用時保留本機部分結果。".into(),
        };
        let engine_result = if let Some(path) = engine_path.filter(|p| p.is_file()) {
            run_semgrep(&path, &engine_files, &cancel, options.timeout_secs)
        } else {
            Err("找不到本機 Semgrep 引擎，請使用完整交付資料夾或設定引擎路徑".into())
        };
        match engine_result {
            Ok(result) => {
                for file in &mut report.files {
                    if result.scanned.contains(&file.file) {
                        file.semgrep = if result
                            .status
                            .errors
                            .iter()
                            .any(|e| e.starts_with(&file.file))
                        {
                            "partial"
                        } else {
                            "complete"
                        }
                        .into();
                    } else if file.semgrep == "pending" {
                        file.semgrep = "not_scanned".into();
                    }
                }
                report.findings.extend(
                    result
                        .findings
                        .into_iter()
                        .filter(|f| options.mode.is_none_or(|m| f.category == m)),
                );
                if result.status.status != "complete" {
                    report.state = ScanState::Partial;
                }
                report.engines.push(result.status);
            }
            Err(e) => {
                let missing = e.starts_with("找不到");
                report
                    .engines
                    .push(failure(if missing { "missing" } else { "failed" }, e));
                report.state = ScanState::Partial;
                for f in &mut report.files {
                    if f.semgrep == "pending" {
                        f.semgrep = "not_scanned".into();
                    }
                }
            }
        }
    } else {
        report.engines.push(EngineStatus {
            metadata: serde_json::Value::Null,
            name: "Semgrep CE Core".into(),
            version: "".into(),
            status: if cancel.load(Ordering::Relaxed) {
                "cancelled"
            } else {
                "not_applicable"
            }
            .into(),
            eligible: engine_files.len(),
            scanned: 0,
            errors: vec![],
            limitations: "僅支援 C# 與 JavaScript。".into(),
        });
    }
    let mut dep = EngineStatus {
        metadata: serde_json::Value::Null,
        name: "Dependency-Check".into(),
        version: "".into(),
        status: "not_requested".into(),
        eligible: report.packages.len(),
        scanned: 0,
        errors: vec![],
        limitations: "未掃描套件漏洞；套件盤點不等於 CVE 檢查。".into(),
    };
    if !cancel.load(Ordering::Relaxed) && options.mode != Some(Category::QualityPerformance) {
        let raw = if let Some(path) = &options.dependency_report {
            Some(fs::read_to_string(path).map_err(|e| format!("套件報告無法讀取：{e}")))
        } else if let Some(path) = &options.dependency_check {
            progress(Progress {
                stage: "套件分析".into(),
                message: "使用已備妥的本機 Dependency-Check 資料庫（不更新）".into(),
                done: 0,
                total: 0,
            });
            Some((|| {
                let work = tempfile::tempdir().map_err(|e| e.to_string())?;
                let mirror = work.path().join("sources");
                fs::create_dir_all(&mirror).map_err(|e| e.to_string())?;
                for f in inv
                    .files
                    .iter()
                    .filter(|f| f.relative.ends_with("packages.config"))
                {
                    let p = mirror.join(&f.relative);
                    fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
                    fs::write(p, &f.text).map_err(|e| e.to_string())?;
                }
                let cmd = dependency_check_command(path, &mirror, work.path())?;
                let raw = run_process(cmd, &cancel, options.timeout_secs)?;
                if raw.cancelled || raw.timed_out || raw.code != 0 {
                    return Err(format!("套件引擎失敗／取消／逾時，代碼 {}", raw.code));
                }
                fs::read_to_string(work.path().join("dependency-check-report.json"))
                    .map_err(|e| e.to_string())
            })())
        } else {
            None
        };
        if let Some(raw) = raw {
            match raw.and_then(|s| parse_dependency_analysis(&s)) {
                Ok(mut analysis) => {
                    let local = report
                        .packages
                        .iter()
                        .map(|p| (p.id.to_lowercase(), p.version.to_lowercase()))
                        .collect::<std::collections::BTreeSet<_>>();
                    dep.eligible = local.len();
                    dep.scanned = local.intersection(&analysis.identities).count();
                    dep.version = analysis.version;
                    dep.errors = analysis.errors;
                    analysis.metadata["source_report"] = serde_json::json!(
                        options
                            .dependency_report
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "本次本機引擎產生".into())
                    );
                    analysis.metadata["unmatched_local_packages"] = serde_json::json!(
                        local
                            .difference(&analysis.identities)
                            .map(|(n, v)| format!("{n}@{v}"))
                            .collect::<Vec<_>>()
                    );
                    analysis.metadata["coverage_basis"] = serde_json::json!(
                        "僅計算外部報告中可核對的 NuGet ID 與版本，不保證報告與此份原始碼同一時間／專案。"
                    );
                    dep.metadata = analysis.metadata;
                    report.findings.extend(analysis.findings);
                    dep.status = if options.dependency_report.is_some() {
                        "imported_unverified"
                    } else if dep.scanned < dep.eligible || !dep.errors.is_empty() {
                        "partial"
                    } else {
                        "complete"
                    }
                    .into();
                    if dep.status != "complete" {
                        report.state = ScanState::Partial;
                    }
                    dep.limitations="套件覆蓋只計算核實相符的 ID／版本；外部報告的專案關聯與時效仍需核對。資料庫日期 unknown 代表未提供。".into();
                }
                Err(e) => {
                    dep.status = "failed".into();
                    dep.errors.push(redact(&e));
                    report.state = ScanState::Partial;
                }
            }
        }
    }
    report.engines.push(dep);
    let unique_packages = report
        .packages
        .iter()
        .map(|p| format!("{}@{}", p.id.to_lowercase(), p.version.to_lowercase()))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let mut osv_status = EngineStatus {
        metadata: serde_json::Value::Null,
        name: "OSV.dev".into(),
        version: String::new(),
        status: "not_requested".into(),
        eligible: unique_packages,
        scanned: 0,
        errors: vec![],
        limitations:
            "CLI 預設關閉、GUI 預設勾選；啟用後只把套件名稱與版本送到 api.osv.dev，未傳送原始碼。"
                .into(),
    };
    if options.osv && options.mode != Some(Category::QualityPerformance) {
        if cancel.load(Ordering::Relaxed) {
            osv_status.status = "cancelled".into();
        } else if report.packages.is_empty() {
            osv_status.status = "not_applicable".into();
            osv_status.limitations = "沒有 packages.config 套件可查詢。".into();
        } else {
            progress(Progress {
                stage: "套件漏洞".into(),
                message: format!("OSV.dev：查詢 {unique_packages} 組套件名稱與版本"),
                done: 0,
                total: unique_packages,
            });
            let outcome = osv::lookup(&report.packages, &cancel, options.timeout_secs);
            report.warnings.extend(outcome.warnings);
            if outcome.status.status != "complete" {
                report.state = ScanState::Partial;
            }
            report.findings.extend(
                outcome
                    .findings
                    .into_iter()
                    .filter(|f| options.mode.is_none_or(|m| f.category == m)),
            );
            osv_status = outcome.status;
        }
    }
    report.engines.push(osv_status);
    report.findings.sort_by(|a, b| {
        (a.severity, &a.file, a.start_line, &a.rule_id).cmp(&(
            b.severity,
            &b.file,
            b.start_line,
            &b.rule_id,
        ))
    });
    report.findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id && a.file == b.file && a.start_line == b.start_line
    });
    if !report.errors.is_empty() && report.state == ScanState::Complete {
        report.state = ScanState::Partial;
    }
    if inv.files.is_empty() && !cancel.load(Ordering::Relaxed) {
        report.state = ScanState::Failed;
        report
            .errors
            .push("沒有可分析的原始碼；請核對路徑、檔案類型及排除條件。".into());
    }
    if inv.cancelled || cancel.load(Ordering::Relaxed) {
        report.state = ScanState::Cancelled;
    }
    report.finished_at = chrono::Local::now().to_rfc3339();
    progress(Progress {
        stage: "完成".into(),
        message: format!("已彙整 {} 筆發現", report.findings.len()),
        done: report.files.len(),
        total: inv.files.len(),
    });
    report
}
