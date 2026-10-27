use crate::model::*;
use crate::rules::redact;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub fn category_name(category: Category) -> &'static str {
    match category {
        Category::Security => "安全漏洞",
        Category::QualityPerformance => "程式碼品質與效能",
    }
}
pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "嚴重",
        Severity::High => "高",
        Severity::Medium => "中",
        Severity::Low => "低",
        Severity::Info => "資訊",
    }
}
pub fn state_name(state: ScanState) -> &'static str {
    match state {
        ScanState::Complete => "完成",
        ScanState::Partial => "部分完成",
        ScanState::Cancelled => "已取消",
        ScanState::Failed => "失敗",
    }
}
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => *s = redact(s),
        Value::Array(a) => {
            for v in a {
                scrub(v)
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                scrub(v)
            }
        }
        _ => {}
    }
}

fn csv_cell(s: &str) -> String {
    let leading = s.trim_start_matches(|c: char| c.is_whitespace() || c.is_control());
    let prefix = if leading.starts_with(['=', '+', '-', '@']) || s.starts_with(['\t', '\r', '\n']) {
        "'"
    } else {
        ""
    };
    format!("\"{prefix}{}\"", s.replace('"', "\"\""))
}
fn csv(findings: &[&Finding]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(
        &[
            "分類",
            "子分類",
            "嚴重度",
            "判定信心",
            "判定狀態",
            "問題",
            "檔案",
            "行號",
            "規則",
            "引擎",
            "證據",
            "說明",
            "修正建議",
            "限制",
        ]
        .iter()
        .map(|s| csv_cell(s))
        .collect::<Vec<_>>()
        .join(","),
    );
    out.push_str("\r\n");
    for f in findings {
        out.push_str(
            &[
                category_name(f.category),
                &f.subcategory,
                severity_name(f.severity),
                &f.confidence,
                &f.review_status,
                &f.title,
                &f.file,
                &f.start_line.to_string(),
                &f.rule_id,
                &f.engine,
                &f.evidence,
                &f.description,
                &f.recommendation,
                &f.limitations,
            ]
            .iter()
            .map(|s| csv_cell(s))
            .collect::<Vec<_>>()
            .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

fn html(report: &ScanReport, category: Category, findings: &[&Finding]) -> String {
    let name = category_name(category);
    let mut rows = String::new();
    for (n, f) in findings.iter().enumerate() {
        let sev = severity_name(f.severity);
        rows.push_str(&format!("<article class=\"finding\" data-severity=\"{}\"><div class=\"finding-head\"><span class=\"severity\">{}</span><h2>{}. {}</h2></div><p class=\"location\">{}：第 {} 行 · {} · 信心：{}</p><p>{}</p><p class=\"muted\">{}</p><pre>{}</pre><h3>修正建議</h3><p>{}</p><details><summary>判定與限制</summary><p>{}</p><p>{}</p><p>規則：{} · 引擎：{}</p></details></article>",escape(sev),escape(sev),n+1,escape(&f.title),escape(&f.file),f.start_line,escape(&f.subcategory),escape(&f.confidence),escape(&f.description),escape(&f.review_status),escape(&f.evidence),escape(&f.recommendation),escape(&f.review_status),escape(&f.limitations),escape(&f.rule_id),escape(&f.engine)));
    }
    if findings.is_empty() {
        rows.push_str("<div class=\"empty\">此分類沒有命中規則。請同時確認掃描覆蓋與引擎狀態；零命中不代表系統沒有問題。</div>");
    }
    let engines = report
        .engines
        .iter()
        .map(|e| {
            format!(
                "<li><strong>{}</strong> {} · 狀態：{} · 已掃描 {}/{}<p>{}</p>{}{}</li>",
                escape(&e.name),
                escape(&e.version),
                escape(&e.status),
                e.scanned,
                e.eligible,
                escape(&e.limitations),
                e.errors
                    .iter()
                    .map(|m| format!("<p class=\"warning\">{}</p>", escape(m)))
                    .collect::<String>(),
                if e.metadata.is_null() {
                    String::new()
                } else {
                    format!(
                        "<details><summary>報告來源與資料庫日期</summary><pre>{}</pre></details>",
                        escape(&serde_json::to_string_pretty(&e.metadata).unwrap_or_default())
                    )
                }
            )
        })
        .collect::<String>();
    let warnings = report
        .warnings
        .iter()
        .chain(&report.errors)
        .map(|s| format!("<li>{}</li>", escape(s)))
        .collect::<String>();
    let excluded = report
        .excluded
        .iter()
        .map(|s| format!("<li>{}</li>", escape(s)))
        .collect::<String>();
    let high = findings
        .iter()
        .filter(|f| f.severity <= Severity::High)
        .count();
    let mut out = String::from(
        r#"<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>網站原始碼掃描報告</title><style>
:root{font-family:"Microsoft JhengHei","Segoe UI",sans-serif;color:#233a45;background:#f2f5f5;line-height:1.65}*{box-sizing:border-box}body{margin:0}header{background:#123a43;color:#fff;padding:42px max(24px,calc((100vw - 1080px)/2))}header small{color:#9edacc;letter-spacing:.13em}h1{margin:8px 0;font-size:32px}main{max-width:1080px;margin:auto;padding:24px}.meta{opacity:.85;font-size:14px;overflow-wrap:anywhere}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:0 0 24px}.stat,.finding,.coverage,.empty{background:#fff;border:1px solid #dbe5e6;border-radius:12px;padding:22px;margin-bottom:16px}.stat{margin:0}.stat b{display:block;font-size:30px;color:#146b63}.toolbar{display:flex;gap:12px;margin:20px 0;position:sticky;top:0;background:#f2f5f5;padding:12px 0;z-index:1}input,select{border:1px solid #b9cccf;border-radius:8px;padding:12px;background:#fff;font:inherit}input{flex:1;min-width:0}.finding-head{display:flex;gap:12px;align-items:flex-start}.finding h2{font-size:19px;margin:0}.severity{background:#fff0dd;color:#874a0b;border-radius:6px;padding:2px 10px;white-space:nowrap}.location,.muted{color:#5d727b;font-size:14px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf3f4;padding:16px;border-radius:8px;font-family:Consolas,"Microsoft JhengHei",monospace;font-size:13px}h3{font-size:15px;margin-bottom:0}summary{cursor:pointer;color:#13695f}details{margin-top:12px}li{margin:10px 0;overflow-wrap:anywhere}.warning{color:#8b4b20}footer{font-size:13px;color:#5d727b;padding:24px 0}a{color:#176d66}[hidden]{display:none!important}@media(max-width:600px){.stats{grid-template-columns:1fr}.toolbar{flex-wrap:wrap}header{padding:28px 20px}main{padding:14px}}
</style><header><small>WEB SOURCE SCANNER · LOCAL ANALYSIS</small>"#,
    );
    out.push_str(&format!("<h1>{name}</h1><p>網站原始碼檢查報告 · {}</p><div class=\"meta\">{}<br>掃描時間：{}<br>工具 {} · 規則 {}</div></header><main><div class=\"stats\"><div class=\"stat\">此分類發現<b>{}</b></div><div class=\"stat\">嚴重／高風險<b>{high}</b></div><div class=\"stat\">已列入本機檢查的檔案<b>{}</b></div></div><section class=\"coverage\"><strong>判讀方式</strong><p>掃描命中是待確認的問題或改善線索。嚴重度與判定信心分開評估；效能項目未經執行量測。</p><details><summary>查看掃描範圍、引擎與限制</summary><ul>{engines}</ul><ul>{warnings}</ul><details><summary>排除清單（{} 項）</summary><ul>{excluded}</ul></details></details></section><div class=\"toolbar\"><input id=\"search\" placeholder=\"搜尋問題、檔案或修正建議\" aria-label=\"搜尋\"><select id=\"severity\" aria-label=\"嚴重度\"><option value=\"\">全部嚴重度</option><option>嚴重</option><option>高</option><option>中</option><option>低</option><option>資訊</option></select></div><p id=\"count\" class=\"muted\"></p>{rows}<footer>本報告可離線閱讀。原始碼未上傳；敏感憑證預設遮蔽。完整機器可讀結果與覆蓋資訊請參閱同資料夾 JSON。</footer></main>",escape(state_name(report.state)),escape(&report.root),escape(&report.started_at),escape(&report.tool_version),escape(&report.rule_version),findings.len(),report.files.len(),report.excluded.len()));
    out.push_str(r#"<script>const q=document.getElementById('search'),s=document.getElementById('severity'),r=[...document.querySelectorAll('.finding')];function filter(){let n=0;for(const e of r){e.hidden=!(e.textContent.toLocaleLowerCase().includes(q.value.toLocaleLowerCase())&&(!s.value||e.dataset.severity===s.value));if(!e.hidden)n++}document.getElementById('count').textContent=`顯示 ${n} / ${r.length} 筆`}q.addEventListener('input',filter);s.addEventListener('change',filter);filter();</script></html>"#);
    out
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut existing = absolute.as_path();
    let mut suffix = vec![];
    while !existing.exists() {
        suffix.push(
            existing
                .file_name()
                .ok_or("無法解析輸出路徑")?
                .to_os_string(),
        );
        existing = existing.parent().ok_or("無法解析輸出路徑")?;
    }
    let mut full = existing.canonicalize().map_err(|e| e.to_string())?;
    for part in suffix.into_iter().rev() {
        full.push(part);
    }
    Ok(full)
}

pub fn export_report(
    report: &ScanReport,
    output: &Path,
    category: Option<Category>,
) -> Result<Vec<PathBuf>, String> {
    let output = normalized_absolute(output)?;
    if let Ok(root) = normalized_absolute(Path::new(&report.root)) {
        let dest = output.to_string_lossy().replace('\\', "/").to_lowercase();
        let root = root.to_string_lossy().replace('\\', "/").to_lowercase();
        if dest == root || dest.starts_with(&(root + "/")) {
            return Err("匯出位置不能在受掃描網站內，請選擇另一個資料夾。".into());
        }
    }
    let mut safe = serde_json::to_value(report).map_err(|e| e.to_string())?;
    scrub(&mut safe);
    let safe: ScanReport = serde_json::from_value(safe).map_err(|e| e.to_string())?;
    let mut summary = serde_json::to_value(&safe).map_err(|e| e.to_string())?;
    summary.as_object_mut().unwrap().remove("findings");
    summary["finding_counts"] = json!({"security":safe.findings.iter().filter(|f|f.category==Category::Security).count(),"quality_performance":safe.findings.iter().filter(|f|f.category==Category::QualityPerformance).count()});
    summary["exported_category"] = json!(category);
    let mut payloads = vec![(
        "scan-summary.json".to_string(),
        serde_json::to_vec_pretty(&summary).map_err(|e| e.to_string())?,
    )];
    for (cat, stem) in [
        (Category::Security, "security-vulnerabilities"),
        (Category::QualityPerformance, "code-quality-performance"),
    ] {
        if category.is_some_and(|c| c != cat) {
            continue;
        }
        let findings = safe
            .findings
            .iter()
            .filter(|f| f.category == cat)
            .collect::<Vec<_>>();
        let value =
            json!({"schema_version":"1.0","category":cat,"scan":summary,"findings":findings});
        payloads.push((
            format!("{stem}.json"),
            serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
        ));
        payloads.push((format!("{stem}.csv"), csv(&findings).into_bytes()));
        payloads.push((
            format!("{stem}.html"),
            html(&safe, cat, &findings).into_bytes(),
        ));
    }
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let mut paths = vec![];
    for (name, bytes) in payloads {
        let mut temp = tempfile::NamedTempFile::new_in(&output).map_err(|e| e.to_string())?;
        temp.write_all(&bytes).map_err(|e| e.to_string())?;
        temp.flush().map_err(|e| e.to_string())?;
        let path = output.join(name);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        temp.persist(&path).map_err(|e| e.to_string())?;
        paths.push(path);
    }
    Ok(paths)
}
