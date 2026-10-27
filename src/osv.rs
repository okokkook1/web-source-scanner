//! Optional NuGet vulnerability lookup through OSV.dev.
//!
//! Only package names and versions are sent; source code is never uploaded.
//! The lookup is off by default and requires network access. Responses are
//! cached on disk for a day so repeated scans stay fast and gentle.

use crate::model::*;
use crate::rules::redact;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

const CACHE_TTL_SECS: i64 = 86_400;

pub struct OsvOutcome {
    pub findings: Vec<Finding>,
    pub status: EngineStatus,
    pub warnings: Vec<String>,
}

fn endpoint() -> String {
    std::env::var("WSS_OSV_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://api.osv.dev/v1/query".into())
}

pub fn query_body(id: &str, version: &str) -> String {
    json!({"package": {"name": id, "ecosystem": "NuGet"}, "version": version}).to_string()
}

fn severity_of(vuln: &Value) -> Severity {
    let raw = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_uppercase();
    match raw.as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn fixed_versions(vuln: &Value, id: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let Some(affected) = vuln.get("affected").and_then(|a| a.as_array()) else {
        return vec![];
    };
    for entry in affected {
        let name = entry
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let ecosystem = entry
            .get("package")
            .and_then(|p| p.get("ecosystem"))
            .and_then(|e| e.as_str())
            .unwrap_or("");
        if !ecosystem.eq_ignore_ascii_case("NuGet") || !name.eq_ignore_ascii_case(id) {
            continue;
        }
        if let Some(ranges) = entry.get("ranges").and_then(|r| r.as_array()) {
            for range in ranges {
                if let Some(events) = range.get("events").and_then(|e| e.as_array()) {
                    for event in events {
                        if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                            out.insert(fixed.to_string());
                        }
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

fn aliases(vuln: &Value) -> Vec<String> {
    vuln.get("aliases")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn cwes(vuln: &Value) -> Vec<String> {
    vuln.get("database_specific")
        .and_then(|d| d.get("cwe_ids"))
        .and_then(|c| c.as_array())
        .map(|c| {
            c.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn parse_response(raw: &str, package: &PackageInfo) -> Result<Vec<Finding>, String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|e| format!("OSV 回應不是有效 JSON：{e}"))?;
    let Some(vulns) = value.get("vulns").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };
    let mut findings = vec![];
    for vuln in vulns {
        let vuln_id = vuln
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("OSV-UNKNOWN");
        let summary = vuln
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("已知套件漏洞");
        let details = vuln.get("details").and_then(|d| d.as_str()).unwrap_or("");
        let fixed = fixed_versions(vuln, &package.id);
        let aliases = aliases(vuln);
        let cwe = cwes(vuln);
        let severity = severity_of(vuln);
        let digest = Sha256::digest(format!(
            "osv:{vuln_id}:{}:{}",
            package.id.to_lowercase(),
            package.version
        ));
        let evidence = format!(
            "套件：{} {}（{}:{}）\n漏洞：{} {}\n別名：{}\n修復版本：{}",
            package.id,
            package.version,
            package.file,
            package.line.max(1),
            vuln_id,
            summary,
            if aliases.is_empty() {
                "無".to_string()
            } else {
                aliases.join(", ")
            },
            if fixed.is_empty() {
                "公告未提供".to_string()
            } else {
                fixed.join(", ")
            }
        );
        let mut references = vec![format!("https://osv.dev/vulnerability/{vuln_id}")];
        for alias in &aliases {
            if alias.starts_with("CVE-") {
                references.push(format!("https://nvd.nist.gov/vuln/detail/{alias}"));
            }
        }
        findings.push(Finding {
            id: format!("{:x}", digest)[..16].to_string(),
            rule_id: format!("DEP-OSV-{vuln_id}"),
            category: Category::Security,
            subcategory: "套件漏洞".into(),
            title: format!("套件 {} {} 已知漏洞：{vuln_id}", package.id, package.version),
            severity,
            confidence: "高".into(),
            review_status: "版本命中，仍需確認實際載入版本與可達性".into(),
            engine: "OSV.dev".into(),
            file: package.file.clone(),
            start_line: package.line.max(1),
            end_line: package.line.max(1),
            evidence: redact(&evidence),
            description: {
                let trimmed: String = details.chars().take(400).collect();
                redact(if trimmed.is_empty() { summary } else { &trimmed })
            },
            recommendation: if fixed.is_empty() {
                "查閱 OSV／GHSA 公告確認修復版本；必要時評估替代套件或補償控制。".into()
            } else {
                format!(
                    "升級至 {} 以上（優先 {}），並核對相依套件相容性、授權與部署後的實際版本。",
                    fixed.join("／"),
                    fixed[0]
                )
            },
            limitations: "以 OSV.dev 當下資料比對 NuGet 套件名稱與版本；未確認 DLL 實際版本、載入路徑、使用方式或程式碼可達性。".into(),
            references,
            cwe,
        });
    }
    Ok(findings)
}

fn cache_path() -> Option<PathBuf> {
    let base = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)?;
    Some(base.join("WebSourceScanner").join("osv-cache.json"))
}

fn load_cache() -> BTreeMap<String, (i64, String)> {
    let Some(path) = cache_path() else {
        return BTreeMap::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return BTreeMap::new();
    };
    let mut cache = BTreeMap::new();
    if let Some(entries) = value.get("entries").and_then(|e| e.as_object()) {
        for (key, entry) in entries {
            let Some(time) = entry.get("time").and_then(|t| t.as_i64()) else {
                continue;
            };
            let Some(body) = entry.get("body").and_then(|b| b.as_str()) else {
                continue;
            };
            cache.insert(key.clone(), (time, body.to_string()));
        }
    }
    cache
}

fn save_cache(cache: &BTreeMap<String, (i64, String)>) {
    let Some(path) = cache_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let entries = cache
        .iter()
        .map(|(k, (t, b))| (k.clone(), json!({"time": t, "body": b})))
        .collect::<serde_json::Map<_, _>>();
    let _ = std::fs::write(path, json!({"entries": entries}).to_string());
}

fn post(body: &str, timeout_secs: u64) -> Result<String, String> {
    let timeout = timeout_secs.clamp(5, 30).to_string();
    let endpoint = endpoint();
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            &timeout,
            "--header",
            "Content-Type: application/json",
            "--request",
            "POST",
            "--data-binary",
            "@-",
            &endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("無法啟動 curl.exe 進行 OSV 查詢：{e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("無法寫入 OSV 查詢")?
        .write_all(body.as_bytes())
        .map_err(|e| format!("無法送出 OSV 查詢：{e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("OSV 查詢中斷：{e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "OSV 查詢失敗（curl 代碼 {}）：{}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    if stdout.trim().is_empty() {
        return Err("OSV 回應為空".into());
    }
    Ok(stdout)
}

pub fn lookup(packages: &[PackageInfo], cancel: &AtomicBool, timeout_secs: u64) -> OsvOutcome {
    let mut unique = BTreeMap::new();
    for package in packages {
        unique
            .entry(format!(
                "{}@{}",
                package.id.to_lowercase(),
                package.version.to_lowercase()
            ))
            .or_insert(package);
    }
    let eligible = unique.len();
    let mut findings = vec![];
    let mut errors = vec![];
    let mut scanned = 0usize;
    let mut cache = load_cache();
    let now = chrono::Utc::now().timestamp();
    for (key, package) in &unique {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let cached = cache
            .get(key)
            .filter(|(time, _)| now - time < CACHE_TTL_SECS)
            .map(|(_, body)| body.clone());
        let body = match cached {
            Some(body) => Some(body),
            None => match post(&query_body(&package.id, &package.version), timeout_secs) {
                Ok(body) => {
                    cache.insert(key.clone(), (now, body.clone()));
                    Some(body)
                }
                Err(e) => {
                    errors.push(format!("{} {}：{}", package.id, package.version, e));
                    None
                }
            },
        };
        let Some(body) = body else {
            continue;
        };
        match parse_response(&body, package) {
            Ok(mut list) => {
                scanned += 1;
                findings.append(&mut list);
            }
            Err(e) => errors.push(format!("{} {}：{}", package.id, package.version, e)),
        }
    }
    save_cache(&cache);
    let status = if errors.is_empty() {
        "complete"
    } else if scanned == 0 {
        "failed"
    } else {
        "partial"
    };
    OsvOutcome {
        findings,
        status: EngineStatus {
            name: "OSV.dev".into(),
            version: String::new(),
            status: status.into(),
            eligible,
            scanned,
            errors: errors.into_iter().map(|e| redact(&e)).collect(),
            limitations: "僅比對 packages.config 的 NuGet 名稱與版本；線上查詢，未驗證實際載入的 DLL 或程式碼可達性。".into(),
            metadata: json!({"endpoint": endpoint(), "cache": cache_path().map(|p| p.to_string_lossy().into_owned())}),
        },
        warnings: if eligible == 0 {
            vec![]
        } else {
            vec![format!(
                "OSV 查詢會把 {} 組套件名稱與版本送到 api.osv.dev（不含原始碼）；結果快取 24 小時。",
                eligible
            )]
        },
    }
}
