use crate::model::*;
use crate::rules::{make_finding, redact, rule_catalog};
use serde_json::Value;
use sha2::Digest;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
pub struct ProcessOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub cancelled: bool,
    pub timed_out: bool,
}
pub struct EngineResults {
    pub findings: Vec<Finding>,
    pub status: EngineStatus,
    pub scanned: Vec<String>,
}

#[cfg(windows)]
struct ProcessJob(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl ProcessJob {
    fn attach(child: &std::process::Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{Foundation::CloseHandle, System::JobObjects::*};
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err("無法建立引擎程序群組".into());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0
            {
                CloseHandle(handle);
                return Err(format!(
                    "無法限制引擎程序群組：{}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(handle))
        }
    }
}
#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub fn run_process(
    mut command: Command,
    cancel: &AtomicBool,
    timeout: u64,
) -> Result<ProcessOutput, String> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(ProcessOutput {
            code: -1,
            stdout: String::new(),
            stderr: String::new(),
            cancelled: true,
            timed_out: false,
        });
    }
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let out = dir.path().join("stdout.json");
    let err = dir.path().join("stderr.txt");
    command
        .stdin(Stdio::null())
        .stdout(fs::File::create(&out).map_err(|e| e.to_string())?)
        .stderr(fs::File::create(&err).map_err(|e| e.to_string())?);
    let mut managed = spawn_paused(command)?;
    if let Err(e) = managed.resume() {
        managed.terminate();
        return Err(e);
    }
    let start = Instant::now();
    let mut cancelled = false;
    let mut timed_out = false;
    let code = loop {
        if let Some(status) = managed.child.try_wait().map_err(|e| e.to_string())? {
            break status.code().unwrap_or(-1);
        }
        cancelled = cancel.load(Ordering::Relaxed);
        timed_out = start.elapsed() > Duration::from_secs(timeout.max(1));
        let too_large = fs::metadata(&out)
            .map(|m| m.len() > 64 * 1024 * 1024)
            .unwrap_or(false);
        if cancelled || timed_out || too_large {
            managed.terminate();
            if too_large {
                return Err("引擎輸出超過 64 MiB 上限".into());
            }
            break -1;
        }
        thread::sleep(Duration::from_millis(40));
    };
    let stdout = fs::read_to_string(out).map_err(|_| "引擎輸出不是有效 UTF-8".to_string())?;
    let stderr = fs::read(err)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    Ok(ProcessOutput {
        code,
        stdout,
        stderr: redact(&stderr),
        cancelled,
        timed_out,
    })
}

pub struct PausedProcess {
    pub child: std::process::Child,
    #[cfg(windows)]
    job: Option<ProcessJob>,
}
impl PausedProcess {
    pub fn resume(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
                System::{
                    Diagnostics::ToolHelp::*,
                    Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
                },
            };
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err("無法列舉暫停的引擎執行緒".into());
                }
                let mut entry: THREADENTRY32 = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                let mut ids = vec![];
                let mut found = Thread32First(snapshot, &mut entry);
                while found != 0 {
                    if entry.th32OwnerProcessID == self.child.id() {
                        ids.push(entry.th32ThreadID);
                    }
                    found = Thread32Next(snapshot, &mut entry);
                }
                CloseHandle(snapshot);
                // CREATE_SUSPENDED prevents engine code from running before Job attachment.
                // There must be exactly one initial thread; fail closed otherwise.
                if ids.len() != 1 {
                    return Err("無法唯一辨識引擎的暫停主執行緒".into());
                }
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, ids[0]);
                if thread.is_null() {
                    return Err("無法開啟引擎主執行緒".into());
                }
                let previous = ResumeThread(thread);
                CloseHandle(thread);
                if previous != 1 {
                    return Err("引擎主執行緒並非預期的暫停狀態".into());
                }
            }
        }
        Ok(())
    }
    pub fn terminate(&mut self) {
        #[cfg(windows)]
        self.job.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub fn spawn_paused(mut command: Command) -> Result<PausedProcess, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000 | 0x00000004);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let job = match ProcessJob::attach(&child) {
        Ok(j) => j,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    Ok(PausedProcess {
        child,
        #[cfg(windows)]
        job: Some(job),
    })
}

fn relative_engine_path(path: &str, mirror: &Path) -> Option<String> {
    let path = path.replace('\\', "/");
    let prefix = mirror.to_string_lossy().replace('\\', "/");
    let rel = if path
        .to_lowercase()
        .starts_with(&(prefix.to_lowercase() + "/"))
    {
        path[prefix.len() + 1..].to_string()
    } else if Path::new(&path).is_absolute() || path.contains(':') {
        return None;
    } else {
        path.trim_start_matches("./").to_string()
    };
    if rel.split('/').any(|s| s == ".." || s.is_empty()) {
        None
    } else {
        Some(rel)
    }
}

pub fn parse_semgrep(
    json: &str,
    files: &[SourceFile],
    mirror: &Path,
) -> Result<EngineResults, String> {
    let data: Value = serde_json::from_str(json).map_err(|_| "引擎 JSON 無法解析".to_string())?;
    let rows = data
        .get("results")
        .and_then(Value::as_array)
        .ok_or("引擎缺少 results 陣列")?;
    let mut status = EngineStatus {
        metadata: serde_json::Value::Null,
        name: "Semgrep CE Core".into(),
        version: data["version"].as_str().unwrap_or("unknown").into(),
        status: "complete".into(),
        eligible: files.len(),
        scanned: 0,
        errors: vec![],
        limitations: "僅 C#／JavaScript；函式內資料流與語法模式，不含付費跨檔案分析。".into(),
    };
    let mut scanned = vec![];
    let mut findings = vec![];
    if let Some(paths) = data["paths"]["scanned"].as_array() {
        for path in paths.iter().filter_map(Value::as_str) {
            if let Some(rel) = relative_engine_path(path, mirror)
                && files.iter().any(|f| f.relative == rel)
            {
                scanned.push(rel);
            } else {
                status.errors.push("引擎回傳不在掃描清單內的路徑".into());
            }
        }
    } else {
        status.errors.push("引擎未提供已掃描路徑清單".into());
    }
    for row in rows {
        let id = row["check_id"].as_str().unwrap_or("");
        let rel = relative_engine_path(row["path"].as_str().unwrap_or(""), mirror);
        let file = rel.and_then(|r| files.iter().find(|f| f.relative == r));
        if let Some(file) = file
            && rule_catalog().iter().any(|r| r.id == id)
        {
            let line = row["start"]["line"].as_u64().unwrap_or(0) as usize;
            let end = row["end"]["line"].as_u64().unwrap_or(0) as usize;
            if line == 0 || end < line || line > file.text.lines().count().max(1) {
                status
                    .errors
                    .push(format!("{}：引擎行號不合法", file.relative));
                continue;
            }
            let mut f = make_finding(id, file, line, end);
            if let Some(trace) = row["extra"].get("dataflow_trace") {
                let source_line = trace["taint_source"][1][0]["start"]["line"].as_u64();
                if let Some(source_line) = source_line {
                    f.description = format!(
                        "{}。函式內輸入來源第 {} 行 → 敏感操作第 {} 行。",
                        f.title, source_line, line
                    );
                }
            }
            findings.push(f);
        } else {
            status
                .errors
                .push("引擎命中未知規則或清單以外的檔案".into());
        }
    }
    if let Some(errors) = data["errors"].as_array() {
        for e in errors {
            let typ = e["error_type"]
                .as_str()
                .or_else(|| e["type"].as_str())
                .unwrap_or("analysis_error");
            let rel = e["location"]["path"]
                .as_str()
                .and_then(|p| relative_engine_path(p, mirror))
                .unwrap_or_else(|| "無可對映路徑".into());
            status.errors.push(format!(
                "{}：{}（該檔案／規則可能未完整分析）",
                redact(&rel),
                redact(typ)
            ));
        }
    } else {
        status.errors.push("引擎未提供 errors 陣列".into());
    }
    scanned.sort();
    scanned.dedup();
    status.scanned = scanned.len();
    if !status.errors.is_empty() || scanned.len() < files.len() {
        status.status = "partial".into();
    }
    Ok(EngineResults {
        findings,
        status,
        scanned,
    })
}

pub fn import_dependency_check(json: &str) -> Result<Vec<Finding>, String> {
    let data: Value = serde_json::from_str(json).map_err(|_| "套件報告 JSON 無法解析")?;
    let deps = data["dependencies"]
        .as_array()
        .ok_or("套件報告缺少 dependencies")?;
    let mut result = vec![];
    for dep in deps {
        let pkg = dep["packages"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| p["id"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        if let Some(vulns) = dep["vulnerabilities"].as_array() {
            for v in vulns {
                let name = v["name"].as_str().unwrap_or("未知漏洞");
                let source = SourceFile {
                    relative: dep["fileName"].as_str().unwrap_or("packages.config").into(),
                    text: String::new(),
                    encoding: "".into(),
                    extension: "config".into(),
                };
                let mut f = make_finding("LOCAL-SECRET", &source, 1, 1);
                f.rule_id = "DEPENDENCY-CVE".into();
                f.id = format!("{}:{pkg}:{name}", source.relative);
                f.title = format!("套件已知漏洞：{name}");
                f.description = redact(&format!(
                    "{pkg}：{}",
                    v["description"].as_str().unwrap_or("請查閱漏洞公告")
                ));
                f.evidence = redact(&pkg);
                f.engine = "OWASP Dependency-Check".into();
                f.subcategory = "套件已知漏洞".into();
                f.confidence = "中".into();
                f.severity = match v["severity"].as_str().unwrap_or("").to_uppercase().as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "LOW" => Severity::Low,
                    _ => Severity::Medium,
                };
                f.recommendation = "核對受影響版本與使用條件，升級到已修正版本並重新測試。".into();
                f.review_status = "待人工確認套件對映與可利用條件".into();
                f.limitations="來自外部套件報告；CPE 對映可能誤判，無法據此證明執行路徑可達。行號 1 為清單檔案定位。".into();
                f.cwe = vec![];
                f.references = v["references"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|r| r["url"].as_str())
                            .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                result.push(f);
            }
        }
    }
    Ok(result)
}

pub struct DependencyAnalysis {
    pub findings: Vec<Finding>,
    pub identities: std::collections::BTreeSet<(String, String)>,
    pub version: String,
    pub metadata: Value,
    pub errors: Vec<String>,
}

pub fn parse_dependency_analysis(json: &str) -> Result<DependencyAnalysis, String> {
    let findings = import_dependency_check(json)?;
    let data: Value = serde_json::from_str(json).map_err(|_| "無法解析套件報告")?;
    let mut identities = std::collections::BTreeSet::new();
    let mut errors = vec![];
    let deps = data["dependencies"].as_array().ok_or("缺少套件陣列")?;
    for dep in deps {
        if let Some(packages) = dep["packages"].as_array() {
            for p in packages {
                if let Some(id) = p["id"].as_str().and_then(|p| p.strip_prefix("pkg:nuget/"))
                    && let Some((name, version)) =
                        id.split('?').next().unwrap_or(id).rsplit_once('@')
                {
                    identities.insert((name.to_lowercase(), version.to_lowercase()));
                }
            }
        }
        if let Some(exceptions) = dep["analysisExceptions"].as_array() {
            for _ in exceptions {
                errors.push("外部報告含套件分析錯誤，請核對原始報告。".into());
            }
        }
    }
    if let Some(exceptions) = data["scanInfo"]["analysisExceptions"].as_array() {
        for _ in exceptions {
            errors.push("外部報告含掃描分析錯誤。".into());
        }
    }
    let sources=data["scanInfo"]["dataSource"].as_array().map(|a|a.iter().map(|s|serde_json::json!({"name":s["name"].as_str().unwrap_or("unknown"),"timestamp":s["timestamp"].as_str().unwrap_or("unknown")})).collect::<Vec<_>>()).unwrap_or_default();
    Ok(DependencyAnalysis {
        findings,
        identities,
        version: data["scanInfo"]["engineVersion"]
            .as_str()
            .unwrap_or("unknown")
            .into(),
        metadata: serde_json::json!({"report_date":data["projectInfo"]["reportDate"].as_str().unwrap_or("unknown"),"database_sources":sources,"dependency_count":deps.len(),"report_sha256":format!("{:x}",sha2::Sha256::digest(json.as_bytes()))}),
        errors,
    })
}

pub fn detect_engine() -> Option<PathBuf> {
    let mut candidates = vec![];
    if let Ok(path) = std::env::var("WSS_ENGINE") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        candidates.push(parent.join("engine/semgrep-core.exe"));
    }
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../outputs/web-source-scanner/engine/semgrep-core.exe"),
    );
    candidates.into_iter().find(|p| p.is_file())
}

pub fn run_semgrep(
    engine: &Path,
    files: &[SourceFile],
    cancel: &AtomicBool,
    timeout: u64,
) -> Result<EngineResults, String> {
    let work = tempfile::tempdir().map_err(|e| e.to_string())?;
    let rules = work.path().join("website.yml");
    fs::write(&rules, include_str!("../rules/website.yml")).map_err(|e| e.to_string())?;
    let mut combined = EngineResults {
        findings: vec![],
        scanned: vec![],
        status: EngineStatus {
            metadata: serde_json::Value::Null,
            name: "Semgrep CE Core".into(),
            version: String::new(),
            status: "complete".into(),
            eligible: files.len(),
            scanned: 0,
            errors: vec![],
            limitations: "函式內資料流；無跨檔案分析；Razor／設定檔由 Rust 專用規則檢查。".into(),
        },
    };
    let start = Instant::now();
    for (lang, ext) in [("csharp", "cs"), ("javascript", "js")] {
        let selected = files
            .iter()
            .filter(|f| f.extension == ext)
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let mirror = work.path().join(lang);
        fs::create_dir_all(&mirror).map_err(|e| e.to_string())?;
        for file in &selected {
            if Path::new(&file.relative)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err("不合法的來源相對路徑".into());
            }
            let path = mirror.join(&file.relative);
            fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
            fs::write(path, &file.text).map_err(|e| e.to_string())?;
        }
        // Native core accepts a single -lang file, or this explicit target plan.
        // Match the pinned 1.182.0 wheel's semgrep_output_v1 Targets schema.
        let targets=selected.iter().map(|f|serde_json::json!(["CodeTarget",{"path":{"fpath":mirror.join(&f.relative).to_string_lossy(),"ppath":format!("/{}",f.relative)},"analyzer":lang,"products":["sast"]}])).collect::<Vec<_>>();
        let target_plan = work.path().join(format!("{lang}-targets.json"));
        fs::write(
            &target_plan,
            serde_json::to_vec(&serde_json::json!(["Targets", targets]))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut cmd = Command::new(engine);
        cmd.args(["-json_nodots", "-rules"])
            .arg(&rules)
            .arg("-targets")
            .arg(&target_plan)
            .args([
                "-j",
                "2",
                "-timeout",
                "5",
                "-timeout_threshold",
                "3",
                "-max_memory",
                "2048",
                "-max_match_per_file",
                "10000",
            ]);
        cmd.current_dir(work.path())
            .env("SEMGREP_SEND_METRICS", "off")
            .env("SEMGREP_ENABLE_VERSION_CHECK", "0")
            .env_remove("SEMGREP_APP_TOKEN")
            .env_remove("SEMGREP_AGENT_ID");
        let remaining = timeout.saturating_sub(start.elapsed().as_secs());
        if remaining == 0 {
            combined.status.status = "timeout".into();
            combined.status.errors.push("分析超過總時間上限".into());
            break;
        }
        let raw = run_process(cmd, cancel, remaining)?;
        if raw.cancelled || raw.timed_out {
            combined.status.status = if raw.cancelled {
                "cancelled"
            } else {
                "timeout"
            }
            .into();
            combined
                .status
                .errors
                .push("引擎已取消或逾時，結果不完整".into());
            break;
        }
        let parsed = parse_semgrep(&raw.stdout, &selected, &mirror);
        match parsed {
            Ok(p) => {
                combined.status.version = p.status.version;
                combined.status.errors.extend(p.status.errors);
                combined.findings.extend(p.findings);
                combined.scanned.extend(p.scanned);
            }
            Err(e) => combined.status.errors.push(format!("{lang}：{e}")),
        }
        if raw.code != 0 {
            combined
                .status
                .errors
                .push(format!("{lang}：引擎非正常結束，代碼 {}", raw.code));
        }
    }
    combined.scanned.sort();
    combined.scanned.dedup();
    combined.status.scanned = combined.scanned.len();
    if combined.status.status == "complete"
        && (!combined.status.errors.is_empty() || combined.status.scanned < files.len())
    {
        combined.status.status = "partial".into();
    }
    Ok(combined)
}

pub fn dependency_check_command(path: &Path, mirror: &Path, out: &Path) -> Result<Command, String> {
    let mut cmd = if path.extension().is_some_and(|e| e == "bat" || e == "sh") {
        let parent = path.parent().ok_or("無法辨識 Dependency-Check 目錄")?;
        let lib = if parent.join("lib").is_dir() {
            parent.join("lib")
        } else {
            parent.parent().ok_or("缺少 lib")?.join("lib")
        };
        if !lib.is_dir() {
            return Err("找不到 Dependency-Check lib；請指定完整 CLI 套件內的啟動檔".into());
        }
        let mut c = Command::new("java");
        c.arg("-cp")
            .arg(lib.join("*"))
            .arg("org.owasp.dependencycheck.App");
        c
    } else {
        Command::new(path)
    };
    let data = path.parent().unwrap_or(Path::new(".")).join("data");
    cmd.args([
        "--project",
        "WebSourceScanner",
        "--format",
        "JSON",
        "--noupdate",
        "--disableNodeAudit",
        "--disableYarnAudit",
        "--disablePnpmAudit",
        "--disableOssIndex",
        "--disableNodeJS",
        "--disableAssembly",
        "--disableCentral",
        "--disableNexus",
        "--disableArtifactory",
    ])
    .arg("--data")
    .arg(data)
    .arg("--scan")
    .arg(mirror)
    .arg("--out")
    .arg(out);
    Ok(cmd)
}
