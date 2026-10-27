use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Security,
    QualityPerformance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub category: Category,
    pub subcategory: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: String,
    pub review_status: String,
    pub engine: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub evidence: String,
    pub description: String,
    pub recommendation: String,
    pub limitations: String,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub mode: Option<Category>,
    pub excludes: Vec<String>,
    pub engine: Option<PathBuf>,
    pub dependency_check: Option<PathBuf>,
    pub dependency_report: Option<PathBuf>,
    pub timeout_secs: u64,
    pub max_file_bytes: u64,
    #[serde(default)]
    pub osv: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub relative: String,
    pub text: String,
    pub encoding: String,
    pub extension: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub files: Vec<SourceFile>,
    pub enumerated: usize,
    pub excluded: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub technologies: Vec<String>,
    pub cancelled: bool,
}

pub struct DecodedSource {
    pub text: String,
    pub encoding: String,
}

impl ScanOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            mode: None,
            excludes: vec![],
            engine: None,
            dependency_check: None,
            dependency_report: None,
            timeout_secs: 180,
            max_file_bytes: 2_000_000,
            osv: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub name: String,
    pub version: String,
    pub status: String,
    pub eligible: usize,
    pub scanned: usize,
    pub errors: Vec<String>,
    pub limitations: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverage {
    pub file: String,
    pub encoding: String,
    pub local: String,
    pub semgrep: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub file: String,
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub tool_version: String,
    pub rule_version: String,
    pub scan_id: String,
    pub root: String,
    pub started_at: String,
    pub finished_at: String,
    pub state: ScanState,
    pub mode: Option<Category>,
    pub technologies: Vec<String>,
    pub enumerated: usize,
    pub files: Vec<FileCoverage>,
    pub excluded: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub engines: Vec<EngineStatus>,
    pub packages: Vec<PackageInfo>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub stage: String,
    pub message: String,
    pub done: usize,
    pub total: usize,
}
