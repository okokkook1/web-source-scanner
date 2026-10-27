use clap::{Parser, ValueEnum};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use web_source_scanner::{model::*, report::export_report, scan::run_scan};

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    All,
    Security,
    Quality,
}
#[derive(Parser)]
#[command(version, about = "網站原始碼掃描工具：Windows 中文介面與本機分析引擎")]
struct Args {
    #[arg(long, help = "以命令列掃描此資料夾")]
    scan: Option<PathBuf>,
    #[arg(long, help = "報告輸出資料夾（不可位於受掃描網站內）")]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "all")]
    mode: Mode,
    #[arg(long, help = "Semgrep CE Core 原生執行檔路徑")]
    engine: Option<PathBuf>,
    #[arg(long, help = "選配 Dependency-Check CLI 路徑（須有本機資料庫）")]
    dependency_check: Option<PathBuf>,
    #[arg(long, help = "選配匯入既有 Dependency-Check JSON")]
    dependency_report: Option<PathBuf>,
    #[arg(long, help = "額外排除路徑片段，可重複指定")]
    exclude: Vec<String>,
    #[arg(long,default_value_t=180,value_parser=clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,
    #[arg(long, help = "線上查詢套件漏洞（OSV.dev；只送套件名稱與版本）")]
    osv: bool,
    #[arg(long, help = "開啟視窗並預填資料夾，不自動開始掃描")]
    gui_root: Option<PathBuf>,
}

pub fn run() {
    let args = Args::parse();
    if let Some(root) = args.scan {
        let mut options = ScanOptions::new(root);
        options.mode = match args.mode {
            Mode::All => None,
            Mode::Security => Some(Category::Security),
            Mode::Quality => Some(Category::QualityPerformance),
        };
        options.engine = args.engine;
        options.dependency_check = args.dependency_check;
        options.dependency_report = args.dependency_report;
        options.excludes = args.exclude;
        options.timeout_secs = args.timeout;
        options.osv = args.osv;
        let report = run_scan(options, Arc::new(AtomicBool::new(false)), |p| {
            if p.stage != "本機檢查" {
                eprintln!("{}：{}", p.stage, p.message);
            }
        });
        let output = args.output.unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("reports").join(&report.scan_id)))
                .unwrap_or_else(|| PathBuf::from("reports").join(&report.scan_id))
        });
        match export_report(&report, &output, None) {
            Ok(paths) => {
                println!(
                    "{}",
                    serde_json::json!({"state":report.state,"findings":report.findings.len(),"files":report.files.len(),"reports":paths})
                );
            }
            Err(e) => {
                eprintln!("匯出失敗：{e}");
                std::process::exit(1);
            }
        }
        std::process::exit(match report.state {
            ScanState::Complete => 0,
            ScanState::Partial => 2,
            ScanState::Cancelled => 130,
            ScanState::Failed => 1,
        });
    }
    #[cfg(feature = "gui")]
    if let Err(e) = crate::gui::launch(args.gui_root, args.engine) {
        eprintln!("無法開啟視窗：{e}");
        std::process::exit(1);
    }
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("此組建沒有視窗介面；請指定 --scan 與 --output。");
        std::process::exit(1);
    }
}
