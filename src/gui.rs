use eframe::egui::{self, Color32, RichText};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::Duration,
};
use web_source_scanner::{
    engine::detect_engine,
    model::*,
    report::{category_name, export_report, severity_name, state_name},
    rules::rule_catalog,
    scan::run_scan,
};

const TEAL: Color32 = Color32::from_rgb(20, 100, 96);
const INK: Color32 = Color32::from_rgb(25, 57, 66);
const MUTED: Color32 = Color32::from_rgb(100, 118, 125);

enum Message {
    Progress(Progress),
    Finished(Box<ScanReport>),
    Exported(Result<(PathBuf, usize), String>),
    Failed(String),
}
struct App {
    source: String,
    engine: String,
    excludes: String,
    timeout: u64,
    scan_mode: Option<Category>,
    dependency: String,
    dependency_json: String,
    report: Option<ScanReport>,
    category: Option<Category>,
    severity: Option<Severity>,
    search: String,
    selected: Option<usize>,
    cancel: Arc<AtomicBool>,
    receiver: Option<Receiver<Message>>,
    busy: bool,
    exporting: bool,
    progress: Option<Progress>,
    notice: String,
    export_dir: Option<PathBuf>,
    export_category: Option<Category>,
    export_path: String,
    export_error: Option<String>,
    osv: bool,
}

pub fn launch(root: Option<PathBuf>, engine: Option<PathBuf>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("原碼檢查站｜網站原始碼掃描工具")
            .with_inner_size([1380.0, 880.0])
            .with_min_inner_size([1080.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "原碼檢查站",
        options,
        Box::new(move |cc| {
            let mut fonts = egui::FontDefinitions::default();
            for path in [
                r"C:\Windows\Fonts\msjh.ttc",
                r"C:\Windows\Fonts\mingliu.ttc",
                r"C:\Windows\Fonts\msyh.ttc",
            ] {
                if let Ok(bytes) = std::fs::read(path) {
                    fonts
                        .font_data
                        .insert("chinese".into(), egui::FontData::from_owned(bytes).into());
                    fonts
                        .families
                        .entry(egui::FontFamily::Proportional)
                        .or_default()
                        .insert(0, "chinese".into());
                    fonts
                        .families
                        .entry(egui::FontFamily::Monospace)
                        .or_default()
                        .push("chinese".into());
                    break;
                }
            }
            cc.egui_ctx.set_fonts(fonts);
            let mut style = (*cc.egui_ctx.style()).clone();
            style.visuals = egui::Visuals::light();
            style.visuals.panel_fill = Color32::from_rgb(246, 248, 247);
            style.visuals.window_fill = Color32::WHITE;
            style.visuals.override_text_color = Some(INK);
            style.visuals.selection.bg_fill = Color32::from_rgb(204, 232, 225);
            style.visuals.selection.stroke = egui::Stroke::new(1.0_f32, TEAL);
            style.spacing.item_spacing = egui::vec2(10.0, 10.0);
            style.spacing.button_padding = egui::vec2(12.0, 8.0);
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(16.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
            style
                .text_styles
                .insert(egui::TextStyle::Heading, egui::FontId::proportional(23.0));
            style
                .text_styles
                .insert(egui::TextStyle::Small, egui::FontId::proportional(13.0));
            cc.egui_ctx.set_style(style);
            Ok(Box::new(App {
                source: root
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                engine: engine
                    .or_else(detect_engine)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                excludes: String::new(),
                timeout: 180,
                scan_mode: None,
                dependency: String::new(),
                dependency_json: String::new(),
                report: None,
                category: None,
                severity: None,
                search: String::new(),
                selected: None,
                cancel: Arc::new(AtomicBool::new(false)),
                receiver: None,
                busy: false,
                exporting: false,
                progress: None,
                notice: String::new(),
                export_dir: None,
                export_category: None,
                export_path: default_export_dir().to_string_lossy().into_owned(),
                export_error: None,
                osv: true,
            }))
        }),
    )
}

fn default_export_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let docs = PathBuf::from(profile).join("Documents");
        if docs.is_dir() {
            return docs.join("網站掃描報告");
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        return parent.join("reports");
    }
    std::env::temp_dir().join("web-source-scanner-reports")
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(220, 230, 230)))
        .corner_radius(10)
        .inner_margin(16)
        .show(ui, add);
}
fn risk_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical | Severity::High => Color32::from_rgb(173, 67, 46),
        Severity::Medium => Color32::from_rgb(167, 110, 34),
        _ => TEAL,
    }
}

impl App {
    fn start(&mut self, ctx: &egui::Context) {
        if !PathBuf::from(self.source.trim()).is_dir() {
            self.notice = "請先選擇可讀取的網站原始碼資料夾。".into();
            return;
        }
        let mut opts = ScanOptions::new(self.source.trim());
        opts.mode = self.scan_mode;
        opts.engine = if self.engine.trim().is_empty() {
            None
        } else {
            Some(self.engine.trim().into())
        };
        opts.excludes = self
            .excludes
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        opts.timeout_secs = self.timeout;
        opts.dependency_check = if self.dependency.trim().is_empty() {
            None
        } else {
            Some(self.dependency.trim().into())
        };
        opts.dependency_report = if self.dependency_json.trim().is_empty() {
            None
        } else {
            Some(self.dependency_json.trim().into())
        };
        opts.osv = self.osv;
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.busy = true;
        self.report = None;
        self.selected = None;
        self.export_dir = None;
        self.export_error = None;
        self.notice = String::new();
        self.progress = None;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(|| {
                run_scan(opts, cancel, |p| {
                    let _ = tx.send(Message::Progress(p));
                })
            });
            let _ = tx.send(match result {
                Ok(r) => Message::Finished(Box::new(r)),
                Err(_) => Message::Failed("掃描發生內部錯誤；未將不完整結果判為通過。".into()),
            });
            ctx.request_repaint();
        });
    }
    fn poll(&mut self) {
        if let Some(rx) = &self.receiver {
            while let Ok(message) = rx.try_recv() {
                match message {
                    Message::Progress(p) => self.progress = Some(p),
                    Message::Finished(r) => {
                        self.busy = false;
                        self.selected = if r.findings.is_empty() { None } else { Some(0) };
                        self.notice = format!(
                            "掃描{}：{} 個檔案，{} 筆待檢查項目。",
                            state_name(r.state),
                            r.files.len(),
                            r.findings.len()
                        );
                        self.report = Some(*r);
                    }
                    Message::Exported(result) => {
                        self.exporting = false;
                        match result {
                            Ok((p, n)) => {
                                self.export_error = None;
                                self.notice = format!(
                                    "已匯出 {n} 個報告檔案到 {}（HTML 可直接離線開啟）。",
                                    p.display()
                                );
                                self.export_dir = Some(p);
                            }
                            Err(e) => {
                                self.notice = format!("匯出失敗：{e}");
                                self.export_error = Some(e);
                            }
                        }
                    }
                    Message::Failed(e) => {
                        self.busy = false;
                        self.notice = e;
                    }
                }
            }
        }
    }
    fn export(&mut self, ctx: &egui::Context) {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("選擇報告輸出位置（請選網站以外的資料夾）")
            .pick_folder()
        {
            self.export_path = dir.to_string_lossy().into_owned();
            self.export_to(ctx, dir);
        }
    }
    fn export_to(&mut self, ctx: &egui::Context, dir: PathBuf) {
        if self.busy {
            self.notice = "掃描仍在進行，請等掃描完成後再匯出。".into();
            return;
        }
        let Some(report) = self.report.clone() else {
            self.notice = "尚無掃描結果，請先完成一次掃描再匯出。".into();
            self.export_error = Some(self.notice.clone());
            return;
        };
        if dir.as_os_str().is_empty() {
            self.export_error = Some("請先指定報告輸出資料夾。".into());
            self.notice = self.export_error.clone().unwrap_or_default();
            return;
        }
        let target = dir.join(format!("scan-{}", report.scan_id));
        let category = self.export_category;
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.exporting = true;
        self.export_error = None;
        self.notice = format!("正在匯出到 {} …", target.display());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = export_report(&report, &target, category).map(|v| (target, v.len()));
            let _ = tx.send(Message::Exported(result));
            ctx.request_repaint();
        });
    }
    fn sidebar(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("掃描設定");
        ui.label(
            RichText::new("選擇網站資料夾，開始本機檢查。")
                .small()
                .color(MUTED),
        );
        ui.add_space(8.0);
        ui.add_enabled_ui(!self.busy && !self.exporting, |ui| {
            ui.label(RichText::new("原始碼資料夾").strong());
            ui.add(
                egui::TextEdit::multiline(&mut self.source)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .hint_text("選擇含 .sln／網站原始碼的資料夾"),
            );
            if ui.button("選擇資料夾…").clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("選擇網站原始碼資料夾")
                    .pick_folder()
            {
                self.source = p.to_string_lossy().into_owned();
            }
            ui.add_space(6.0);
            ui.label(RichText::new("掃描範圍").strong());
            egui::ComboBox::from_id_salt("scan_mode")
                .selected_text(self.scan_mode.map(category_name).unwrap_or("全部檢查"))
                .width(265.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.scan_mode, None, "全部檢查");
                    ui.selectable_value(&mut self.scan_mode, Some(Category::Security), "安全漏洞");
                    ui.selectable_value(
                        &mut self.scan_mode,
                        Some(Category::QualityPerformance),
                        "程式碼品質與效能",
                    );
                });
            ui.add_space(6.0);
            ui.label(RichText::new("掃描強度").strong());
            ui.checkbox(&mut self.osv, "最強掃描：線上查詢套件漏洞（OSV.dev）");
            ui.label(
                RichText::new(
                    "預設勾選；只送套件名稱與版本到 api.osv.dev，不送原始碼，可隨時取消。",
                )
                .small()
                .color(MUTED),
            );
            ui.add_space(8.0);
            egui::CollapsingHeader::new("進階設定").show(ui, |ui| {
                ui.label("額外排除：每行一個路徑片段");
                ui.add(
                    egui::TextEdit::multiline(&mut self.excludes)
                        .desired_rows(3)
                        .desired_width(270.0)
                        .hint_text("例如：archive/"),
                );
                ui.horizontal(|ui| {
                    ui.label("引擎時間上限（秒）");
                    ui.add(egui::DragValue::new(&mut self.timeout).range(1..=3600));
                });
                ui.label("Semgrep Core 執行檔");
                ui.add(egui::TextEdit::singleline(&mut self.engine).desired_width(270.0));
                if ui.small_button("指定引擎…").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("Semgrep Core", &["exe"])
                        .pick_file()
                {
                    self.engine = p.to_string_lossy().into_owned();
                }
                ui.separator();
                ui.label("選配：Dependency-Check（需先備妥工具與資料庫）");
                ui.label("Dependency-Check CLI 路徑");
                ui.add(egui::TextEdit::singleline(&mut self.dependency).desired_width(270.0));
                ui.label("或匯入既有 Dependency-Check JSON");
                ui.add(egui::TextEdit::singleline(&mut self.dependency_json).desired_width(270.0));
                if ui.small_button("選擇套件報告…").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("JSON", &["json"])
                        .pick_file()
                {
                    self.dependency_json = p.to_string_lossy().into_owned();
                }
            });
        });
        ui.add_space(14.0);
        if self.busy {
            if ui
                .add_sized([270.0, 42.0], egui::Button::new("取消掃描"))
                .clicked()
            {
                self.cancel.store(true, Ordering::Relaxed);
                self.notice = "正在停止引擎，將保留可辨識的部分結果。".into();
            }
        } else if ui
            .add_enabled(
                !self.exporting,
                egui::Button::new(RichText::new("開始掃描").color(Color32::WHITE))
                    .fill(TEAL)
                    .min_size(egui::vec2(270.0, 44.0)),
            )
            .clicked()
        {
            self.start(ctx);
        }
        ui.add_space(16.0);
        card(ui, |ui| {
            let ready = PathBuf::from(&self.engine).is_file();
            ui.colored_label(
                if ready {
                    TEAL
                } else {
                    risk_color(Severity::High)
                },
                if ready {
                    "本機引擎檔案已就緒"
                } else {
                    "尚未找到分析引擎"
                },
            );
            ui.label(RichText::new("Semgrep CE Core + Rust 專用規則").small());
            ui.label(
                RichText::new(
                    "掃描不執行網站，也不修改原始碼。引擎版本與實際涵蓋範圍於結果中列出。",
                )
                .small()
                .color(MUTED),
            );
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new(format!("{} 組專用規則 · 本機分析", rule_catalog().len()))
                .small()
                .color(MUTED),
        );
        ui.label(
            RichText::new("社群引擎不含付費版跨檔案深度分析。套件盤點不等於 CVE 掃描。")
                .small()
                .color(MUTED),
        );
    }
    fn details(&self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("問題詳情");
        let finding = self
            .report
            .as_ref()
            .and_then(|r| self.selected.and_then(|i| r.findings.get(i)));
        if let Some(f) = finding {
            ui.add_space(12.0);
            ui.colored_label(
                risk_color(f.severity),
                format!("{}風險 · 信心：{}", severity_name(f.severity), f.confidence),
            );
            ui.label(RichText::new(&f.title).size(21.0).strong());
            ui.label(RichText::new(format!("{}\n第 {} 行", f.file, f.start_line)).color(MUTED));
            ui.separator();
            ui.label(RichText::new("判定").strong());
            ui.label(&f.review_status);
            ui.label(&f.description);
            ui.add_space(8.0);
            ui.label(RichText::new("程式片段（敏感值已遮蔽）").strong());
            egui::Frame::new()
                .fill(Color32::from_rgb(235, 241, 242))
                .corner_radius(6)
                .inner_margin(12)
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&f.evidence).monospace().size(13.0)).wrap(),
                    );
                });
            ui.add_space(10.0);
            ui.label(RichText::new("修正建議").strong());
            ui.label(&f.recommendation);
            ui.add_space(10.0);
            ui.label(RichText::new("判讀限制").strong());
            ui.label(RichText::new(&f.limitations).small().color(MUTED));
            ui.separator();
            ui.label(
                RichText::new(format!("{}\n{}", f.rule_id, f.engine))
                    .small()
                    .color(MUTED),
            );
        } else {
            ui.add_space(20.0);
            ui.label(
                RichText::new("點選左側檢查結果，查看檔案位置、證據與修正建議。").color(MUTED),
            );
        }
    }
    fn results(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let Some(report) = &self.report else {
            ui.add_space(30.0);
            ui.heading(if self.busy {
                "正在檢查網站原始碼"
            } else {
                "讓網站問題有跡可循"
            });
            ui.label(
                RichText::new("一次掃描，兩份清楚的檢查結果。")
                    .size(18.0)
                    .color(MUTED),
            );
            ui.add_space(24.0);
            card(ui, |ui| {
                ui.label(RichText::new("01  安全漏洞").size(21.0).strong());
                ui.label("找出疑似 SQL／命令注入、危險輸出、硬編碼憑證與網站設定風險。");
                ui.add_space(12.0);
                ui.label(RichText::new("02  程式碼品質與效能").size(21.0).strong());
                ui.label("檢查例外處理、過長函式、重複查詢與可能的阻塞操作，提供改善方向。");
            });
            ui.add_space(14.0);
            ui.label(RichText::new("支援本次網站使用的 C#、ASP.NET MVC、Razor、JavaScript 與設定檔。掃描結果包含判定信心與未涵蓋範圍。").color(MUTED));
            if self.busy {
                ui.add_space(20.0);
                ui.spinner();
            }
            return;
        };
        let security = report
            .findings
            .iter()
            .filter(|f| f.category == Category::Security)
            .count();
        let quality = report.findings.len() - security;
        ui.horizontal(|ui| {
            ui.heading("掃描結果");
            ui.label(RichText::new(state_name(report.state)).color(
                if report.state == ScanState::Complete {
                    TEAL
                } else {
                    risk_color(Severity::Medium)
                },
            ));
        });
        ui.add_space(8.0);
        ui.columns(3, |cols| {
            card(&mut cols[0], |ui| {
                ui.label(RichText::new("安全漏洞").small().color(MUTED));
                ui.label(
                    RichText::new(security.to_string())
                        .size(28.0)
                        .color(TEAL)
                        .strong(),
                );
            });
            card(&mut cols[1], |ui| {
                ui.label(RichText::new("品質與效能").small().color(MUTED));
                ui.label(
                    RichText::new(quality.to_string())
                        .size(28.0)
                        .color(TEAL)
                        .strong(),
                );
            });
            card(&mut cols[2], |ui| {
                ui.label(RichText::new("掃描檔案").small().color(MUTED));
                ui.label(
                    RichText::new(report.files.len().to_string())
                        .size(28.0)
                        .color(TEAL)
                        .strong(),
                );
            });
        });
        egui::CollapsingHeader::new("查看覆蓋範圍與引擎狀態").show(ui, |ui| {
            for e in &report.engines {
                ui.label(format!(
                    "{} {} · {} · {}/{} 個檔案／套件",
                    e.name, e.version, e.status, e.scanned, e.eligible
                ));
                ui.label(RichText::new(&e.limitations).small().color(MUTED));
                if !e.metadata.is_null() {
                    ui.collapsing(format!("{} 資料來源／資料庫日期", e.name), |ui| {
                        ui.label(
                            RichText::new(
                                serde_json::to_string_pretty(&e.metadata).unwrap_or_default(),
                            )
                            .monospace()
                            .size(12.0),
                        );
                    });
                }
                for error in &e.errors {
                    ui.colored_label(risk_color(Severity::Medium), error);
                }
            }
            egui::ScrollArea::vertical()
                .id_salt("warnings")
                .max_height(130.0)
                .show(ui, |ui| {
                    for w in report.warnings.iter().chain(&report.errors) {
                        ui.label(RichText::new(w).small());
                    }
                    ui.label(format!(
                        "排除 {} 項；套件盤點 {} 筆。完整清單隨報告匯出。",
                        report.excluded.len(),
                        report.packages.len()
                    ));
                });
        });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.category, None, "全部");
            ui.selectable_value(&mut self.category, Some(Category::Security), "安全漏洞");
            ui.selectable_value(
                &mut self.category,
                Some(Category::QualityPerformance),
                "品質與效能",
            );
        });
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .desired_width((ui.available_width() - 115.0).max(100.0))
                    .hint_text("搜尋問題、檔案或規則"),
            );
            egui::ComboBox::from_id_salt("severity_filter")
                .selected_text(self.severity.map(severity_name).unwrap_or("全部風險"))
                .width(90.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.severity, None, "全部風險");
                    for s in [
                        Severity::Critical,
                        Severity::High,
                        Severity::Medium,
                        Severity::Low,
                        Severity::Info,
                    ] {
                        ui.selectable_value(&mut self.severity, Some(s), severity_name(s));
                    }
                });
        });
        let needle = self.search.to_lowercase();
        let indices = report
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                self.category.is_none_or(|c| f.category == c)
                    && self.severity.is_none_or(|s| f.severity == s)
                    && format!("{} {} {} {}", f.title, f.file, f.rule_id, f.description)
                        .to_lowercase()
                        .contains(&needle)
            })
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        ui.label(
            RichText::new(format!(
                "顯示 {} / {} 筆 · 點選項目查看詳情",
                indices.len(),
                report.findings.len()
            ))
            .small()
            .color(MUTED),
        );
        let available = (ui.available_height() - 180.0).max(80.0);
        egui::ScrollArea::vertical()
            .id_salt("findings")
            .max_height(available)
            .show_rows(ui, 73.0, indices.len(), |ui, range| {
                for row in range {
                    let i = indices[row];
                    let f = &report.findings[i];
                    let text = format!(
                        "{}  {}\n{}：{}  ·  {}",
                        severity_name(f.severity),
                        f.title,
                        f.file,
                        f.start_line,
                        f.subcategory
                    );
                    let response = ui.add_sized(
                        [ui.available_width(), 68.0],
                        egui::Button::new(RichText::new(text).size(14.0))
                            .wrap()
                            .fill(if self.selected == Some(i) {
                                Color32::from_rgb(219, 237, 232)
                            } else {
                                Color32::WHITE
                            })
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(220, 230, 230))),
                    );
                    if response.clicked() {
                        self.selected = Some(i);
                    }
                }
            });
        ui.separator();
        ui.label(RichText::new("報告輸出資料夾").strong());
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 110.0).max(160.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.export_path)
                    .desired_width(width)
                    .hint_text("例如 D:\\掃描報告（不可選受掃描網站內的資料夾）"),
            );
            if ui.button("選擇…").clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("選擇報告輸出位置（請選網站以外的資料夾）")
                    .pick_folder()
            {
                self.export_path = p.to_string_lossy().into_owned();
            }
        });
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("export_category")
                .selected_text(
                    self.export_category
                        .map(category_name)
                        .unwrap_or("兩類分別匯出"),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.export_category, None, "兩類分別匯出");
                    ui.selectable_value(
                        &mut self.export_category,
                        Some(Category::Security),
                        "僅安全漏洞",
                    );
                    ui.selectable_value(
                        &mut self.export_category,
                        Some(Category::QualityPerformance),
                        "僅品質與效能",
                    );
                });
            if ui
                .add_enabled(
                    !self.exporting && !self.busy,
                    egui::Button::new(if self.exporting {
                        "正在匯出…"
                    } else {
                        "匯出 HTML / CSV / JSON"
                    }),
                )
                .clicked()
            {
                let dir = PathBuf::from(self.export_path.trim());
                self.export_to(ctx, dir);
            }
            if ui
                .add_enabled(
                    !self.exporting && !self.busy,
                    egui::Button::new("選擇資料夾並匯出…"),
                )
                .clicked()
            {
                self.export(ctx);
            }
            if let Some(dir) = &self.export_dir
                && ui.small_button("開啟報告資料夾").clicked()
            {
                let _ = open_folder(dir);
            }
        });
        if let Some(err) = &self.export_error {
            ui.label(RichText::new(format!("匯出失敗：{err}")).color(risk_color(Severity::High)));
        } else {
            ui.label(
                RichText::new(
                    "會在指定資料夾建立 scan-時間 子資料夾；受掃描網站內的資料夾不可作為輸出。",
                )
                .small()
                .color(MUTED),
            );
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.busy || self.exporting {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(18))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(38.0, 38.0), egui::Sense::hover());
                    let painter = ui.painter();
                    painter.rect_filled(rect, 8, TEAL);
                    painter.circle_stroke(
                        rect.center() - egui::vec2(2.0, 2.0),
                        9.0,
                        egui::Stroke::new(2.0_f32, Color32::WHITE),
                    );
                    painter.line_segment(
                        [
                            rect.center() + egui::vec2(5.0, 5.0),
                            rect.center() + egui::vec2(12.0, 12.0),
                        ],
                        egui::Stroke::new(2.0_f32, Color32::WHITE),
                    );
                    ui.vertical(|ui| {
                        ui.label(RichText::new("原碼檢查站").size(24.0).strong());
                        ui.label(RichText::new("網站原始碼掃描工具").small().color(MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new("本機分析  ·  中文報告").color(TEAL));
                    });
                });
            });
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(233, 240, 238))
                    .inner_margin(12),
            )
            .show(ctx, |ui| {
                if let Some(p) = &self.progress
                    && self.busy
                {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(format!("{}：{}", p.stage, p.message));
                    });
                } else if !self.notice.is_empty() {
                    ui.label(&self.notice);
                } else {
                    ui.label(
                        RichText::new("準備就緒。掃描命中仍需人工確認；效能項目須配合實際量測。")
                            .color(MUTED),
                    );
                }
                if let Some(dir) = &self.export_dir
                    && ui.small_button("開啟報告資料夾").clicked()
                {
                    let _ = open_folder(dir);
                }
            });
        egui::SidePanel::left("settings")
            .exact_width(315.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(239, 245, 242))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.sidebar(ctx, ui));
            });
        egui::SidePanel::right("details")
            .default_width(370.0)
            .width_range(280.0..=550.0)
            .resizable(true)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(20))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("detail_scroll")
                    .show(ui, |ui| self.details(ui));
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(246, 248, 247))
                    .inner_margin(20),
            )
            .show(ctx, |ui| self.results(ctx, ui));
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

fn open_folder(path: &std::path::Path) -> std::io::Result<std::process::Child> {
    std::process::Command::new("explorer.exe").arg(path).spawn()
}
