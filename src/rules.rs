use crate::model::*;
use quick_xml::{Reader, events::Event};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tree_sitter::{Node, Parser};

#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub confidence: &'static str,
    pub recommendation: &'static str,
    pub cwe: &'static str,
}

pub fn rule_catalog() -> &'static [RuleInfo] {
    static RULES: OnceLock<Vec<RuleInfo>> = OnceLock::new();
    RULES.get_or_init(|| {
        use Category::*; use Severity::*;
        vec![
            RuleInfo{id:"LOCAL-SECRET",title:"原始碼／設定內含疑似硬編碼憑證",category:Security,severity:High,confidence:"中",recommendation:"將憑證移至受保護的設定或秘密管理服務；若曾外洩，請撤銷並換發。",cwe:"CWE-798"},
            RuleInfo{id:"CONFIG-DEBUG",title:"網站設定開啟 debug",category:Security,severity:Medium,confidence:"高",recommendation:"正式環境請關閉 compilation debug，並核對部署轉換設定。",cwe:"CWE-489"},
            RuleInfo{id:"CONFIG-ERRORS",title:"網站設定對外顯示詳細錯誤",category:Security,severity:Medium,confidence:"高",recommendation:"設定 customErrors On 或 RemoteOnly，將詳細錯誤留在受控日誌。",cwe:"CWE-209"},
            RuleInfo{id:"CONFIG-COOKIE",title:"Cookie 安全屬性明確停用",category:Security,severity:Medium,confidence:"高",recommendation:"正式 HTTPS 網站請啟用 HttpOnly 與 Secure，並核對實際 Cookie 設定。",cwe:"CWE-614"},
            RuleInfo{id:"CONFIG-VALIDATION",title:"設定停用 Request Validation",category:Security,severity:Medium,confidence:"低",recommendation:"核對是否有完整的輸入驗證、輸出編碼與全域保護。",cwe:"CWE-79"},
            RuleInfo{id:"RAZOR-RAW",title:"Razor 原始 HTML 輸出",category:Security,severity:Medium,confidence:"低",recommendation:"純文字請使用 Razor 預設編碼；必要 HTML 請以可信清理器過濾並核對來源。",cwe:"CWE-79"},
            RuleInfo{id:"QUALITY-EMPTY-CATCH",title:"例外處理區塊沒有實際處理",category:QualityPerformance,severity:Medium,confidence:"高",recommendation:"記錄適當資訊、回復狀態或重新拋出；若刻意忽略，請說明可安全忽略的條件。",cwe:""},
            RuleInfo{id:"QUALITY-THROW",title:"以 throw 變數重新拋出例外",category:QualityPerformance,severity:Medium,confidence:"中",recommendation:"若要保留原始例外堆疊，請使用 throw;，或保留原始例外作為 InnerException。",cwe:""},
            RuleInfo{id:"QUALITY-LONG-METHOD",title:"函式超過 80 行",category:QualityPerformance,severity:Low,confidence:"中",recommendation:"依單一職責拆分函式，保留可測試的明確輸入與輸出。",cwe:""},
            RuleInfo{id:"QUALITY-NESTING",title:"控制流程巢狀超過 4 層",category:QualityPerformance,severity:Low,confidence:"中",recommendation:"考慮提早回傳、拆分條件與抽出子函式，降低閱讀負擔。",cwe:""},
            RuleInfo{id:"QUALITY-RESOURCE",title:"資源建立處未見 using 保護",category:QualityPerformance,severity:Low,confidence:"低",recommendation:"核對所有權及 Dispose 路徑；局部資源可使用 using 或 try/finally。",cwe:""},
            RuleInfo{id:"PERF-LOOP-QUERY",title:"迴圈內呼叫資料查詢／集合具現化",category:QualityPerformance,severity:Medium,confidence:"中",recommendation:"評估批次查詢、預先載入或快取；以執行紀錄與量測確認是否造成重複 I/O。",cwe:""},
            RuleInfo{id:"PERF-SYNC-WAIT",title:"可能同步阻塞等待非同步工作",category:QualityPerformance,severity:Medium,confidence:"低",recommendation:"核對型別是否為 Task，必要時改用 async/await；需量測執行環境與呼叫鏈。",cwe:""},
            RuleInfo{id:"PERF-SLEEP",title:"程式執行緒使用 Sleep 等待",category:QualityPerformance,severity:Low,confidence:"中",recommendation:"核對是否在網站請求路徑；若可行使用非同步等待或排程機制。",cwe:""},
            RuleInfo{id:"ENGINE-SQL-TAINT",title:"輸入經函式內資料流進入 SQL 查詢",category:Security,severity:High,confidence:"中",recommendation:"改用參數化查詢，將 SQL 結構與資料值分離，核對自訂查詢封裝。",cwe:"CWE-89"},
            RuleInfo{id:"ENGINE-COMMAND-TAINT",title:"輸入經函式內資料流進入系統命令",category:Security,severity:High,confidence:"中",recommendation:"使用固定命令、允許清單與結構化參數；避免接受使用者提供的執行檔／命令。",cwe:"CWE-78"},
            RuleInfo{id:"ENGINE-PATH-TAINT",title:"輸入經函式內資料流進入檔案操作",category:Security,severity:High,confidence:"中",recommendation:"限制可存取根目錄，正規化路徑後核對邊界，避免信任上傳檔名。",cwe:"CWE-22"},
            RuleInfo{id:"ENGINE-TLS-BYPASS",title:"TLS 憑證驗證無條件接受",category:Security,severity:High,confidence:"高",recommendation:"移除無條件 true 回呼，使用正常的主機名稱與憑證信任驗證。",cwe:"CWE-295"},
            RuleInfo{id:"ENGINE-WEAK-CRYPTO",title:"使用弱雜湊／加密 API",category:Security,severity:Medium,confidence:"中",recommendation:"核對用途；安全雜湊使用 SHA-256 以上，密碼使用適當的加鹽密碼雜湊演算法。",cwe:"CWE-327"},
            RuleInfo{id:"ENGINE-DESERIALIZE",title:"BinaryFormatter 反序列化風險",category:Security,severity:High,confidence:"中",recommendation:"改用明確型別的安全序列化格式，不反序列化不可信 BinaryFormatter 資料。",cwe:"CWE-502"},
            RuleInfo{id:"ENGINE-MVC-VALIDATION",title:"MVC 動作停用輸入驗證",category:Security,severity:Medium,confidence:"低",recommendation:"核對全域保護、輸入驗證與輸出編碼；屬性存在不直接證明可利用漏洞。",cwe:"CWE-79"},
            RuleInfo{id:"ENGINE-RAW-HTML",title:"C# 原始 HTML 輸出",category:Security,severity:Medium,confidence:"低",recommendation:"核對資料來源及清理方式，純文字使用安全編碼輸出。",cwe:"CWE-79"},
            RuleInfo{id:"ENGINE-JS-EVAL",title:"JavaScript 動態執行程式碼",category:Security,severity:Medium,confidence:"低",recommendation:"避免 eval／Function 處理不可信字串，改用結構化資料解析。",cwe:"CWE-95"},
            RuleInfo{id:"ENGINE-JS-HTML",title:"JavaScript 直接寫入 HTML",category:Security,severity:Medium,confidence:"低",recommendation:"純文字使用 textContent；HTML 需核對可信來源與清理器。",cwe:"CWE-79"},
            RuleInfo{id:"FLOW-SQL",title:"使用者輸入經跨檔案資料流進入 SQL 查詢",category:Security,severity:High,confidence:"低",recommendation:"改用參數化查詢，並核對中介服務是否重新組合 SQL；確認呼叫鏈後再修補。",cwe:"CWE-89"},
            RuleInfo{id:"FLOW-COMMAND",title:"使用者輸入經跨檔案資料流進入系統命令",category:Security,severity:High,confidence:"低",recommendation:"使用固定命令與允許清單，避免任何一層把使用者輸入拼進命令列。",cwe:"CWE-78"},
            RuleInfo{id:"FLOW-PATH",title:"使用者輸入經跨檔案資料流進入檔案操作",category:Security,severity:High,confidence:"低",recommendation:"在最終檔案操作前限制根目錄並正規化路徑，核對所有中介轉換。",cwe:"CWE-22"},
            RuleInfo{id:"FLOW-OUTPUT",title:"使用者輸入經跨檔案資料流進入 HTML 輸出",category:Security,severity:Medium,confidence:"低",recommendation:"在輸出層統一編碼；核對中介是否已清理，勿只依賴呼叫端。",cwe:"CWE-79"},
        ]
    })
}

pub fn make_finding(id: &str, file: &SourceFile, line: usize, end: usize) -> Finding {
    let info = rule_catalog()
        .iter()
        .find(|r| r.id == id)
        .expect("registered rule");
    let evidence = file
        .text
        .lines()
        .skip(line.saturating_sub(1))
        .take(end.saturating_sub(line).min(3) + 1)
        .collect::<Vec<_>>()
        .join("\n");
    let digest = Sha256::digest(format!("{}:{id}:{line}", file.relative));
    Finding {
        id: format!("{:x}", digest)[..16].to_string(),
        rule_id: id.into(),
        category: info.category,
        subcategory: if id.starts_with("PERF-") {
            "效能改善線索"
        } else if info.category == Category::Security {
            "安全風險"
        } else {
            "程式碼品質"
        }
        .into(),
        title: info.title.into(),
        severity: info.severity,
        confidence: info.confidence.into(),
        review_status: if id.ends_with("TAINT") {
            "已建立局部資料流，仍需人工確認"
        } else if id.starts_with("CONFIG-") && id != "CONFIG-VALIDATION"
            || id == "ENGINE-TLS-BYPASS"
        {
            "明確危險設定，需核對部署環境"
        } else {
            "待人工確認"
        }
        .into(),
        engine: if id.starts_with("ENGINE-") {
            "Semgrep CE Core"
        } else {
            "Rust 本機專用規則"
        }
        .into(),
        file: file.relative.clone(),
        start_line: line,
        end_line: end,
        evidence: redact(&evidence),
        description: info.title.into(),
        recommendation: info.recommendation.into(),
        limitations: if info.category == Category::QualityPerformance {
            "靜態檢查線索，未量測執行速度；缺乏型別／呼叫鏈的項目可能誤報。"
        } else {
            "不保證可利用；未執行跨檔案深度分析、全域防護或業務權限驗證。"
        }
        .into(),
        references: if info.cwe.is_empty() {
            vec![]
        } else {
            vec![format!(
                "https://cwe.mitre.org/data/definitions/{}.html",
                info.cwe.trim_start_matches("CWE-")
            )]
        },
        cwe: if info.cwe.is_empty() {
            vec![]
        } else {
            vec![info.cwe.into()]
        },
    }
}

fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| [
        r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r#"(?is)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)\s*[\"']?\s*[:=]\s*)@?"(?:\\.|[^"\\])*""#,
        r#"(?is)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)\s*[\"']?\s*[:=]\s*)'(?:\\.|[^'\\])*'"#,
        r#"(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)\s*[\"']?\s*[:=]\s*)[^\"'\r\n;<>,}]+"#,
        r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+=*",
    ].iter().map(|p|Regex::new(p).expect("valid redaction regex")).collect())
}

pub fn redact(s: &str) -> String {
    let mut s = patterns()[0]
        .replace_all(s, "[私密金鑰已遮蔽]")
        .into_owned();
    static ADD: OnceLock<Regex> = OnceLock::new();
    static KEY: OnceLock<Regex> = OnceLock::new();
    static VALUE: OnceLock<Regex> = OnceLock::new();
    static CONNECTION: OnceLock<Regex> = OnceLock::new();
    let connection = CONNECTION
        .get_or_init(|| Regex::new(r#"(?is)(\bconnectionString\s*=\s*)["'][^"']*["']"#).unwrap());
    // Mask the whole XML attribute: entity delimiters contain semicolons and
    // must never be treated as connection-string field separators.
    s = connection
        .replace_all(&s, "${1}\"[連線字串已遮蔽]\"")
        .into_owned();
    let add = ADD.get_or_init(|| Regex::new(r"(?is)<add\b[^>]*>").unwrap());
    let key =
        KEY.get_or_init(|| Regex::new(r#"(?i)\b(?:key|name)\s*=\s*["']([^"']+)["']"#).unwrap());
    let value = VALUE.get_or_init(|| Regex::new(r#"(?is)(\bvalue\s*=\s*)["'][^"']*["']"#).unwrap());
    s = add
        .replace_all(&s, |c: &regex::Captures<'_>| {
            if key.captures(&c[0]).is_some_and(|k| {
                sensitive_key(
                    &quick_xml::escape::unescape(&k[1])
                        .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&k[1])),
                )
            }) {
                value.replace_all(&c[0], "${1}\"[已遮蔽]\"").into_owned()
            } else {
                c[0].to_string()
            }
        })
        .into_owned();
    for (n, re) in patterns()[1..].iter().enumerate() {
        s = re
            .replace_all(
                &s,
                if n < 2 {
                    "${1}\"[已遮蔽]\""
                } else {
                    "${1}[已遮蔽]"
                },
            )
            .into_owned();
    }
    s
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_lowercase().replace(['_', '-'], "");
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "apikey",
        "accesstoken",
        "clientsecret",
    ]
    .iter()
    .any(|p| key.contains(p))
}

fn parse(text: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    parser.parse(text, None)
}

pub fn csharp_parse_has_errors(text: &str) -> bool {
    parse(text).is_none_or(|t| t.root_node().has_error())
}

pub fn xml_diagnostics(text: &str) -> Vec<String> {
    let mut reader = Reader::from_str(text);
    let mut diagnostics = vec![];
    let mut depth = 0usize;
    let mut roots = 0usize;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let is_empty = text
                    .as_bytes()
                    .get(reader.buffer_position().saturating_sub(2) as usize)
                    == Some(&b'/');
                if depth == 0 {
                    roots += 1;
                }
                if !is_empty {
                    depth += 1;
                }
                for attr in e.attributes() {
                    match attr {
                        Ok(a) => {
                            if a.decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
                            .is_err()
                            {
                                diagnostics.push("XML 屬性有無法解析的 entity".into());
                            }
                        }
                        Err(_) => diagnostics.push("XML 屬性格式錯誤或重複".into()),
                    }
                }
            }
            Ok(Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(Event::DocType(_)) => diagnostics.push("XML DTD／外部實體不在分析範圍".into()),
            Ok(Event::Eof) => {
                if depth != 0 {
                    diagnostics.push("XML 標籤未完整結束".into());
                }
                if roots != 1 {
                    diagnostics.push("XML 必須有單一根節點".into());
                }
                break;
            }
            Err(_) => {
                diagnostics.push("XML 語法／結束標籤解析錯誤".into());
                break;
            }
            _ => {}
        }
    }
    diagnostics
}

fn ancestors_match(mut node: Node<'_>, predicate: impl Fn(Node<'_>) -> bool) -> bool {
    while let Some(parent) = node.parent() {
        if predicate(parent) {
            return true;
        }
        node = parent;
    }
    false
}
fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}
fn walk(node: Node<'_>, visit: &mut impl FnMut(Node<'_>)) {
    visit(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, visit);
    }
}
fn nesting(node: Node<'_>, depth: usize) -> usize {
    let depth = depth
        + usize::from(matches!(
            node.kind(),
            "if_statement"
                | "for_statement"
                | "foreach_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "try_statement"
        ));
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .map(|c| nesting(c, depth))
        .max()
        .unwrap_or(depth)
}

pub fn analyze_source(file: &SourceFile) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |id: &str, line: usize, end: usize| out.push(make_finding(id, file, line, end));
    let mut comments = vec![];
    let tree = if file.extension == "cs" {
        parse(&file.text)
    } else {
        None
    };
    if let Some(tree) = &tree {
        walk(tree.root_node(), &mut |n| {
            if n.kind() == "comment" {
                comments.push(n.byte_range());
            }
        });
    }
    static SECRET: OnceLock<Regex> = OnceLock::new();
    let secret=SECRET.get_or_init(||Regex::new(r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{4,})[\"']"#).unwrap());
    for cap in secret.captures_iter(&file.text) {
        let m = cap.get(0).unwrap();
        let value = &cap[1];
        let prefix = file.text[..m.start()]
            .rsplit_once('\n')
            .map_or(&file.text[..m.start()], |(_, s)| s);
        if comments.iter().any(|r| r.contains(&m.start()))
            || prefix.trim_start().starts_with("//")
            || value.contains("${")
            || value.starts_with("[已遮蔽")
            || [
                "password",
                "changeme",
                "example",
                "placeholder",
                "your_password",
            ]
            .contains(&value.to_lowercase().as_str())
        {
            continue;
        }
        let line = file.text[..m.start()]
            .bytes()
            .filter(|&b| b == b'\n')
            .count()
            + 1;
        push("LOCAL-SECRET", line, line);
    }
    if file.text.contains("-----BEGIN PRIVATE KEY-----")
        || file.text.contains("-----BEGIN RSA PRIVATE KEY-----")
    {
        let line = file
            .text
            .lines()
            .position(|l| l.contains("PRIVATE KEY-----"))
            .unwrap_or(0)
            + 1;
        push("LOCAL-SECRET", line, line);
    }
    if file.extension == "config" {
        let mut reader = Reader::from_str(&file.text);
        loop {
            let start = reader.buffer_position() as usize;
            match reader.read_event() {
                Ok(Event::Start(e) | Event::Empty(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_lowercase();
                    let attrs = e
                        .attributes()
                        .flatten()
                        .map(|a| {
                            (
                                String::from_utf8_lossy(a.key.as_ref()).to_lowercase(),
                                a.decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map(|v| v.to_lowercase())
                                .unwrap_or_default(),
                            )
                        })
                        .collect::<std::collections::HashMap<_, _>>();
                    let eq = |key: &str, value: &str| attrs.get(key).is_some_and(|s| s == value);
                    let id = if name == "compilation" && eq("debug", "true") {
                        Some("CONFIG-DEBUG")
                    } else if name == "customerrors" && eq("mode", "off") {
                        Some("CONFIG-ERRORS")
                    } else if name == "httpcookies"
                        && (eq("httponlycookies", "false") || eq("requiressl", "false"))
                    {
                        Some("CONFIG-COOKIE")
                    } else if name == "pages" && eq("validaterequest", "false") {
                        Some("CONFIG-VALIDATION")
                    } else {
                        None
                    };
                    if let Some(id) = id {
                        let line = file.text[..start.min(file.text.len())]
                            .bytes()
                            .filter(|&b| b == b'\n')
                            .count()
                            + 1;
                        push(id, line, line);
                    }
                    let app_secret = attrs
                        .get("key")
                        .or_else(|| attrs.get("name"))
                        .is_some_and(|k| sensitive_key(k))
                        && attrs.get("value").is_some_and(|v| {
                            v.len() >= 4 && !v.contains("${") && !v.starts_with("[已遮蔽")
                        });
                    let conn_secret = attrs.get("connectionstring").is_some_and(|v| {
                        v.split(';').any(|part| {
                            part.split_once('=').is_some_and(|(k, v)| {
                                ["password", "pwd"].contains(&k.trim())
                                    && !v.trim().is_empty()
                                    && !v.contains("${")
                            })
                        })
                    });
                    if name == "add" && (app_secret || conn_secret) {
                        let line = file.text[..start.min(file.text.len())]
                            .bytes()
                            .filter(|&b| b == b'\n')
                            .count()
                            + 1;
                        push("LOCAL-SECRET", line, line);
                    }
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
        }
    }
    if file.extension == "cshtml" {
        static RAZOR_COMMENT: OnceLock<Regex> = OnceLock::new();
        let re = RAZOR_COMMENT.get_or_init(|| Regex::new(r"(?s)@\*.*?\*@|<!--.*?-->").unwrap());
        let masked = re.replace_all(&file.text, |c: &regex::Captures<'_>| {
            c[0].chars()
                .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                .collect::<String>()
        });
        for (i, line) in masked.lines().enumerate() {
            if line.contains("Html.Raw(") {
                push("RAZOR-RAW", i + 1, i + 1);
            }
        }
    }
    if let Some(tree) = tree {
        walk(tree.root_node(), &mut |n| {
            let kind = n.kind();
            let line = n.start_position().row + 1;
            let end = n.end_position().row + 1;
            if kind == "catch_clause"
                && let Some(body) = n.child_by_field_name("body")
            {
                let mut cursor = body.walk();
                if body
                    .named_children(&mut cursor)
                    .all(|c| c.kind() == "comment")
                {
                    push("QUALITY-EMPTY-CATCH", line, end);
                }
            }
            if kind == "throw_statement"
                && n.named_child(0).is_some_and(|c| c.kind() == "identifier")
                && ancestors_match(n, |p| p.kind() == "catch_clause")
            {
                push("QUALITY-THROW", line, end);
            }
            if matches!(
                kind,
                "method_declaration" | "constructor_declaration" | "local_function_statement"
            ) {
                if end.saturating_sub(line) + 1 > 80 {
                    push("QUALITY-LONG-METHOD", line, end);
                }
                if nesting(n, 0) > 4 {
                    push("QUALITY-NESTING", line, end);
                }
            }
            if kind == "invocation_expression" {
                let name = n
                    .child_by_field_name("function")
                    .map(|c| text(c, &file.text))
                    .unwrap_or("");
                if [
                    "GetDBData",
                    "ExecuteReader",
                    "ExecuteNonQuery",
                    "GetChildren",
                    "GetDescendants",
                    "ToList",
                    "ToArray",
                ]
                .iter()
                .any(|s| name.ends_with(s))
                    && ancestors_match(n, |p| {
                        matches!(
                            p.kind(),
                            "for_statement"
                                | "foreach_statement"
                                | "while_statement"
                                | "do_statement"
                        )
                    })
                {
                    push("PERF-LOOP-QUERY", line, end);
                }
                if name == "Thread.Sleep" || name == "System.Threading.Thread.Sleep" {
                    push("PERF-SLEEP", line, end);
                }
                if name.ends_with(".Wait") || name.ends_with("GetAwaiter().GetResult") {
                    push("PERF-SYNC-WAIT", line, end);
                }
            }
            if kind == "member_access_expression"
                && n.child_by_field_name("name")
                    .is_some_and(|c| text(c, &file.text) == "Result")
            {
                push("PERF-SYNC-WAIT", line, end);
            }
            if kind == "object_creation_expression" {
                let typ = n
                    .child_by_field_name("type")
                    .map(|c| text(c, &file.text))
                    .unwrap_or("");
                if [
                    "FileStream",
                    "StreamReader",
                    "StreamWriter",
                    "SqlConnection",
                    "SqlCommand",
                ]
                .contains(&typ)
                    && !ancestors_match(n, |p| {
                        p.kind() == "using_statement"
                            || p.kind() == "local_declaration_statement"
                                && text(p, &file.text).trim_start().starts_with("using ")
                    })
                {
                    push("QUALITY-RESOURCE", line, end);
                }
            }
        });
    }
    out
}
