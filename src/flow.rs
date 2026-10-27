//! Heuristic cross-file taint tracking for C#.
//!
//! The local rules and Semgrep CE only see a single function or file. This
//! module adds a deliberately conservative pass: it builds a method summary
//! (which parameters reach a dangerous sink, what a method returns) and then
//! follows arguments across method and file boundaries for a few hops.
//!
//! It is not a type-aware dataflow engine. Calls are resolved by name (and
//! optionally by receiver name), so overloads, interfaces, delegates and
//! dynamic dispatch can produce false positives or misses. Every finding is
//! therefore reported with low confidence and an explicit call-chain note.

use crate::model::*;
use crate::rules::{redact, rule_catalog};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;
use tree_sitter::{Node, Parser};

const MAX_HOPS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SinkKind {
    Sql,
    Command,
    Path,
    Output,
}

impl SinkKind {
    fn rule_id(self) -> &'static str {
        match self {
            SinkKind::Sql => "FLOW-SQL",
            SinkKind::Command => "FLOW-COMMAND",
            SinkKind::Path => "FLOW-PATH",
            SinkKind::Output => "FLOW-OUTPUT",
        }
    }
    fn label(self) -> &'static str {
        match self {
            SinkKind::Sql => "SQL 查詢",
            SinkKind::Command => "系統命令",
            SinkKind::Path => "檔案操作",
            SinkKind::Output => "HTML 輸出",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    /// Request input, or an MVC action parameter bound from the request.
    Source,
    /// The method's own parameter at this position.
    Param(usize),
}

#[derive(Debug)]
struct ParamDef {
    name: String,
    type_text: String,
}

#[derive(Debug)]
struct MethodDef {
    file: usize,
    class: Option<String>,
    name: String,
    params: Vec<ParamDef>,
    is_public: bool,
    is_controller: bool,
    lines: Vec<LineFacts>,
}

#[derive(Debug, Default, Clone)]
struct LineFacts {
    line: usize,
    assign: Option<String>,
    append: bool,
    rhs_idents: Vec<String>,
    has_source: bool,
    sink: Option<SinkKind>,
    is_return: bool,
    calls: Vec<CallLocal>,
}

#[derive(Debug, Clone)]
struct CallLocal {
    callee: String,
    qualifier: Option<String>,
    args: Vec<Vec<String>>,
}

#[derive(Debug, Default, Clone)]
struct Facts {
    sink_sites: BTreeMap<SinkKind, BTreeSet<(usize, usize)>>,
    calls: Vec<(CallLocal, usize, Vec<BTreeSet<Origin>>)>,
    returns: BTreeSet<Origin>,
    param_to_sink: BTreeMap<usize, BTreeSet<SinkKind>>,
}

pub struct FlowOutcome {
    pub findings: Vec<Finding>,
    pub files: usize,
    pub methods: usize,
    pub warnings: Vec<String>,
}

fn re_assign() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\s*(?:[A-Za-z_][\w<>,\[\]\?\.]*\s+)?([A-Za-z_]\w*)\s*(\+=|=)").unwrap()
    })
}
fn re_return() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^\s*return\b").unwrap())
}
fn re_call() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:([A-Za-z_]\w*)\s*\.\s*)?([A-Za-z_]\w*)\s*\(").unwrap())
}
fn re_ident() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap())
}
fn re_source() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\bRequest\s*\.\s*(?:QueryString|Form|Params|Cookies|Headers|Unvalidated|Query|InputStream|Files|ServerVariables)\b|\bRequest\s*\[|\bHttpContext\.Current\.Request\b",
        )
        .unwrap()
    })
}
fn re_sink() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)new\s+(?:[\w]+\.)*(?:SqlCommand|OleDbCommand|MySqlCommand|SQLiteCommand|NpgsqlCommand|OracleCommand)\s*\(|\.CommandText\s*[+:]?=|\bProcess\.Start\s*\(|new\s+ProcessStartInfo\s*\(|\bFile\.(?:ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|AppendAllText|Open|Delete)\s*\(|\bDirectory\.(?:Delete|CreateDirectory|GetFiles)\s*\(|\bResponse\.Write\s*\(",
        )
        .unwrap()
    })
}
fn sink_kind(line: &str) -> Option<SinkKind> {
    if !re_sink().is_match(line) {
        return None;
    }
    let lower = line.to_lowercase();
    if lower.contains("process.start") || lower.contains("processstartinfo") {
        Some(SinkKind::Command)
    } else if lower.contains("response.write") {
        Some(SinkKind::Output)
    } else if lower.contains("commandtext")
        || lower.contains("sqlcommand")
        || lower.contains("oledbcommand")
        || lower.contains("mysqlcommand")
        || lower.contains("sqlitecommand")
        || lower.contains("npgsqlcommand")
        || lower.contains("oraclecommand")
    {
        Some(SinkKind::Sql)
    } else {
        Some(SinkKind::Path)
    }
}

const KEYWORDS: &[&str] = &[
    "if",
    "for",
    "foreach",
    "while",
    "switch",
    "using",
    "lock",
    "catch",
    "return",
    "new",
    "typeof",
    "nameof",
    "sizeof",
    "checked",
    "unchecked",
    "base",
    "this",
    "await",
    "throw",
    "as",
    "is",
    "in",
    "out",
    "ref",
    "var",
    "true",
    "false",
    "null",
];

fn idents(text: &str) -> Vec<String> {
    re_ident()
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|s| !KEYWORDS.contains(&s.as_str()))
        .collect()
}

/// Remove string/char literal contents so identifiers inside SQL or messages
/// are not mistaken for variables.
fn strip_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote = None::<char>;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                    out.push(' ');
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    out.push(' ');
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

fn split_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quote = None::<char>;
    let mut current = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            current.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    current.push(n);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                current.push(c);
            }
            '(' | '[' | '{' | '<' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn calls_in(line: &str) -> Vec<CallLocal> {
    let mut out = vec![];
    for caps in re_call().captures_iter(line) {
        let qualifier = caps.get(1).map(|m| m.as_str().to_string());
        let callee = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if callee.is_empty() || KEYWORDS.contains(&callee.as_str()) {
            continue;
        }
        let start = caps.get(0).map(|m| m.end()).unwrap_or(0);
        let rest = line.get(start..).unwrap_or("");
        let Some(end) = matching_paren(rest) else {
            continue;
        };
        let args = split_args(&rest[..end])
            .iter()
            .map(|a| idents(a))
            .collect::<Vec<_>>();
        out.push(CallLocal {
            callee,
            qualifier,
            args,
        });
    }
    out
}

/// `text` starts right after the opening parenthesis.
fn matching_paren(text: &str) -> Option<usize> {
    let mut depth = 1i32;
    let mut quote = None::<char>;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                chars.next();
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse(text: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    parser.parse(text, None)
}

fn line_of(text: &str, byte: usize) -> usize {
    text.as_bytes()[..byte.min(text.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

fn collect_methods(files: &[SourceFile]) -> (Vec<MethodDef>, Vec<String>, usize) {
    let mut methods = vec![];
    let mut warnings = vec![];
    let mut scanned = 0usize;
    for (file_index, file) in files.iter().enumerate() {
        if file.extension != "cs" {
            continue;
        }
        let Some(tree) = parse(&file.text) else {
            warnings.push(format!(
                "{}：無法建立語法樹，跨檔案資料流略過此檔",
                file.relative
            ));
            continue;
        };
        scanned += 1;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
            if node.kind() != "method_declaration" && node.kind() != "constructor_declaration" {
                continue;
            }
            let Some(name_node) = node.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, &file.text).to_string();
            let mut params = vec![];
            if let Some(list) = node.child_by_field_name("parameters") {
                let mut c = list.walk();
                for param in list.named_children(&mut c) {
                    if param.kind().starts_with("parameter")
                        && let Some(p) = param.child_by_field_name("name")
                    {
                        params.push(ParamDef {
                            name: node_text(p, &file.text).to_string(),
                            type_text: param
                                .child_by_field_name("type")
                                .map(|t| node_text(t, &file.text).to_string())
                                .unwrap_or_default(),
                        });
                    }
                }
            }
            let Some(body) = node.child_by_field_name("body") else {
                continue;
            };
            let class = ancestor_class(node, &file.text);
            let prefix = file
                .text
                .get(node.start_byte()..name_node.start_byte())
                .unwrap_or("");
            let is_public = prefix.contains("public");
            let is_controller = class
                .as_deref()
                .is_some_and(|c| c.ends_with("Controller") || c.ends_with("ApiController"));
            let body_text = node_text(body, &file.text);
            let body_line = line_of(&file.text, body.start_byte());
            methods.push(MethodDef {
                file: file_index,
                class,
                name,
                params,
                is_public,
                is_controller,
                lines: line_facts(body_text, body_line),
            });
        }
    }
    (methods, warnings, scanned)
}

fn ancestor_class(mut node: Node<'_>, text: &str) -> Option<String> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            return Some(node_text(name, text).to_string());
        }
        node = parent;
    }
    None
}

fn line_facts(body: &str, body_line: usize) -> Vec<LineFacts> {
    let mut facts = vec![];
    for (offset, raw) in body.lines().enumerate() {
        let stripped = strip_literals(raw);
        let mut entry = LineFacts {
            line: body_line + offset,
            ..Default::default()
        };
        if let Some(caps) = re_assign().captures(&stripped) {
            let operator = caps.get(2).expect("operator");
            let comparison =
                operator.as_str() == "=" && stripped.as_bytes().get(operator.end()) == Some(&b'=');
            if comparison {
                entry.rhs_idents = idents(&stripped);
            } else {
                entry.assign = caps.get(1).map(|m| m.as_str().to_string());
                entry.append = operator.as_str() == "+=";
                entry.rhs_idents = idents(stripped.get(operator.end()..).unwrap_or(""));
            }
        } else {
            entry.rhs_idents = idents(&stripped);
        }
        entry.has_source = re_source().is_match(&stripped);
        entry.sink = sink_kind(&stripped);
        entry.is_return = re_return().is_match(raw);
        entry.calls = calls_in(&stripped);
        facts.push(entry);
    }
    facts
}

struct Resolver {
    by_name: HashMap<String, Vec<usize>>,
}

impl Resolver {
    fn build(methods: &[MethodDef]) -> Self {
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, m) in methods.iter().enumerate() {
            by_name.entry(m.name.to_lowercase()).or_default().push(i);
            if let Some(class) = &m.class {
                by_name
                    .entry(format!(
                        "{}.{}",
                        class.to_lowercase(),
                        m.name.to_lowercase()
                    ))
                    .or_default()
                    .push(i);
            }
        }
        Self { by_name }
    }
    fn resolve(&self, call: &CallLocal) -> Vec<usize> {
        let name = call.callee.to_lowercase();
        let mut found = vec![];
        if let Some(q) = &call.qualifier
            && let Some(list) = self.by_name.get(&format!("{}.{}", q.to_lowercase(), name))
        {
            found.extend(list.iter().copied());
        }
        if found.is_empty()
            && let Some(list) = self.by_name.get(&name)
        {
            found.extend(list.iter().copied());
        }
        found.sort_unstable();
        found.dedup();
        found
    }
}

fn origins_of(idents: &[String], vars: &HashMap<String, BTreeSet<Origin>>) -> BTreeSet<Origin> {
    let mut out = BTreeSet::new();
    for id in idents {
        if let Some(set) = vars.get(id) {
            out.extend(set.iter().copied());
        }
    }
    out
}

fn is_primitive(type_text: &str) -> bool {
    let base = type_text
        .trim()
        .trim_end_matches('?')
        .trim_end_matches("[]")
        .to_lowercase();
    matches!(
        base.as_str(),
        "int"
            | "long"
            | "short"
            | "byte"
            | "sbyte"
            | "uint"
            | "ulong"
            | "ushort"
            | "float"
            | "double"
            | "decimal"
            | "bool"
            | "char"
            | "guid"
            | "datetime"
            | "datetimeoffset"
            | "timespan"
            | "system.int32"
            | "system.int64"
            | "system.boolean"
            | "system.guid"
            | "system.datetime"
            | "system.datetimeoffset"
            | "system.timespan"
    )
}

fn evaluate(method: &MethodDef, summaries: &[Facts], resolver: &Resolver) -> Facts {
    let mut facts = Facts::default();
    let mut vars: HashMap<String, BTreeSet<Origin>> = HashMap::new();
    for (i, param) in method.params.iter().enumerate() {
        let mut set = BTreeSet::new();
        if method.is_controller && method.is_public && !is_primitive(&param.type_text) {
            set.insert(Origin::Source);
        } else {
            set.insert(Origin::Param(i));
        }
        vars.insert(param.name.clone(), set);
    }
    for line in &method.lines {
        let mut origins = origins_of(&line.rhs_idents, &vars);
        if line.has_source {
            origins.insert(Origin::Source);
        }
        for call in &line.calls {
            for target in resolver.resolve(call) {
                let summary = &summaries[target];
                if summary.returns.contains(&Origin::Source) {
                    origins.insert(Origin::Source);
                }
                for (arg_index, arg_idents) in call.args.iter().enumerate() {
                    if summary.returns.contains(&Origin::Param(arg_index)) {
                        origins.extend(origins_of(arg_idents, &vars));
                    }
                }
            }
        }
        if let Some(target) = &line.assign {
            let mut assigned = origins.clone();
            if line.append
                && let Some(previous) = vars.get(target)
            {
                assigned.extend(previous.iter().copied());
            }
            vars.insert(target.clone(), assigned);
        }
        if let Some(kind) = line.sink
            && !origins.is_empty()
        {
            facts
                .sink_sites
                .entry(kind)
                .or_default()
                .insert((method.file, line.line));
            for origin in &origins {
                if let Origin::Param(index) = origin {
                    facts.param_to_sink.entry(*index).or_default().insert(kind);
                }
            }
        }
        if line.is_return {
            facts.returns.extend(origins.iter().copied());
        }
        for call in &line.calls {
            let args = call
                .args
                .iter()
                .map(|a| origins_of(a, &vars))
                .collect::<Vec<_>>();
            facts.calls.push((call.clone(), line.line, args));
        }
    }
    facts
}

fn propagate(methods: &[MethodDef], resolver: &Resolver, summaries: &mut [Facts]) {
    for _ in 0..MAX_HOPS {
        let snapshot = summaries.to_vec();
        let mut changed = false;
        for (index, method) in methods.iter().enumerate() {
            let mut facts = evaluate(method, &snapshot, resolver);
            for (call, _line, args) in &facts.calls {
                for target in resolver.resolve(call) {
                    let callee = &snapshot[target];
                    for (arg_index, arg_origins) in args.iter().enumerate() {
                        let Some(kinds) = callee.param_to_sink.get(&arg_index) else {
                            continue;
                        };
                        for kind in kinds {
                            for origin in arg_origins {
                                if let Origin::Param(position) = origin {
                                    facts
                                        .param_to_sink
                                        .entry(*position)
                                        .or_default()
                                        .insert(*kind);
                                    if let Some(sites) = callee.sink_sites.get(kind) {
                                        facts
                                            .sink_sites
                                            .entry(*kind)
                                            .or_default()
                                            .extend(sites.iter().copied());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if facts.param_to_sink != snapshot[index].param_to_sink
                || facts.sink_sites != snapshot[index].sink_sites
                || facts.returns != snapshot[index].returns
            {
                changed = true;
            }
            summaries[index] = facts;
        }
        if !changed {
            break;
        }
    }
}

fn finding(
    rule_id: &str,
    file: &SourceFile,
    line: usize,
    evidence: String,
    description: String,
) -> Finding {
    let info = rule_catalog()
        .iter()
        .find(|r| r.id == rule_id)
        .expect("registered flow rule");
    let digest = Sha256::digest(format!("{}:{rule_id}:{line}", file.relative));
    Finding {
        id: format!("{:x}", digest)[..16].to_string(),
        rule_id: rule_id.into(),
        category: Category::Security,
        subcategory: "跨檔案資料流".into(),
        title: info.title.into(),
        severity: info.severity,
        confidence: "低".into(),
        review_status: "啟發式跨檔案追蹤，需人工確認呼叫鏈".into(),
        engine: "Rust 跨檔案資料流".into(),
        file: file.relative.clone(),
        start_line: line,
        end_line: line,
        evidence: redact(&evidence),
        description,
        recommendation: info.recommendation.into(),
        limitations: "以方法名稱解析呼叫鏈，未做型別推導、介面／委派或動態分派解析；同名多載可能配錯，安全寫法也可能被列出。"
            .into(),
        references: vec![format!(
            "https://cwe.mitre.org/data/definitions/{}.html",
            info.cwe.trim_start_matches("CWE-")
        )],
        cwe: vec![info.cwe.into()],
    }
}

pub fn analyze(files: &[SourceFile]) -> FlowOutcome {
    let (methods, warnings, scanned) = collect_methods(files);
    let mut outcome = FlowOutcome {
        findings: vec![],
        files: scanned,
        methods: methods.len(),
        warnings,
    };
    if methods.is_empty() {
        return outcome;
    }
    let resolver = Resolver::build(&methods);
    let base = vec![Facts::default(); methods.len()];
    let mut summaries = methods
        .iter()
        .map(|m| evaluate(m, &base, &resolver))
        .collect::<Vec<_>>();
    propagate(&methods, &resolver, &mut summaries);

    let mut seen = BTreeSet::new();
    for (index, method) in methods.iter().enumerate() {
        for (call, call_line, args) in &summaries[index].calls {
            for (arg_index, arg_origins) in args.iter().enumerate() {
                if !arg_origins.contains(&Origin::Source) {
                    continue;
                }
                for target in resolver.resolve(call) {
                    let Some(kinds) = summaries[target].param_to_sink.get(&arg_index) else {
                        continue;
                    };
                    let callee = &methods[target];
                    for kind in kinds {
                        let Some(sites) = summaries[target].sink_sites.get(kind) else {
                            continue;
                        };
                        for (file_index, sink_line) in sites {
                            if !seen.insert((kind.rule_id(), *file_index, *sink_line)) {
                                continue;
                            }
                            let sink_file = &files[*file_index];
                            let caller = &files[method.file];
                            let source_text = caller
                                .text
                                .lines()
                                .nth(call_line.saturating_sub(1))
                                .unwrap_or("")
                                .trim();
                            let sink_text = sink_file
                                .text
                                .lines()
                                .nth(sink_line.saturating_sub(1))
                                .unwrap_or("")
                                .trim();
                            let display = match &callee.class {
                                Some(class) => format!("{class}.{}", callee.name),
                                None => callee.name.clone(),
                            };
                            let evidence = format!(
                                "來源：{}:{}｜{}\n呼叫：{}()（{}:{}）\n流入：{}:{}｜{}",
                                caller.relative,
                                call_line,
                                source_text,
                                display,
                                caller.relative,
                                call_line,
                                sink_file.relative,
                                sink_line,
                                sink_text
                            );
                            let description = format!(
                                "{}:{} 的使用者輸入在呼叫 {}() 時傳入，最後到達 {}:{} 的{}；此為啟發式跨檔案追蹤，需確認實際呼叫的型別與防護。",
                                caller.relative,
                                call_line,
                                display,
                                sink_file.relative,
                                sink_line,
                                kind.label()
                            );
                            outcome.findings.push(finding(
                                kind.rule_id(),
                                sink_file,
                                *sink_line,
                                evidence,
                                description,
                            ));
                        }
                    }
                }
            }
        }
    }
    outcome
}
