use crate::model::*;
use std::{
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use walkdir::WalkDir;

pub fn decode(bytes: &[u8]) -> Result<DecodedSource, String> {
    if bytes.starts_with(&[255, 254]) || bytes.starts_with(&[254, 255]) {
        if !(bytes.len() - 2).is_multiple_of(2) {
            return Err("不完整的 UTF-16 內容".into());
        }
        let little = bytes[0] == 255;
        let units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if little {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            })
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units).map_err(|_| "無法解碼 UTF-16")?;
        return Ok(DecodedSource {
            text,
            encoding: if little { "UTF-16LE" } else { "UTF-16BE" }.into(),
        });
    }
    if bytes
        .iter()
        .any(|&b| b == 0 || (b < 9) || (b > 13 && b < 32))
    {
        return Err("二進位或控制字元內容".into());
    }
    let bytes = bytes.strip_prefix(&[239, 187, 191]).unwrap_or(bytes);
    if let Ok(s) = std::str::from_utf8(bytes) {
        return Ok(DecodedSource {
            text: s.to_owned(),
            encoding: "UTF-8".into(),
        });
    }
    let (text, _, bad) = encoding_rs::BIG5.decode(bytes);
    if bad {
        return Err("無法以 UTF-8／Big5 正確解碼".into());
    }
    Ok(DecodedSource {
        text: text.into_owned(),
        encoding: "Big5".into(),
    })
}

fn exclusion(path: &Path, root: &Path, extra: &[String]) -> Option<String> {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let lower = relative.to_lowercase();
    let parts = lower.split('/').collect::<Vec<_>>();
    if parts.iter().any(|s| {
        matches!(
            *s,
            ".git"
                | ".svn"
                | "bin"
                | "obj"
                | "target"
                | "node_modules"
                | "packages"
                | "vendor"
                | "umbraco"
                | "umbraco_client"
                | "app_data"
                | "generated"
                | "web references"
        ) || s.starts_with("validation")
            || s.starts_with(".superpowers")
    }) {
        return Some(format!("{relative}：第三方／產生碼／測試副本"));
    }
    let name = parts.last().copied().unwrap_or("");
    if name.ends_with(".min.js")
        || name.ends_with(".generated.cs")
        || name.ends_with(".designer.cs")
        || name.ends_with(".bak")
        || name.ends_with("_org.cs")
        || (name.ends_with(".js")
            && [
                "jquery",
                "bootstrap",
                "angular",
                "modernizr",
                "knockout",
                "underscore",
            ]
            .iter()
            .any(|p| name.starts_with(p)))
    {
        return Some(format!("{relative}：第三方／壓縮腳本／備份"));
    }
    if extra
        .iter()
        .any(|s| !s.trim().is_empty() && lower.contains(&s.to_lowercase().replace('\\', "/")))
    {
        return Some(format!("{relative}：使用者排除"));
    }
    None
}

pub fn inventory(options: &ScanOptions, cancel: &AtomicBool) -> Inventory {
    let mut result = Inventory::default();
    if cancel.load(Ordering::Relaxed) {
        result.cancelled = true;
        return result;
    }
    if !options.root.is_dir() {
        result.errors.push("指定路徑不是可讀取的資料夾".into());
        return result;
    }
    let mut walker = WalkDir::new(&options.root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();
    while let Some(entry) = walker.next() {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                result.errors.push(format!("無法列舉：{e}"));
                continue;
            }
        };
        let path = entry.path();
        if path == options.root {
            continue;
        }
        let relative = path
            .strip_prefix(&options.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let reparse = entry.path_is_symlink() || is_reparse(path);
        if reparse {
            result
                .excluded
                .push(format!("{relative}：連結／junction 不跟隨"));
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        if let Some(reason) = exclusion(path, &options.root, &options.excludes) {
            result.excluded.push(reason);
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        result.enumerated += 1;
        let extension = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if ![
            "cs", "cshtml", "js", "html", "aspx", "config", "csproj", "sln",
        ]
        .contains(&extension.as_str())
        {
            result
                .excluded
                .push(format!("{relative}：不支援的檔案類型"));
            continue;
        }
        match entry.metadata() {
            Ok(m) if m.len() <= options.max_file_bytes => {}
            Ok(_) => {
                result.errors.push(format!("{relative}：超過檔案大小上限"));
                continue;
            }
            Err(e) => {
                result.errors.push(format!("{relative}：無法讀取大小：{e}"));
                continue;
            }
        }
        let decoded = fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| decode(&b));
        match decoded {
            Ok(s) => {
                if s.encoding == "Big5" {
                    result.warnings.push(format!(
                        "{relative}：以 Big5 解碼，建議核對文字；引擎使用 UTF-8 鏡像"
                    ));
                }
                if s.text
                    .lines()
                    .take(8)
                    .any(|l| l.contains("<auto-generated"))
                {
                    result.excluded.push(format!("{relative}：標記為自動產生"));
                    continue;
                }
                result.files.push(SourceFile {
                    relative,
                    text: s.text,
                    encoding: s.encoding,
                    extension,
                });
            }
            Err(e) => result.errors.push(format!("{relative}：{e}")),
        }
    }
    if result.files.iter().any(|f| f.extension == "cs") {
        result.technologies.push("C# / ASP.NET（規則分析）".into());
    }
    if result.files.iter().any(|f| f.extension == "cshtml") {
        result.technologies.push("Razor（混合樣板規則）".into());
    }
    if result.files.iter().any(|f| f.extension == "js") {
        result.technologies.push("JavaScript".into());
    }
    if result.files.iter().any(|f| f.text.contains("Umbraco")) {
        result.technologies.push("Umbraco".into());
    }
    for project in result.files.iter().filter(|f| f.extension == "csproj") {
        let parent = Path::new(&project.relative)
            .parent()
            .unwrap_or(Path::new(""));
        if project.text.contains("349c5851")
            || parent
                .file_name()
                .is_some_and(|n| n.to_string_lossy().contains("Website"))
        {
            let config = parent
                .join("web.config")
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase();
            if !result
                .files
                .iter()
                .any(|f| f.relative.to_lowercase() == config)
            {
                result.warnings.push(format!(
                    "{}：缺少主網站 web.config，部署設定未完整涵蓋",
                    project.relative
                ));
            }
        }
    }
    result
}

#[cfg(windows)]
fn is_reparse(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    fs::symlink_metadata(path)
        .map(|m| m.file_attributes() & 0x400 != 0)
        .unwrap_or(false)
}
#[cfg(not(windows))]
fn is_reparse(_path: &Path) -> bool {
    false
}
