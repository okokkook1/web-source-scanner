# 原碼檢查站 — Windows 網站原始碼掃描工具

Rust 中文視窗 + 原生 Semgrep CE Core 本機引擎，針對 C#／ASP.NET MVC 網站，分別產出安全漏洞與程式碼品質／效能報告。

## 下載預先編譯版本

GitHub Releases 提供 Windows x64 可攜版（含原生引擎、規則、授權文件與 SHA-256）：

<https://github.com/okokkook1/web-source-scanner/releases/latest>

解壓後雙擊 `web-source-scanner.exe`；`engine` 資料夾必須與執行檔放在一起。執行檔未簽章，Windows 可能顯示 SmartScreen 提示。

## 一般使用

1. 保留完整 `web-source-scanner` 資料夾，雙擊 `web-source-scanner.exe`。
2. 按「選擇資料夾」，指定網站原始碼資料夾，例如 `D:\Website`。
3. 選擇全部、安全漏洞或品質與效能，按「開始掃描」。
4. 點選結果查看檔案、行號、判定信心與修正建議。
5. 確認「報告輸出資料夾」（預設 `文件\網站掃描報告`，可自行輸入或按「選擇…」），再按「匯出 HTML / CSV / JSON」；不想用對話框時可直接用這個欄位。

匯出後會建立獨立的 `scan-時間識別碼` 子資料夾（「選擇資料夾並匯出…」也走同一流程）。HTML 可直接離線閱讀，CSV 可用 Excel 開啟；JSON 包含機器可讀結果與覆蓋資訊。兩類結果可分別匯出；畫面搜尋與嚴重度篩選不會刪除報告內的結果，匯出範圍由匯出選單決定。受掃描網站內的資料夾不可作為輸出，錯誤會顯示在匯出區塊。

Windows 10／11 x64，使用系統微軟正黑體。交付資料夾已附原生引擎與 DLL，一般使用者不需要安裝 Python、Node.js、Visual Studio 或架設伺服器。主程式與 `engine` 資料夾必須一起移動；不需系統管理員權限。首次執行未簽署程式可能出現 Windows 的一般信任提示，本工具沒有要求修改系統安全設定。

## 報告檔案

- `security-vulnerabilities.html` / `.csv` / `.json`：安全類。
- `code-quality-performance.html` / `.csv` / `.json`：品質與效能類。
- `scan-summary.json`：引擎版本、狀態、檔案覆蓋、排除、警告、錯誤與套件盤點。

「部分完成」表示有檔案、語法解析或引擎未完整執行，必須查看覆蓋摘要。「零命中」不代表網站沒有漏洞。「效能」是改善線索，沒有執行負載測試或量測速度。

## 第一版分析能力

28 組自製規則：10 組由 Semgrep 引擎執行，18 組由 Rust 的語法樹／設定解析／樣板與跨檔案追蹤執行。規則使用正反例驗證，規則數量不代表檢出率。

- C#：函式內的輸入到 SQL、命令／檔案操作資料流；TLS 驗證繞過、弱雜湊、BinaryFormatter、停用 MVC 驗證、原始 HTML 輸出。
- **跨檔案資料流**：建立方法摘要與呼叫鏈，追蹤 Request 輸入或 MVC 動作參數經過多個方法／檔案後，是否到達 SQL、系統命令、檔案操作或 HTML 輸出。以方法名稱解析呼叫鏈，未做型別推導、介面／委派或動態分派，全部標示低信心。
- JavaScript：eval／Function、innerHTML／document.write 等危險用法。
- Razor：原始 HTML 輸出規則；不提供完整 Razor C# 語意模型。
- XML 設定：debug、詳細錯誤、明確停用 Cookie 防護、停用 Request Validation、疑似憑證。
- C# 品質：空白 catch、throw 變數、過長函式、巢狀流程、資源管理疑慮。
- 效能：迴圈內查詢／具現化、同步等待與執行緒 Sleep。第一版的 `.Result` 檢查缺少型別模型，可能將一般業務結果屬性（例如某些 ORM／CMS 物件的 `xxx.Result`）列為低信心線索；請先確認是否真的是 Task，不能把命中數當成已確認的效能問題。

**重要限制：** 引擎成熟度與規則庫完整度是不同的事。本工具使用的是自製、有限的規則集，不等同於購買完整商用規則。Semgrep CE 不含付費跨檔案深度分析；本版以 Rust 啟發式跨檔案追蹤補強，但仍沒有 .NET 型別／建置語意模型，也未提供完整重複碼、業務權限、全域防護、跨服務資料流或動態漏洞驗證。未知自訂函式、別名與框架封裝可能漏報；危險 API 或語法模式可能誤報。所有結果均需依信心及證據人工核對。

掃描不執行目標網站、不連資料庫、不建置或修正來源檔，也沒有來源上傳功能。引擎僅使用內嵌本機規則及本機來源鏡像；不使用 Registry、自動規則、帳號、metrics 或版本檢查。UTF-8／UTF-16／Big5 來源會轉成暫存 UTF-8 鏡像供引擎使用，原始檔保持原樣，行號不變。Big5 是明確標記的推定解碼，請核對內容。

預設排除套件、第三方常見腳本、壓縮腳本、產生碼、Web References、validation 副本與備份；不跟隨 junction／符號連結，不依 `.gitignore` 隱藏其他業務檔案。額外排除是「路徑片段」，不是萬用字元。大於 2,000,000 bytes 或無法解碼的檔案會記錄為未完整涵蓋。

報告預設遮蔽常見密碼／token／私密金鑰格式。報告仍可能包含業務原始碼與路徑，請依原專案的存取方式保管。遮蔽只針對明確辨識的憑證模式，不能保證遮蔽任意格式的所有敏感資料。

## 套件已知漏洞

預設僅盤點 `packages.config` 中的套件與版本；視窗版預設會同時勾選線上 OSV 查詢，取消勾選後就只做盤點。

### 線上查詢 OSV.dev（GUI 預設開啟，可取消）

視窗版在「掃描強度」預設勾選「最強掃描：線上查詢套件漏洞」，CLI 則需加 `--osv`。只會把 NuGet 套件名稱與版本送到 `api.osv.dev`，不送出原始碼、路徑或檔案內容；不想連線時取消勾選即可。

- 需要網路與 Windows 內建 `curl.exe`；單次查詢上限 30 秒。
- 結果快取在 `%LOCALAPPDATA%\WebSourceScanner\osv-cache.json` 24 小時，重複掃描不會重複查詢。
- 每筆命中會列出 GHSA／CVE、CVSS 等級、修復版本與公告連結；仍須確認實際載入的 DLL 版本、載入路徑與程式碼可達性。
- 查詢失敗（離線、被防火牆阻擋、curl 缺失）會標示「部分完成」並保留錯誤，不會被當成零漏洞。

### OWASP Dependency-Check（選配，未內附）

可在進階設定指定已備妥的 OWASP Dependency-Check CLI 與本機資料庫，或匯入該工具先前產生的 JSON。CLI 以 `--noupdate` 與停用可關閉的線上分析器執行；此交付不包含 Java、大型漏洞資料庫或商用授權。資料庫的準備與更新需由工具管理者另行處理。此轉接器與 JSON 匯入經測試，**未在本次交付中執行真實 Dependency-Check CVE 掃描**；版本／資料庫日期未知時不能宣稱已取得最新漏洞覆蓋。若需要 NVD 等級的覆蓋，請另行建置 Dependency-Check 資料庫，或改用 OSV 線上查詢。

匯入會保留原報告日期、引擎版本、資料庫來源日期及報告雜湊，只將能核對的 NuGet ID／版本計入套件覆蓋；外部報告與本次來源的關聯仍標示為 `imported_unverified`，並將整體標示部分完成。空報告不會冒充已掃完整套件。

已知的選配轉接限制：若 CLI 位於 `D:\dc\bin\dependency-check.bat`，程式目前查找 `D:\dc\bin\data`，不會自動改用 `D:\dc\data`，也尚未提供獨立 data-dir 選項。若資料庫位置不同，第一版請優先使用既有 JSON 匯入；這不影響預設的原始碼掃描。

## 命令列／自動化

```powershell
.\web-source-scanner-cli.exe --scan 'D:\Website' --output 'D:\掃描報告\website'
.\web-source-scanner-cli.exe --scan 'D:\網站' --output 'D:\報告' --mode security --osv
.\web-source-scanner-cli.exe --scan 'D:\網站' --output 'D:\報告' --mode quality --exclude 'archive/'
```

其他參數：`--osv`（線上查詢套件漏洞）、`--engine`、`--dependency-check`、`--dependency-report`、`--timeout 180`（1–3600 秒）、`--gui-root`（預填視窗資料夾、不自動掃描）。命令列模式仍匯出兩份分類結果；只掃一類時另一類為空白。退出代碼：0 完成、2 部分完成、1 失敗、130 取消。是否有高風險命中不改變退出代碼；自動化應自行讀取 JSON 評估。

自動化請用 `web-source-scanner-cli.exe`，它會讓 PowerShell 正常等待並取得退出碼；視窗版在 Windows 使用無主控台子系統，直接呼叫它時 PowerShell 可能提前返回。

## 開發與重新封裝

需要 Rust stable MSVC 與 Windows C++ Build Tools。第一次取得依賴或準備引擎需要網路；之後掃描可離線。

發布到公開儲存庫前，先執行 `python scripts/check-publication.py .`：它會檢查客戶／專案識別字、憑證、PII、私有 IP 與不該提交的產物，發現問題會以非零結束碼擋下。`scripts/prepare-public.py` 會先產生只含原始碼、規則、測試與授權文件的可發布副本，再自動掃描該副本。

```powershell
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
python scripts/test-engine.py '<完整引擎路徑>\semgrep-core.exe'
cargo test --test native_engine_tests -- --ignored
powershell -NoProfile -File scripts/package.ps1
```

`scripts/prepare-engine.ps1` 從 PyPI 取得固定 Semgrep 1.182.0 Windows wheel，只擷取原封不動的原生引擎／DLL 與授權，不修改全域 Python。可指定 `WSS_ENGINE` 或 `--engine` 供測試。獨立引擎協定依固定版本的 Targets JSON；換引擎版本前必須執行完整相容性測試。

版本標示方式：該 wheel 內附的 `semgrep-core.exe` 自行回報 `1.182.1`（上游 wheel 的建置產物，帶 `dirty` 標記，GitHub 沒有對應的公開 `v1.182.1` 標籤）。因此報告與 `scan-summary.json` 的引擎版本以執行檔實際回報為準，授權與原始碼來源則指向實際散布的 1.182.0 wheel 與 `v1.182.0` 標籤；`engine/engine-manifest.json` 同時記錄 wheel 版本、core 回報版本、core commit 與兩者 SHA-256。這是如實記錄，不代表兩者為同一建置。

Windows 沙箱可能限制 Semgrep 的本機 socketpair 或暫存檔原子更名。開發驗證需在一般使用者權限的 Windows 環境執行；程式不應要求使用者停用防護。

