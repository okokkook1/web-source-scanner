param([string]$Destination = (Join-Path $PSScriptRoot '../../../outputs/web-source-scanner'))
$ErrorActionPreference = 'Stop'
$projectPath = Split-Path -Parent $PSScriptRoot
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
Push-Location $projectPath
try {
    & cargo build --release --locked --bin web-source-scanner
    if ($LASTEXITCODE -ne 0) { throw 'Rust release build failed.' }
    New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectPath 'target/release/web-source-scanner.exe') -Destination $destinationPath -Force
    & cargo build --release --locked --no-default-features --bin web-source-scanner-cli
    if ($LASTEXITCODE -ne 0) { throw 'Rust CLI build failed.' }
    Copy-Item -LiteralPath (Join-Path $projectPath 'target/release/web-source-scanner-cli.exe') -Destination $destinationPath -Force
    foreach ($file in @('README.md','THIRD-PARTY-NOTICES.md','LICENSE')) { Copy-Item -LiteralPath (Join-Path $projectPath $file) -Destination $destinationPath -Force }
    Copy-Item -LiteralPath (Join-Path $projectPath 'rules') -Destination $destinationPath -Recurse -Force
    if (!(Test-Path -LiteralPath (Join-Path $destinationPath 'engine/semgrep-core.exe'))) {
        & (Join-Path $PSScriptRoot 'prepare-engine.ps1') -Destination (Join-Path $destinationPath 'engine')
    }
    Get-FileHash -LiteralPath (Join-Path $destinationPath 'web-source-scanner.exe') -Algorithm SHA256 | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destinationPath 'executable-sha256.json') -Encoding UTF8
    Write-Output "Packaged: $destinationPath"
} finally { Pop-Location }
