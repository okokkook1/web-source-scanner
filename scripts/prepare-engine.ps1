param(
    [string]$Destination = (Join-Path $PSScriptRoot '../../../outputs/web-source-scanner/engine'),
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$version = '1.182.0'
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$stagingPath = Join-Path ([System.IO.Path]::GetTempPath()) ('wss-engine-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stagingPath,$destinationPath -Force | Out-Null
try {
    & $Python -m pip download --no-deps --only-binary=:all: --platform win_amd64 --python-version 311 --implementation cp --dest $stagingPath "semgrep==$version"
    if ($LASTEXITCODE -ne 0) { throw 'Semgrep 官方 wheel 下載失敗。' }
    $wheel = Get-ChildItem -LiteralPath $stagingPath -Filter '*.whl' | Select-Object -First 1
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($wheel.FullName)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -match '^semgrep/bin/[^/]+\.(exe|dll)$') {
                $target = Join-Path $destinationPath ([System.IO.Path]::GetFileName($entry.FullName))
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$true)
            } elseif ($entry.FullName -match '\.dist-info/licenses/LICENSE$') {
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $destinationPath 'SEMGREP-LICENSE.txt'),$true)
            }
        }
    } finally { $archive.Dispose() }
    # The wheel's core binary reports its own build version, which can differ from
    # the wheel version. Record both instead of assuming they match.
    $corePath = Join-Path $destinationPath 'semgrep-core.exe'
    $coreReport = (& $corePath -version 2>&1 | Out-String).Trim()
    $coreVersion = 'unknown'
    $coreCommit = ''
    if ($coreReport -match 'semgrep-core version:\s*(\S+)\s*(?:\(([^)]*)\))?') {
        $coreVersion = $Matches[1]
        $coreCommit = ($Matches[2] -replace '-dirty$', '')
    }
    $note = ''
    if ($coreVersion -ne $version) {
        $note = "PyPI wheel semgrep $version bundles a native core that reports $coreVersion. The license and source references describe the distributed $version wheel; there is no public source tag for the core's own version string."
    }
    $manifest = [ordered]@{
        engine = 'Semgrep CE Core'
        version = $version
        core_reported_version = $coreVersion
        core_commit = $coreCommit
        source = "https://github.com/semgrep/semgrep/tree/v$version"
        source_archive = "https://github.com/semgrep/semgrep/archive/refs/tags/v$version.tar.gz"
        wheel_sha256 = (Get-FileHash -LiteralPath $wheel.FullName -Algorithm SHA256).Hash
        core_sha256 = (Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash
        created = [DateTimeOffset]::Now.ToString('o')
        note = $note
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destinationPath 'engine-manifest.json') -Encoding UTF8
    Write-Output "Native engine prepared: $destinationPath"
} finally {
    # Only delete this invocation's known, absolute staging directory.
    $resolvedStage = [System.IO.Path]::GetFullPath($stagingPath)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if ($resolvedStage.StartsWith($tempRoot,[System.StringComparison]::OrdinalIgnoreCase) -and ([System.IO.Path]::GetFileName($resolvedStage) -like 'wss-engine-*')) {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}

