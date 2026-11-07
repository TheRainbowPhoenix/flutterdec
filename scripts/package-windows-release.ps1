param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Archive
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$binaryPath = (Resolve-Path $Binary).Path
$archivePath = [IO.Path]::GetFullPath($Archive)
$stage = Join-Path $env:RUNNER_TEMP 'flutterdec-windows-stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
$binDir = Join-Path $stage 'bin'
$dataDir = Join-Path $stage 'share/flutterdec'
New-Item -ItemType Directory -Force $binDir, (Join-Path $dataDir 'adapters/python'), (Join-Path $dataDir 'data') | Out-Null
Copy-Item $binaryPath (Join-Path $binDir 'flutterdec.exe')
Copy-Item (Join-Path $repo 'adapters/registry.json') (Join-Path $dataDir 'adapters/registry.json')
Copy-Item (Join-Path $repo 'adapters/python/adapter_template.py') (Join-Path $dataDir 'adapters/python/adapter_template.py')
Copy-Item (Join-Path $repo 'data/*.json') (Join-Path $dataDir 'data')
$archiveDir = Split-Path -Parent $archivePath
New-Item -ItemType Directory -Force $archiveDir | Out-Null
if (Test-Path $archivePath) { Remove-Item -Force $archivePath }
Compress-Archive -Path (Join-Path $stage 'bin'), (Join-Path $stage 'share') -DestinationPath $archivePath
Write-Host "[package-windows-release] wrote $archivePath"
