param(
    [Parameter(Mandatory = $true)][string]$Archive
)
$ErrorActionPreference = 'Stop'
$archivePath = (Resolve-Path $Archive).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('flutterdec-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $work | Out-Null
try {
    $extracted = Join-Path $work 'extracted'
    Expand-Archive -Path $archivePath -DestinationPath $extracted
    $cli = Join-Path $extracted 'bin/flutterdec.exe'
    $registry = Join-Path $extracted 'share/flutterdec/adapters/registry.json'
    $producer = Join-Path $extracted 'share/flutterdec/adapters/python/adapter_template.py'
    $profile = Join-Path $extracted 'share/flutterdec/data/dart-profiles.json'
    foreach ($required in @($cli, $registry, $producer, $profile)) {
        if (!(Test-Path $required -PathType Leaf)) { throw "Missing archive member: $required" }
    }
    $isolatedProfile = Join-Path $work 'home'
    $cwd = Join-Path $work 'cwd'
    New-Item -ItemType Directory -Force $isolatedProfile, $cwd | Out-Null
    $oldLocation = Get-Location
    $oldEnv = @{}
    foreach ($name in @('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'XDG_DATA_HOME', 'FLUTTERDEC_ADAPTER_STORE', 'FLUTTERDEC_DATA_DIR', 'FLUTTERDEC_SYMBOL_CACHE')) {
        $oldEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    try {
        Set-Location $cwd
        $env:USERPROFILE = $isolatedProfile
        & $cli --version
        if ($LASTEXITCODE -ne 0) { throw 'CLI --version failed' }
        $beforeText = & $cli adapter list --json
        if ($LASTEXITCODE -ne 0) { throw 'adapter list failed' }
        $hashMatch = [regex]::Match(($beforeText -join [Environment]::NewLine), '"snapshot_hash"\s*:\s*"([0-9a-f]{32})"')
        if (!$hashMatch.Success) { throw 'adapter list did not load a snapshot hash' }
        $hash = $hashMatch.Groups[1].Value
        if (!(Select-String -Path $registry -Pattern $hash -Quiet)) { throw 'snapshot hash is not in packaged registry' }
        $installedText = & $cli adapter install --dart-hash $hash --json
        if ($LASTEXITCODE -ne 0) { throw 'adapter install failed' }
        if (($installedText -join [Environment]::NewLine) -notmatch '"source"\s*:\s*"packaged-producer"') {
            throw 'adapter install did not use packaged producer'
        }
        $afterText = & $cli adapter list --json
        if ($LASTEXITCODE -ne 0 -or ($afterText -join [Environment]::NewLine) -notmatch '"state"\s*:\s*"verified"') {
            throw 'adapter list did not report a verified adapter'
        }
        $store = Join-Path $isolatedProfile 'AppData/Local/flutterdec/adapters'
        if (!(Test-Path (Join-Path $store 'artifacts'))) { throw 'writable adapter store was not created under USERPROFILE' }
        Write-Host '[windows-release-smoke] extracted distribution works outside checkout'
    }
    finally {
        Set-Location $oldLocation
        foreach ($name in $oldEnv.Keys) {
            [Environment]::SetEnvironmentVariable($name, $oldEnv[$name], 'Process')
        }
    }
}
finally {
    Remove-Item -Recurse -Force $work
}
