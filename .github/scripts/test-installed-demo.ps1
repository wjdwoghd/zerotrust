param(
    [Parameter(Mandatory=$true)]
    [string]$Installer
)

$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:LOCALAPPDATA 'ZeroTrustDemo'
$lockRoot = Join-Path $env:LOCALAPPDATA 'ZeroTrustDemo.install.lock'
$stageRoot = Join-Path $env:LOCALAPPDATA 'ZeroTrustDemo.installing'

if (Test-Path -LiteralPath $installRoot) {
    throw "The Windows runner is not clean: $installRoot already exists."
}
if (-not (Test-Path -LiteralPath $Installer)) {
    throw "Installer is missing: $Installer"
}

$python = Join-Path $installRoot 'runtime\python\python.exe'
$controller = Join-Path $installRoot 'zt_demo_ctl.py'
$setup = Start-Process -FilePath (Resolve-Path -LiteralPath $Installer).Path -ArgumentList '/Q:A' -PassThru
$installed = $false
for ($attempt = 0; $attempt -lt 24; $attempt++) {
    if ($setup.HasExited -and $setup.ExitCode -ne 0) {
        throw "Installer exited with code $($setup.ExitCode)."
    }
    if ((Test-Path -LiteralPath $python) -and -not (Test-Path -LiteralPath $lockRoot)) {
        $installed = $true
        break
    }
    if ($setup.HasExited) {
        Start-Sleep -Seconds 30
    } else {
        [void]$setup.WaitForExit(30000)
    }
    if ($attempt % 2 -eq 1) {
        Write-Output "Installer minute $([int](($attempt + 1) / 2)): lock=$(Test-Path -LiteralPath $lockRoot), staging=$(Test-Path -LiteralPath $stageRoot), installed=$(Test-Path -LiteralPath $installRoot)"
    }
}
if (-not $installed) {
    Stop-Process -Id $setup.Id -Force -ErrorAction SilentlyContinue
    throw 'Installer did not create a complete installation within twelve minutes.'
}
foreach ($required in @($python, $controller,
        (Join-Path $installRoot 'server.py'),
        (Join-Path $installRoot 'runtime\postgres\bin\postgres.exe'))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Installed file missing: $required" }
}
if (Test-Path -LiteralPath $lockRoot) { throw 'Installer lock remains after setup.' }
foreach ($excluded in @('tests', 'build', 'dist', 'requirements-dev.txt', 'scripts\bootstrap_admin.py')) {
    if (Test-Path -LiteralPath (Join-Path $installRoot $excluded)) {
        throw "Development file was installed: $excluded"
    }
}

$shell = New-Object -ComObject WScript.Shell
$desktop = $shell.SpecialFolders.Item('Desktop')
foreach ($shortcut in @('ZeroTrust.lnk', 'ZeroTrust 제어.lnk', 'ZeroTrust 토큰 기기.lnk')) {
    if (-not (Test-Path -LiteralPath (Join-Path $desktop $shortcut))) {
        throw "Desktop shortcut missing: $shortcut"
    }
}

$started = $false
try {
    & $python $controller start
    if ($LASTEXITCODE -ne 0) { throw "Installed controller start failed: $LASTEXITCODE" }
    $started = $true

    $portLine = Get-Content -LiteralPath (Join-Path $installRoot '.env') |
        Where-Object { $_ -match '^SERVER_PORT=[0-9]+$' } | Select-Object -First 1
    if (-not $portLine) { throw 'Installed server port is missing.' }
    $baseUrl = "http://127.0.0.1:$($portLine.Split('=')[1])"
    $health = Invoke-RestMethod -Uri "$baseUrl/healthz" -TimeoutSec 10
    if ($health.status -ne 'ok' -or $health.service -ne 'zerotrust') {
        throw 'Installed server health response is invalid.'
    }
    $ready = Invoke-RestMethod -Uri "$baseUrl/readyz" -TimeoutSec 10
    if ($ready.status -ne 'ready') { throw 'Installed server is not ready.' }
    try {
        Invoke-WebRequest -Uri "$baseUrl/api/auth/me" -TimeoutSec 10 | Out-Null
        throw 'Unauthenticated session request was accepted.'
    } catch {
        if ([int]$_.Exception.Response.StatusCode -ne 401) { throw }
    }
    $launchers = Get-ChildItem -LiteralPath (Join-Path $installRoot 'apps\launchers') -Filter 'token_*.pyw'
    if ($launchers.Count -lt 1) { throw 'No token launcher was generated.' }
    foreach ($launcher in $launchers) {
        if (-not (Select-String -LiteralPath $launcher.FullName -Pattern ([regex]::Escape($baseUrl)) -Quiet)) {
            throw "Token launcher uses a different URL: $($launcher.Name)"
        }
    }

    & $python $controller stop
    if ($LASTEXITCODE -ne 0) { throw "Installed controller stop failed: $LASTEXITCODE" }
    $started = $false
    if (Test-Path -LiteralPath (Join-Path $installRoot 'logs\server.pid')) {
        throw 'Server PID file remains after shutdown.'
    }
    $pgCtl = Join-Path $installRoot 'runtime\postgres\bin\pg_ctl.exe'
    $pgData = Join-Path $installRoot 'data\postgres'
    & $pgCtl -D $pgData status | Out-Null
    if ($LASTEXITCODE -eq 0) { throw 'PostgreSQL remains running after shutdown.' }
    Write-Output "Fresh Windows installation smoke passed at $baseUrl"
} finally {
    if ($started) { & $python $controller stop | Out-Null }
}
