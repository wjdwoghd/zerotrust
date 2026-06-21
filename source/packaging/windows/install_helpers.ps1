param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("stop", "replace")]
    [string]$Action,

    [Parameter(Mandatory=$true)]
    [string]$InstallDir,

    [string]$StagingDir = ""
)

$ErrorActionPreference = "Stop"

function Normalize-PathText([string]$PathText) {
    return [System.IO.Path]::GetFullPath($PathText).TrimEnd("\")
}

function Test-PathUnderRoot([string]$PathText, [string]$RootText) {
    if ([string]::IsNullOrWhiteSpace($PathText)) {
        return $false
    }
    return $PathText.StartsWith($RootText, [System.StringComparison]::OrdinalIgnoreCase)
}

function Stop-ZeroTrustProcesses([string]$RootText) {
    $self = $PID
    $candidates = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        if ($_.ProcessId -eq $self) {
            return $false
        }

        $exe = [string]$_.ExecutablePath
        $cmd = [string]$_.CommandLine
        (Test-PathUnderRoot $exe $RootText) -or
            (-not [string]::IsNullOrWhiteSpace($cmd) -and
             $cmd.IndexOf($RootText, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    }

    foreach ($proc in $candidates) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }

    Start-Sleep -Milliseconds 900
}

function Remove-DirectoryWithRetry([string]$PathText, [int]$Attempts) {
    for ($i = 0; $i -lt $Attempts; $i++) {
        if (-not (Test-Path -LiteralPath $PathText)) {
            return $true
        }

        Remove-Item -LiteralPath $PathText -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 700
    }

    return -not (Test-Path -LiteralPath $PathText)
}

function Move-DirectoryWithRetry([string]$Source, [string]$Destination, [int]$Attempts) {
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            Move-Item -LiteralPath $Source -Destination $Destination -ErrorAction Stop
            return $true
        } catch {
            Start-Sleep -Milliseconds 700
        }
    }

    return $false
}

function Replace-InstallDirectory([string]$InstallPath, [string]$StagePath) {
    if ([string]::IsNullOrWhiteSpace($StagePath) -or -not (Test-Path -LiteralPath $StagePath)) {
        Write-Output "[ZeroTrust Setup] Staging directory is missing."
        exit 1
    }

    $root = Normalize-PathText $InstallPath
    Stop-ZeroTrustProcesses $root

    $parent = Split-Path -Parent $InstallPath
    $stamp = (Get-Date -Format "yyyyMMddHHmmssfff")
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $backup = Join-Path $parent ("ZeroTrustDemo.old.$stamp.$suffix")

    if (Test-Path -LiteralPath $InstallPath) {
        $movedAside = Move-DirectoryWithRetry $InstallPath $backup 5
        if (-not $movedAside) {
            [void](Remove-DirectoryWithRetry $InstallPath 5)
        }
    }

    if (Test-Path -LiteralPath $InstallPath) {
        Write-Output "[ZeroTrust Setup] Failed to replace existing install directory."
        Write-Output "[ZeroTrust Setup] Close ZeroTrust windows/processes and run the installer again."
        exit 1
    }

    Move-Item -LiteralPath $StagePath -Destination $InstallPath -ErrorAction Stop

    Get-ChildItem -LiteralPath $parent -Directory -Filter "ZeroTrustDemo.old.*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
}

$installRoot = Normalize-PathText $InstallDir

if ($Action -eq "stop") {
    Stop-ZeroTrustProcesses $installRoot
    exit 0
}

if ($Action -eq "replace") {
    Replace-InstallDirectory $InstallDir $StagingDir
    exit 0
}
