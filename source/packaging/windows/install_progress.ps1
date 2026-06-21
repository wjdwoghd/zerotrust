param(
    [string]$Payload = "",
    [int]$AutoCloseSeconds = -1
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installCmd = Join-Path $scriptDir "install.cmd"
$logFile = Join-Path $env:TEMP "ZeroTrustDemoInstallProgress.log"
$cmdLogFile = Join-Path $env:TEMP "ZeroTrustDemoInstallCommand.log"
Set-Content -LiteralPath $logFile -Value ("ZeroTrust installer GUI log " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -Encoding UTF8
Set-Content -LiteralPath $cmdLogFile -Value "" -Encoding UTF8

$form = New-Object System.Windows.Forms.Form
$form.Text = "ZeroTrust Demo 설치"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size -ArgumentList 560, 380
$form.MinimumSize = New-Object System.Drawing.Size -ArgumentList 560, 380
$form.MaximizeBox = $false

$title = New-Object System.Windows.Forms.Label
$title.Text = "ZeroTrust Demo 설치 중"
$title.Font = New-Object System.Drawing.Font -ArgumentList "Malgun Gothic", 14, ([System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point -ArgumentList 18, 16
$form.Controls.Add($title)

$status = New-Object System.Windows.Forms.Label
$status.Text = "설치를 준비하는 중입니다..."
$status.Font = New-Object System.Drawing.Font -ArgumentList "Malgun Gothic", 9
$status.AutoSize = $false
$status.Size = New-Object System.Drawing.Size -ArgumentList 506, 28
$status.Location = New-Object System.Drawing.Point -ArgumentList 20, 58
$form.Controls.Add($status)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 0
$progress.Style = "Continuous"
$progress.Size = New-Object System.Drawing.Size -ArgumentList 506, 24
$progress.Location = New-Object System.Drawing.Point -ArgumentList 20, 92
$form.Controls.Add($progress)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = "Vertical"
$logBox.Font = New-Object System.Drawing.Font -ArgumentList "Consolas", 9
$logBox.Size = New-Object System.Drawing.Size -ArgumentList 506, 160
$logBox.Location = New-Object System.Drawing.Point -ArgumentList 20, 132
$form.Controls.Add($logBox)

$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Text = "닫기"
$closeButton.Enabled = $false
$closeButton.Size = New-Object System.Drawing.Size -ArgumentList 96, 32
$closeButton.Location = New-Object System.Drawing.Point -ArgumentList 430, 304
$closeButton.Add_Click({ $form.Close() })
$form.Controls.Add($closeButton)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500

$script:process = $null
$script:lastLineCount = 0
$script:currentPercent = 0
$script:lastFailureLine = ""
$script:exitCode = 1

function Write-Log([string]$Message) {
    Add-Content -LiteralPath $logFile -Value ("[" + (Get-Date -Format "HH:mm:ss") + "] " + $Message) -Encoding UTF8
}

function Append-UiLog([string]$Message) {
    $logBox.AppendText(("[" + (Get-Date -Format "HH:mm:ss") + "] " + $Message + [Environment]::NewLine))
    Write-Log $Message
}

function Get-PercentFromLine([string]$Line, [int]$Fallback) {
    if ($Line -like "*Step 1/6*") { return 8 }
    if ($Line -like "*Step 2/6*") { return 16 }
    if ($Line -like "*Step 3/6*") { return 25 }
    if ($Line -like "*Step 4/6*") { return 72 }
    if ($Line -like "*Step 5/6*") { return 82 }
    if ($Line -like "*Step 6/6*") { return 92 }
    if ($Line -like "*Installation complete*") { return 100 }
    return $Fallback
}

function Update-FromInstallLine([string]$Line) {
    if ([string]::IsNullOrWhiteSpace($Line)) {
        return
    }

    $script:currentPercent = Get-PercentFromLine $Line $script:currentPercent
    $progress.Value = [Math]::Min(100, [Math]::Max(0, $script:currentPercent))
    $status.Text = $Line
    Append-UiLog $Line

    if ($Line -like "*Failed*" -or $Line -like "*failed*" -or $Line -like "*Missing*" -or $Line -like "*ERROR*" -or $Line -like "*오류*") {
        $script:lastFailureLine = $Line
    }
}

function Read-NewInstallOutput {
    if (-not (Test-Path -LiteralPath $cmdLogFile)) {
        return
    }

    $lines = @(Get-Content -LiteralPath $cmdLogFile -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ($lines.Count -le $script:lastLineCount) {
        return
    }

    for ($i = $script:lastLineCount; $i -lt $lines.Count; $i++) {
        Update-FromInstallLine $lines[$i]
    }
    $script:lastLineCount = $lines.Count
}

function Enable-AutoClose {
    if ($AutoCloseSeconds -ge 0) {
        $autoCloseTimer = New-Object System.Windows.Forms.Timer
        $autoCloseTimer.Interval = [Math]::Max(1, $AutoCloseSeconds) * 1000
        $autoCloseTimer.Add_Tick({
            $autoCloseTimer.Stop()
            $form.Close()
        })
        $autoCloseTimer.Start()
    }
}

function Complete-Install {
    $timer.Stop()
    $closeButton.Enabled = $true
    $status.Text = "설치가 완료되었습니다. 바탕화면의 ZeroTrust 바로가기를 실행하세요."
    $progress.Value = 100
    Append-UiLog "done"

    if ($AutoCloseSeconds -lt 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "ZeroTrust Demo 설치가 완료되었습니다.",
            "ZeroTrust Demo 설치",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }

    $script:exitCode = 0
    Enable-AutoClose
}

function Fail-Install([string]$Message) {
    $timer.Stop()
    $closeButton.Enabled = $true
    $status.Text = "설치가 실패했습니다."

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = "알 수 없는 오류"
    }

    if (-not [string]::IsNullOrWhiteSpace($script:lastFailureLine) -and $Message -notlike "*$script:lastFailureLine*") {
        $Message = $Message + "`n`n마지막 오류: " + $script:lastFailureLine
    }

    $Message = $Message + "`n`n로그: " + $cmdLogFile
    Append-UiLog ("ERROR: " + ($Message -replace "`r?`n", " | "))

    if ($AutoCloseSeconds -lt 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "설치가 실패했습니다.`n`n$Message",
            "ZeroTrust Demo 설치",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }

    $script:exitCode = 1
    Enable-AutoClose
}

function Start-InstallProcess {
    Write-Log "scriptDir=$scriptDir"
    Write-Log "installCmd=$installCmd"
    Write-Log "payload=$Payload"

    if (-not (Test-Path -LiteralPath $installCmd)) {
        throw "install.cmd not found: $installCmd"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $scriptDir "payload.zip"))) {
        throw "payload.zip not found: " + (Join-Path $scriptDir "payload.zip")
    }
    if (-not (Test-Path -LiteralPath (Join-Path $scriptDir "install_helpers.ps1"))) {
        throw "install_helpers.ps1 not found: " + (Join-Path $scriptDir "install_helpers.ps1")
    }

    $script:currentPercent = 2
    $progress.Value = 2
    $status.Text = "설치 프로그램을 시작하는 중..."
    Append-UiLog "start install.cmd /quiet"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cmd.exe"
    $psi.Arguments = '/d /c call "' + $installCmd + '" /quiet > "' + $cmdLogFile + '" 2>&1'
    $psi.WorkingDirectory = $scriptDir
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    Write-Log ("start: " + $psi.FileName + " " + $psi.Arguments)
    $script:process = New-Object System.Diagnostics.Process
    $script:process.StartInfo = $psi
    [void]$script:process.Start()
    $timer.Start()
}

$timer.Add_Tick({
    try {
        Read-NewInstallOutput

        if ($script:process -and $script:process.HasExited) {
            Read-NewInstallOutput
            Write-Log ("exitCode=" + $script:process.ExitCode)

            if ($script:process.ExitCode -eq 0) {
                Complete-Install
            } else {
                Fail-Install ("install.cmd /quiet failed with exit code " + $script:process.ExitCode)
            }
        }
    } catch {
        Fail-Install $_.Exception.Message
    }
})

$form.Add_FormClosing({
    if (-not $closeButton.Enabled) {
        $_.Cancel = $true
        [System.Windows.Forms.MessageBox]::Show(
            "설치가 진행 중입니다. 완료될 때까지 기다려 주세요.",
            "ZeroTrust Demo 설치",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
})

$form.Add_Shown({
    try {
        Start-InstallProcess
    } catch {
        Fail-Install $_.Exception.Message
    }
})

[System.Windows.Forms.Application]::Run($form)
exit $script:exitCode
