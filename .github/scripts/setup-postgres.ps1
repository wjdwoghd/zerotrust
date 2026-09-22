param([Parameter(Mandatory = $true)][string]$Destination)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Official EDB Windows x64 archive, shared by test and build jobs.
# Update version and checksum together; verify the new runtime before release.
$version = '18.6'
$archiveName = "postgresql-$version-1-windows-x64-binaries.zip"
$expectedHash = 'fbe23da234ee31547bf8a36d29dfd81e82b849df2d2b78d2eecb43d360252f8c'
$url = "https://get.enterprisedb.com/postgresql/$archiveName"

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$archivePath = Join-Path $destinationPath $archiveName
if (!(Test-Path -LiteralPath $archivePath)) {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $archivePath
}
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "PostgreSQL archive checksum mismatch: $archivePath"
}

$runtimeRoot = Join-Path $destinationPath 'pgsql'
if (!(Test-Path -LiteralPath (Join-Path $runtimeRoot 'bin\postgres.exe'))) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $destinationPath
}
$actualVersion = & (Join-Path $runtimeRoot 'bin\postgres.exe') --version
if ($LASTEXITCODE -ne 0 -or $actualVersion.Trim() -ne "postgres (PostgreSQL) $version") {
    throw "Unexpected PostgreSQL version: $actualVersion"
}
if ($env:GITHUB_ENV) {
    "ZT_PG_ROOT=$runtimeRoot" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
    "ZT_PG_VERSION=$version" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
    "ZT_PG_SHA256=$expectedHash" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
}
Write-Output "Verified PostgreSQL $version at $runtimeRoot"
