<#
.SYNOPSIS
    ZeroTrust 통합 실행 스크립트 (PowerShell)

.DESCRIPTION
    .bat 의 PowerShell 버전. 사용법은 동일하다.

    운영 모드: .env 로드 → 환경 검증 → 포트 정리 → 마이그레이션 →
               wipe → reseed → 서버 기동
    테스트 모드: zerotrust_test DB 에 대해 pytest 실행. 운영 DB 는 영향 X.

.EXAMPLE
    .\scripts\run.ps1
        운영 서버 기동 (최초 + 재실행 통합)

.EXAMPLE
    .\scripts\run.ps1 test
        전체 테스트 스위트 실행

.EXAMPLE
    .\scripts\run.ps1 test -k smoke -v
        pytest 인자 그대로 전달 — smoke 테스트만 verbose 실행

.NOTES
    매 운영 실행은 모든 사용 흔적을 청소하고 시드를 재삽입한다.
    시연 도중 다시 실행하면 진행 데이터가 사라지므로 주의.

    사전 준비 (1회):
        - .env 파일 (SECRET_KEY 32자 이상)
        - PostgreSQL 운영 DB:  CREATE DATABASE zerotrust OWNER ztuser;
        - PostgreSQL 테스트 DB: CREATE DATABASE zerotrust_test OWNER ztuser;
#>

# Python stdout 을 UTF-8 로 강제 (콘솔 코드페이지 충돌 방지)
$env:PYTHONIOENCODING = "utf-8"

# 프로젝트 루트로 이동 (이 .ps1 은 scripts\ 에 있음)
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot

try {
    # ─── 인자 분기 ──────────────────────────────────────────────
    if ($args.Count -gt 0 -and $args[0] -ieq "test") {
        # ── 테스트 모드 ────────────────────────────────────────
        Write-Host "[run:test] running pytest against zerotrust_test DB ..."
        Write-Host "[run:test] (운영 DB zerotrust 는 영향 없음 - conftest.py 가 격리 보장)"

        # 첫 번째 인자(test) 제외하고 나머지를 pytest 에 그대로 전달
        $pytestArgs = $args | Select-Object -Skip 1
        $cmd = @("-m", "pytest", "tests/") + $pytestArgs
        & python @cmd
        exit $LASTEXITCODE
    }

    # ── 운영 모드 ──────────────────────────────────────────────

    if (-not (Test-Path ".env")) {
        Write-Host "[run] .env not found. Copy .env.example to .env first:"
        Write-Host "      copy .env.example .env"
        exit 2
    }

    Write-Host "[run] loading .env ..."
    Get-Content ".env" | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        $eqIdx = $line.IndexOf("=")
        if ($eqIdx -lt 1) { return }
        $key = $line.Substring(0, $eqIdx).Trim()
        $val = $line.Substring($eqIdx + 1).Trim()
        # PowerShell 변수가 아닌 프로세스 환경변수로 설정
        Set-Item -Path "env:$key" -Value $val
    }

    # 환경변수 검증
    if (-not $env:SECRET_KEY) {
        Write-Host "[run] ERROR: SECRET_KEY is empty in .env"
        exit 4
    }
    if (-not ($env:DATABASE_URL -like "postgresql:*")) {
        Write-Host "[run] ERROR: DATABASE_URL must start with postgresql://"
        Write-Host "      current value: $env:DATABASE_URL"
        exit 3
    }
    Write-Host "[run] DATABASE_URL=$env:DATABASE_URL"

    # 1) 포트 8000 점유 프로세스 종료
    Write-Host "[run] freeing port 8000 if held ..."
    $occupants = netstat -ano | Select-String ":8000\s.*LISTENING"
    foreach ($line in $occupants) {
        $tokens = $line.ToString().Trim() -split "\s+"
        $pidToKill = $tokens[-1]
        if ($pidToKill -match "^\d+$") {
            Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
        }
    }

    # 2) 마이그레이션 적용
    Write-Host "[run] applying migrations ..."
    & python scripts\run_migrations.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run] migration failed. aborting."
        exit 1
    }

    # 3) 사용 흔적 청소
    Write-Host "[run] wiping previous traces ..."
    & python scripts\wipe_traces.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run] wipe failed. aborting."
        exit 1
    }

    # 4) 시드 재삽입
    Write-Host "[run] re-seeding fresh data ..."
    & python init_data.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run] seed failed. aborting."
        exit 1
    }

    # 5) 서버 기동
    Write-Host "[run] starting server ... (Ctrl+C to stop)"
    & python server.py
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
