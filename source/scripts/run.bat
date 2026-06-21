@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
rem =====================================================================
rem ZeroTrust 통합 실행 스크립트 (Windows cmd)
rem
rem 사용법 (zerotrust_prod 폴더에서):
rem     scripts\run.bat              -> 운영 서버 기동 (최초 + 재실행 통합)
rem     scripts\run.bat test         -> 테스트 스위트 실행 (zerotrust_test DB)
rem
rem 운영 모드 흐름 (인자 없음):
rem   1) .env 로드 + 환경변수 검증 (SECRET_KEY, postgresql:// URL)
rem   2) 포트 8000 점유 프로세스 종료 (이전 서버 잔재 정리)
rem   3) 마이그레이션 적용 (멱등 — 첫 실행이면 스키마 생성, 재실행이면 skip)
rem   4) 사용 흔적 청소 (빈 DB 면 no-op, 데이터 있으면 모든 운영 테이블 TRUNCATE)
rem   5) 시드 재삽입 (사용자 7명 + 자료 15건 + 토큰 기기 + 런처 .pyw 갱신)
rem   6) 서버 기동
rem
rem 결과: 매 실행 = 깨끗한 시드 + 떠있는 서버. 발표/시연 환경에 최적화.
rem 주의: 시연 도중 다시 실행하면 진행 데이터가 모두 사라진다.
rem
rem 테스트 모드 흐름 (인자: test):
rem   1) 운영 DB(zerotrust)는 절대 건드리지 않음 — conftest.py 가 보장
rem   2) 별도 zerotrust_test DB 에 대해 pytest 실행
rem   3) 매 테스트마다 wipe + reseed 로 격리됨
rem
rem 사전 준비 (한 번만):
rem   - .env 파일 (cp .env.example .env, SECRET_KEY 32자 이상 채우기)
rem   - PostgreSQL 운영 DB:  CREATE DATABASE zerotrust OWNER ztuser;
rem   - PostgreSQL 테스트 DB: CREATE DATABASE zerotrust_test OWNER ztuser;
rem =====================================================================
setlocal EnableDelayedExpansion

rem --- 프로젝트 루트로 이동 (이 .bat 는 scripts\ 에 있음) ---
pushd "%~dp0.."

rem --- 인자 분기: test 면 테스트 실행으로 점프 ---
if /i "%1"=="test" goto :TEST_MODE
goto :PROD_MODE


rem ─────────────────────────────────────────────────────────────────
rem 운영 모드
rem ─────────────────────────────────────────────────────────────────
:PROD_MODE

if not exist ".env" (
    echo [run] .env not found. Copy .env.example to .env first:
    echo       copy .env.example .env
    popd
    exit /b 2
)

echo [run] loading .env ...
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    set "_line=%%A"
    if not "!_line!"=="" (
        if not "!_line:~0,1!"=="#" (
            if not "%%B"=="" (
                set "%%A=%%B"
            ) else (
                set "%%A="
            )
        )
    )
)

rem --- 환경변수 검증 ---
if "%SECRET_KEY%"=="" (
    echo [run] ERROR: SECRET_KEY is empty in .env
    popd
    exit /b 4
)

echo %DATABASE_URL% | findstr /b /i "postgresql:" >nul
if !errorlevel! neq 0 (
    echo [run] ERROR: DATABASE_URL must start with postgresql://
    echo       current value: %DATABASE_URL%
    popd
    exit /b 3
)

echo [run] DATABASE_URL=%DATABASE_URL%

rem --- 1) 포트 8000 점유 프로세스 종료 ---
echo [run] freeing port 8000 if held ...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000.*LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>nul
)

rem --- 2) 마이그레이션 적용 (멱등) ---
echo [run] applying migrations ...
python scripts\run_migrations.py
if errorlevel 1 (
    echo [run] migration failed. aborting.
    popd
    exit /b 1
)

rem --- 3) 사용 흔적 청소 (빈 DB 에서는 no-op) ---
echo [run] wiping previous traces ...
python scripts\wipe_traces.py
if errorlevel 1 (
    echo [run] wipe failed. aborting.
    popd
    exit /b 1
)

rem --- 4) 시드 재삽입 (사용자/자원/기기 + 런처 .pyw 자동 갱신) ---
echo [run] re-seeding fresh data ...
python init_data.py
if errorlevel 1 (
    echo [run] seed failed. aborting.
    popd
    exit /b 1
)

rem --- 5) 서버 기동 ---
echo [run] starting server ... (Ctrl+C to stop)
python server.py
set "_rc=%errorlevel%"

popd
endlocal & exit /b %_rc%


rem ─────────────────────────────────────────────────────────────────
rem 테스트 모드
rem ─────────────────────────────────────────────────────────────────
:TEST_MODE

echo [run:test] running pytest against zerotrust_test DB ...
echo [run:test] (운영 DB zerotrust 는 영향 없음 - conftest.py 가 격리 보장)

rem 두 번째 인자 이후를 pytest 에 그대로 전달 (예: scripts\run.bat test -k smoke)
shift
set "_PYTEST_ARGS="
:GATHER_ARGS
if "%~1"=="" goto :RUN_PYTEST
set "_PYTEST_ARGS=!_PYTEST_ARGS! %1"
shift
goto :GATHER_ARGS

:RUN_PYTEST
python -m pytest tests/ %_PYTEST_ARGS%
set "_rc=%errorlevel%"

popd
endlocal & exit /b %_rc%
