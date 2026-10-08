"""브라우저에서 사건 상세 상태 전환 시 본문 보관과 재조회 조건을 검증한다."""

import subprocess
from pathlib import Path

import pytest


STATIC_PAGE = Path(__file__).resolve().parents[2] / "static" / "index.html"
CHROME_CANDIDATES = (
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
)


def test_case_status_downgrade_clears_body_and_upgrade_refreshes(tmp_path):
    """실제 JS 실행으로 권한 하락·상승 시 화면 상태 전환을 확인한다."""
    browser = next((path for path in CHROME_CANDIDATES if path.is_file()), None)
    if browser is None:
        pytest.skip("헤드리스 Chromium 브라우저 없음")

    source = STATIC_PAGE.read_text(encoding="utf-8")
    start = source.index("function applyPublicCaseStatus(")
    end = source.index("function CaseDetailPage(", start)
    helpers = source[start:end]
    script = """
        var allowed = {
            request_id: 'one', status: 'ALLOW',
            actions: {can_view: true},
            resource: {id: 7, title: '사건', content: '민감 본문', case_number: 'SECRET'}
        };
        var reauth = applyPublicCaseStatus(allowed, {
            request_id: 'two', status: 'VERIFY',
            actions: {can_view: false, reauthenticate: true},
            external_message: '재인증 필요', risk_score: 68.5
        });
        if (reauth.resource.content !== undefined || reauth.resource.case_number !== undefined ||
            reauth.status !== 'VERIFY' || reauth.risk_score !== 68.5 || shouldRefreshCaseDetail(reauth) ||
            getCaseUiActions(reauth).canView || !getCaseUiActions(reauth).reauthenticate) {
            throw Error('재인증 전 본문 제거 실패');
        }
        var afterReauth = applyPublicCaseStatus(reauth, {
            request_id: 'three', status: 'ALLOW',
            actions: {can_view: true}, external_message: '허용'
        });
        if (afterReauth.resource.content !== undefined || !shouldRefreshCaseDetail(afterReauth) ||
            getCaseUiActions(afterReauth).canView) {
            throw Error('재인증 후 상세 재조회 실패');
        }
        var loaded = {
            status: 'ALLOW', actions: {can_view: true, can_download: true},
            resource: {id: 7, title: '사건', content: '허용 본문'}
        };
        if (!getCaseUiActions(loaded).canView || !getCaseUiActions(loaded).canDownload) {
            throw Error('재조회 후 열람 버튼 활성화 실패');
        }
        var approval = applyPublicCaseStatus(allowed, {
            request_id: 'four', status: 'VERIFY',
            actions: {can_view: false, request_approval: true}
        });
        var afterApproval = applyPublicCaseStatus(approval, {
            request_id: 'five', status: 'ALLOW', actions: {can_view: true}
        });
        if (approval.resource.content !== undefined || !shouldRefreshCaseDetail(afterApproval) ||
            getCaseUiActions(approval).canView || !getCaseUiActions(approval).requestApproval ||
            getCaseUiActions(afterApproval).canView) {
            throw Error('승인 전후 본문 처리 실패');
        }
        var denied = applyPublicCaseStatus(allowed, {
            request_id: 'six', status: 'DENY', actions: {can_view: false}
        });
        if (denied.resource.content !== undefined || denied.status !== 'DENY' ||
            !getCaseUiActions(denied).blocked || getCaseUiActions(denied).canView) {
            throw Error('거부 후 본문 제거 실패');
        }
        if (shouldRefreshCaseDetail(allowed)) throw Error('허용 본문 불필요한 재조회');
        document.getElementById('result').textContent = 'CASE_STATE_PASS';
    """
    page = tmp_path / "case-state.html"
    page.write_text(
        "<html><body><pre id='result'>CASE_STATE_FAIL</pre><script>\n"
        + helpers + "\n" + script + "\n</script></body></html>",
        encoding="utf-8",
    )
    profile = tmp_path / "chrome-profile"
    result = subprocess.run(
        [str(browser), "--headless=new", "--disable-gpu", "--no-first-run",
         "--no-sandbox", f"--user-data-dir={profile}", "--dump-dom", page.as_uri()],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr[-500:]
    assert ">CASE_STATE_PASS</pre>" in result.stdout, result.stderr[-500:]
