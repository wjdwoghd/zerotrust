"""네 승인 유형의 공통 AI 결과 표시를 실제 브라우저에서 검증한다."""

import json
import os
import subprocess
from pathlib import Path

import pytest


STATIC_PAGE = Path(__file__).resolve().parents[2] / "static" / "index.html"


def test_ai_review_results_are_readable_and_escape_model_text(tmp_path):
    """한국어·결측·근거·시간 표시와 React 텍스트 이스케이프를 확인한다."""
    page_source = STATIC_PAGE.read_text(encoding="utf-8")
    start = page_source.index("const REVIEW_LABELS =")
    end = page_source.index("const AUDIT_EVENT_LABELS =", start)
    components = page_source[start:end]
    full_app = page_source.split('<script type="text/babel">', 1)[1].split("</script>", 1)[0]
    # 두 실제 호출 지점(자료 접근/나머지 세 승인)의 공통 표시 연결도 확인한다.
    assert '<AiReviewResult result={current.advice}' in page_source
    assert '<AiReviewResult result={approvalAi[approval.id].result}' in page_source
    assert "JSON.stringify(current.advice" not in page_source
    assert "JSON.stringify(approvalAi[approval.id].result" not in page_source

    script = r"""
        try {
            Babel.transform(FULL_APP, {presets: ['react']});
            const components = Babel.transform(COMPONENTS, {presets: ['react']}).code;
            const run = `
                const DETAIL_KEY_LABELS = {};
                ${components}
                const source = {table: 'approvals', id: 17};
                const fact = (value, reason = null) => ({value, source,
                    observed_at: '2026-10-22T01:14:40+00:00', unknown_reason: reason});
                const unsafe = '<img src=x onerror="window.injected=true">';
                const results = ['resource', 'login', 'assignment', 'break_glass'].map(type => ({
                    model_status: 'completed', generated_at: '2026-10-22T01:14:43+00:00',
                    [type === 'resource' ? 'policy_facts' : 'server_facts']: {
                        review_type: type, fields: {status: fact('pending'), want_download: fact(false),
                            use_count: fact(0), otp_state: fact(null, 'login_gate_otp_not_recorded'),
                            last_observed_final_level: fact(4), scope: fact('broad'),
                            reviewer_role: fact('deputy_admin')}},
                    ai_review: {review_opinion: 'check_further', missing_items: [{text: unsafe,
                        evidence_ids: [source], no_evidence_reason: null}], contradictions: [],
                        items: [{text: '추가 확인 필요', evidence_ids: [], no_evidence_reason: '원문 미제공'}]},
                    uncertainties: {server: [{field: 'policy_facts.current_evaluation',
                        reason: 'read_only_no_re_evaluation'}], ai: []}, evidence_ids: [source]
                }));
                const original = JSON.stringify(results);
                ReactDOM.flushSync(() => ReactDOM.createRoot(document.getElementById('app')).render(
                    React.createElement('div', null, ...results.map((result, key) =>
                        React.createElement(AiReviewResult, {result, key})))));
                const text = document.getElementById('app').textContent;
                for (const label of ['추가 검토 필요', '다운로드 요청', '아니오', '미확인',
                    'OTP 인증 상태는 기록되지 않습니다', 'L4', '긴급 접근 사용 횟수',
                    '자료 승인 요청 #17', '2026. 10. 22.', '10:14:43', '한국 시간',
                    '최소 민감도 등급 이상 자료', '부관리자',
                    '접근 평가를 다시 실행하지 않았습니다', '제시된 항목 없음', unsafe]) {
                    if (!text.includes(label)) throw Error('Missing label: ' + label);
                }
                if (document.querySelectorAll('[data-ai-review-result]').length !== 4)
                    throw Error('Missing review types');
                if (document.querySelector('img') || window.injected) throw Error('Unsafe model HTML');
                if (text.includes('check_further') || text.includes('unknown_reason'))
                    throw Error('Raw machine fields');
                if (JSON.stringify(results) !== original) throw Error('Mutated API data');
                document.getElementById('result').textContent = 'AI_DISPLAY_PASS';
            `;
            new Function(run)();
        } catch (error) { document.getElementById('result').textContent = 'FAIL: ' + error.message; }
    """.replace("COMPONENTS", json.dumps(components).replace("<", "\\u003c")).replace(
        "FULL_APP", json.dumps(full_app).replace("<", "\\u003c"))
    _run_browser_script(tmp_path, script)


def test_bg_review_panel_survives_polling_and_completes_ai_request(tmp_path):
    """실제 관리자 화면에서 조회·수동 토글·폴링·AI 성공/실패 표시를 확인한다."""
    source = STATIC_PAGE.read_text(encoding="utf-8")
    app = source.split('<script type="text/babel">', 1)[1].split('// ============ RENDER APP', 1)[0]
    harness = r"""
        const tick = () => new Promise(resolve => setTimeout(resolve, 0));
        const check = (condition, message) => {if (!condition) throw Error(message);};
        const click = text => {
            const button = [...document.querySelectorAll('button')].find(b => b.textContent.includes(text));
            check(button && !button.disabled, 'Missing/enabled button: ' + text);
            button.click();
        };
        let poll, finishAi, aiCalls = 0, failAi = false;
        window.setInterval = callback => {poll = callback; return 123;};
        const facts = {review_type: 'break_glass', target_id: 1, fields: {
            status: {value: 'released', unknown_reason: null, source: null, observed_at: null}}};
        const advice = {server_facts: facts, ai_review: {review_opinion: 'check_further', items: []},
            uncertainties: {server: [], ai: []}, evidence_ids: [], model_status: 'completed',
            generated_at: '2026-10-22T01:25:42+00:00'};
        window.fetch = async (url, options = {}) => {
            const response = (data, ok = true) => ({ok, status: ok ? 200 : 502, json: async () => data});
            if (url.includes('/reviews/break_glass/1/facts')) return response(facts);
            if (url.includes('/reviews/break_glass/1/ai-review')) {
                aiCalls++;
                if (failAi) return response({code: 'evidence_ref_invalid'}, false);
                return new Promise(resolve => {finishAi = () => resolve(response(advice));});
            }
            if (url.includes('/break-glass/pending')) return response({activations: [{id: 1,
                status: 'released', scope: 'broad', min_grade: 4, justification: '테스트 사유'}]});
            return response({approvals: [], activations: [], requests: []});
        };
        const root = ReactDOM.createRoot(document.getElementById('app'));
        const render = () => ReactDOM.flushSync(() => root.render(
            React.createElement(AuthContext.Provider, {value: {token: 'fixture-token', user: {id: 3, role: 'admin'}}},
                React.createElement(AdminPage))));
        render(); await tick(); await tick();
        click('Break-Glass'); await tick(); await tick();
        click('서버 사실 조회'); await tick(); await tick();
        const details = document.querySelector('[data-review-disclosure]');
        const toggle = details?.querySelector('button');
        const isOpen = element => element?.querySelector('button')?.getAttribute('aria-expanded') === 'true';
        check(details && isOpen(details), 'Facts should open after explicit lookup');
        check(aiCalls === 0, 'Facts lookup must not invoke AI');
        toggle.click(); await tick();
        check(!isOpen(details) && details.querySelector('[hidden]'), 'Click did not close facts');
        render(); await tick();
        check(document.querySelector('[data-review-disclosure]') === details && !isOpen(details), 'Manual close lost on parent update');
        toggle.click(); await tick();
        await poll(); await tick();
        check(document.querySelector('[data-review-disclosure]') === details && isOpen(details), 'Facts collapsed after queue polling');
        click('AI 참고 의견 요청'); await tick();
        check(document.querySelector('[role="status"]')?.textContent.includes('AI'), 'No AI progress');
        await poll(); await tick();
        check(document.querySelector('[data-review-disclosure]') === details && isOpen(details), 'Facts collapsed during AI');
        finishAi(); await tick(); await tick();
        check(document.querySelector('[data-ai-review-result]')?.textContent.includes('추가 검토 필요'), 'AI result missing');
        const result = document.querySelector('[data-ai-review-result]');
        const resultFacts = result.querySelector('[data-review-disclosure]');
        resultFacts.querySelector('button').click(); await tick();
        render(); await poll(); await tick();
        check(document.querySelector('[data-ai-review-result]') === result && isOpen(resultFacts),
            'AI result remounted during polling');
        const evidence = result.querySelectorAll('[data-review-disclosure]')[1];
        evidence.querySelector('button').click(); await tick();
        await poll(); await tick();
        check(isOpen(evidence), 'Evidence collapsed after queue polling');
        failAi = true;
        click('AI 참고 의견 요청'); await tick(); await tick();
        check(document.querySelector('[role="alert"]')?.textContent.includes('근거를 서버에서 검증하지 못했습니다'),
            'Evidence failure not explained');
        check([...document.querySelectorAll('button')].some(b => b.textContent.includes('정당 (justified)') && !b.disabled),
            'Manual review unavailable after AI error');
        document.getElementById('result').textContent = 'AI_DISPLAY_PASS';
    """
    program = app + "\n(async () => {" + harness + "\n})().catch(error => {" + (
        "document.getElementById('result').textContent = 'FAIL: ' + error.message;});")
    script = "try {new Function(Babel.transform(" + json.dumps(program).replace("<", "\\u003c") + (
        ", {presets: ['react']}).code)();} catch(error) {"
        "document.getElementById('result').textContent = 'FAIL: ' + error.message;}")
    _run_browser_script(tmp_path, script)


def _run_browser_script(tmp_path, script):
    browser = next((p for p in (
        Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
        Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    ) if p.is_file()), None)
    assets = Path(os.environ.get("ZT_UI_TEST_ASSETS", str(tmp_path / "missing-assets")))
    names = ("react.js", "react-dom.js", "babel.js")
    if browser is None or not all((assets / name).is_file() for name in names):
        pytest.skip("Chromium 및 ZT_UI_TEST_ASSETS의 React 18·ReactDOM·Babel 필요")

    scripts = "".join(f'<script src="{(assets / name).resolve().as_uri()}"></script>' for name in names)
    page = tmp_path / "ai-review.html"
    page.write_text('<!doctype html><meta charset="utf-8"><div id="app"></div>'
                    '<pre id="result">AI_DISPLAY_PENDING</pre>'
                    '<script>window.onerror = function(message, url, line, column) {'
                    'document.getElementById("result").textContent = "FAIL: " + message + " line " + line + " col " + column;};</script>' + scripts
                    + "<script>" + script.replace("</script>", "<\\/script>") + "</script>",
                    encoding="utf-8")
    result = subprocess.run(
        [str(browser), "--headless=new", "--disable-gpu", "--no-first-run", "--no-sandbox",
         "--allow-file-access-from-files", f"--user-data-dir={tmp_path / 'chrome-profile'}",
         "--virtual-time-budget=5000", "--dump-dom", page.as_uri()], capture_output=True, encoding="utf-8", errors="replace",
        timeout=45, check=False,
    )
    assert result.returncode == 0, result.stderr[-500:]
    status = result.stdout.split('<pre id="result">', 1)[-1].split('</pre>', 1)[0]
    assert status == "AI_DISPLAY_PASS", status
