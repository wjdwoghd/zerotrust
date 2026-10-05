"""Execute the policy lab screen's request, error and result helpers in Chromium."""

import subprocess
from pathlib import Path

import pytest


PAGE = Path(__file__).resolve().parents[2] / "static" / "index.html"
BROWSERS = (
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
)


def test_policy_lab_screen_contract(tmp_path):
    """The browser sends fixed fields and keeps AI prose separate from policy output."""
    browser = next((path for path in BROWSERS if path.is_file()), None)
    if browser is None:
        pytest.skip("headless Chromium is unavailable")
    source = PAGE.read_text(encoding="utf-8")
    start = source.index("const POLICY_LAB_VALUES =")
    end = source.index("function PolicyLab(", start)
    helpers = source[start:end]
    script = """
        const payload = buildPolicyLabPayload('boundary', '2', {hour: [0, 5]});
        if (JSON.stringify(payload) !== JSON.stringify({goal:'boundary', count:2,
            allowed_values:{hour:[0,5]}})) throw Error('payload');
        if (policyLabErrorMessage('model_timeout') ===
            policyLabErrorMessage('model_refusal')) throw Error('error states');
        if (policyLabErrorMessage('key_not_configured') ===
            policyLabErrorMessage('model_output_invalid')) throw Error('key/form');
        const sections = policyLabResultSections({synthetic_conditions:{hour:0},
            policy_engine_result:{score_level:2}, ai_explanation:'AI text'});
        if (sections.synthetic.hour !== 0 || sections.policy.score_level !== 2 ||
            sections.explanation !== 'AI text' || sections.policy.ai_explanation)
            throw Error('result separation');
        document.getElementById('result').textContent = 'POLICY_LAB_PASS';
    """
    page = tmp_path / "policy-lab.html"
    page.write_text(
        "<html><body><pre id='result'>FAIL</pre><script>\n" + helpers +
        "\n" + script + "\n</script></body></html>", encoding="utf-8",
    )
    response = subprocess.run(
        [str(browser), "--headless=new", "--disable-gpu", "--no-first-run",
         "--no-sandbox", f"--user-data-dir={tmp_path / 'profile'}",
         "--dump-dom", page.as_uri()],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=30, check=False,
    )
    assert response.returncode == 0, response.stderr[-500:]
    assert ">POLICY_LAB_PASS</pre>" in response.stdout, response.stderr[-500:]
