"""
virtual_device.py — 제로트러스트 "토큰 기기" 실행 프로그램 (Tkinter)

배경:
    업무에 쓰는 "등록 기기" 와 OTP 를 수신하는 "토큰 기기" 를 물리적으로
    분리하기 위해, 각 계정의 토큰 기기는 이 스크립트를 독립 실행하는
    Tkinter 앱으로 구현한다.

    로그인 모달에서 "OTP 전송" 을 누르면 서버 `otp_requests` 큐에 이벤트가
    쌓이고, 이 앱은 3초 주기로 `/api/device/otp-requests` 를 폴링해
    (a) 큐에 쌓인 요청 목록을 수집/소비하고 (b) 현재 TOTP 를 화면에 표시한다.

    사용자는 이 창을 별도 기기/별도 세션 취급하고, 표시된 6자리 코드를
    로그인 창에 수동으로 입력해 MFA 를 통과한다.

인증:
    - Bearer <api_key> 로 서버에 인증. api_key 는 init_data.py 가
      사용자별로 발급하며 init_data 실행 시 콘솔에 표시된다.

실행 예:
    python apps/virtual_device.py \
        --account alice --device-id token-001 \
        --api-key <HEX> \
        --base-url http://localhost:8000

설계 전제:
    - 단일 스크린, 항상 떠 있는 것을 가정.
    - 네트워크 실패 시 화면 상단에 "오프라인" 배지를 표시하되 TOTP 계산은
      서버 응답 기준이므로 통신 없으면 최근 값을 회색으로 굳혀 보여준다.
    - 이 앱 자체는 mfa_secret 을 보관하지 않는다. TOTP 는 서버에서 받는다.
      (L2-4 "토큰 기기에 비밀을 평문 저장하지 않기" 원칙)

주의:
    이 파일은 서버 프로세스와 같은 파이썬에서 돌릴 수도 있지만, 실제
    시나리오에서는 별도 PC/별도 프로세스에서 실행하는 것이 맞다.
"""
from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


POLL_INTERVAL_SEC = 3.0


# ─────────────────────────────────────────────────────────────────────
# 백그라운드 폴러
# ─────────────────────────────────────────────────────────────────────
class Poller(threading.Thread):
    """
    별도 스레드에서 서버를 주기적으로 GET 하고 결과를 큐에 넣는다.
    GUI 스레드는 `after()` 를 통해 이 큐를 비동기적으로 소비한다.
    """

    # 좀비 토큰 기기 자동 정리 (option A):
    # run.bat 재실행으로 user_devices 가 wipe + 재시드되면 이전 실행에서
    # 남은 토큰 기기 앱은 옛 api_key 로 영구 401 폴링을 한다. 일정 횟수
    # 연속 401 을 받으면 폴링을 멈추고 사용자에게 안내 후 자동 종료한다.
    STOP_AFTER_401_HITS = 5

    def __init__(self, base_url: str, device_id: str, api_key: str,
                 out_queue: "queue.Queue[dict]"):
        super().__init__(daemon=True)
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id
        self.api_key = api_key
        self.out_queue = out_queue
        self._stop = threading.Event()
        self._consecutive_401 = 0

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        url = (
            f"{self.base_url}/api/device/otp-requests?"
            + urlencode({"device_id": self.device_id})
        )
        while not self._stop.is_set():
            try:
                req = Request(
                    url,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                with urlopen(req, timeout=5) as resp:
                    raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                data["_ok"] = True
                self._consecutive_401 = 0  # 정상 응답 → 카운터 reset
                self.out_queue.put(data)
            except HTTPError as e:
                try:
                    body = e.read().decode("utf-8")
                    err_data = json.loads(body)
                except Exception:
                    err_data = {}
                if e.code == 401:
                    self._consecutive_401 += 1
                else:
                    # 401 외 4xx/5xx 는 일시적 오류로 보고 카운터 reset
                    self._consecutive_401 = 0
                self.out_queue.put({
                    "_ok": False,
                    "_status": e.code,
                    "error": err_data.get("error") or str(e),
                    "code": err_data.get("code"),
                    "_consecutive_401": self._consecutive_401,
                })
                if self._consecutive_401 >= self.STOP_AFTER_401_HITS:
                    # 좀비 토큰 기기 — 폴링 중단 + GUI 종료 시그널
                    self.out_queue.put({
                        "_ok": False,
                        "_terminate": True,
                        "reason": "api_key_invalid_repeated_401",
                        "hits": self._consecutive_401,
                    })
                    self._stop.set()
                    return
            except URLError as e:
                # 네트워크 끊김은 401 누적과 별개 — 카운터 유지(reset 안 함)
                self.out_queue.put({
                    "_ok": False,
                    "_status": None,
                    "error": f"서버에 연결할 수 없음: {e.reason}",
                    "code": "network",
                })
            except Exception as e:
                self.out_queue.put({
                    "_ok": False,
                    "_status": None,
                    "error": f"{type(e).__name__}: {e}",
                    "code": "unknown",
                })

            # 인터럽트-가능 슬립
            self._stop.wait(POLL_INTERVAL_SEC)


# ─────────────────────────────────────────────────────────────────────
# 메인 앱
# ─────────────────────────────────────────────────────────────────────
class TokenDeviceApp:
    MAX_LOG_LINES = 30

    def __init__(self, root: tk.Tk, args: argparse.Namespace):
        self.root = root
        self.args = args
        self.queue: "queue.Queue[dict]" = queue.Queue()

        # 최근 유효 응답 스냅샷
        self._last_totp: str | None = None
        self._last_expires_in: int | None = None
        self._last_sync_at: float | None = None
        self._offline: bool = False

        self._build_ui()

        self.poller = Poller(
            base_url=args.base_url,
            device_id=args.device_id,
            api_key=args.api_key,
            out_queue=self.queue,
        )
        self.poller.start()

        # GUI 루프들
        self.root.after(100, self._drain_queue)
        self.root.after(200, self._tick_countdown)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI 구성 ----------
    def _build_ui(self) -> None:
        self.root.title(f"토큰 기기 — {self.args.account} / {self.args.device_id}")
        self.root.geometry("440x420")
        self.root.minsize(380, 380)

        # 상단 헤더
        header = ttk.Frame(self.root, padding=(12, 10))
        header.pack(fill=tk.X)

        ttk.Label(
            header,
            text="제로트러스트 토큰 기기",
            font=("Helvetica", 11, "bold"),
        ).pack(anchor=tk.W)

        ttk.Label(
            header,
            text=f"계정: {self.args.account}    기기: {self.args.device_id}",
            foreground="#555",
        ).pack(anchor=tk.W)

        self.status_var = tk.StringVar(value="서버 대기 중…")
        self.status_label = ttk.Label(
            header,
            textvariable=self.status_var,
            foreground="#888",
        )
        self.status_label.pack(anchor=tk.W, pady=(4, 0))

        ttk.Separator(self.root).pack(fill=tk.X)

        # OTP 표시
        body = ttk.Frame(self.root, padding=(12, 14))
        body.pack(fill=tk.X)

        ttk.Label(body, text="현재 OTP", foreground="#666").pack(anchor=tk.W)

        self.otp_var = tk.StringVar(value="------")
        self.otp_label = tk.Label(
            body,
            textvariable=self.otp_var,
            font=("Menlo", 36, "bold"),
            fg="#222",
        )
        self.otp_label.pack(anchor=tk.W, pady=(2, 6))

        # 진행 바 (30초 주기)
        self.progress = ttk.Progressbar(
            body, orient="horizontal", mode="determinate",
            maximum=30, length=380,
        )
        self.progress.pack(anchor=tk.W, fill=tk.X)

        self.countdown_var = tk.StringVar(value="-- 초 남음")
        ttk.Label(
            body,
            textvariable=self.countdown_var,
            foreground="#888",
        ).pack(anchor=tk.W, pady=(2, 0))

        ttk.Separator(self.root).pack(fill=tk.X)

        # 이벤트 로그
        log_frame = ttk.Frame(self.root, padding=(12, 8))
        log_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            log_frame,
            text="OTP 전송 요청 로그",
            foreground="#666",
        ).pack(anchor=tk.W)

        self.log_text = tk.Text(
            log_frame, height=8, wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Menlo", 9),
            background="#fafafa",
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    # ---------- 큐 소비 ----------
    def _drain_queue(self) -> None:
        try:
            while True:
                item = self.queue.get_nowait()
                self._apply_response(item)
        except queue.Empty:
            pass
        finally:
            self.root.after(250, self._drain_queue)

    def _apply_response(self, data: dict) -> None:
        # 좀비 종료 시그널 — 옛 api_key 로 폴링하던 토큰 기기 앱이 N회 연속 401
        # 을 받으면 Poller 가 이 시그널을 보낸다. UI 에 안내 + 2초 후 자동 종료.
        if data.get("_terminate"):
            hits = data.get("hits", 0)
            self._offline = True
            self.status_var.set(
                f"⚠ api_key 가 무효합니다 ({hits}회 연속 401). "
                f"서버를 재시작했다면 새 launcher 로 다시 실행하세요. "
                f"2초 후 자동 종료됩니다."
            )
            self.status_label.configure(foreground="#b00")
            self.otp_label.configure(fg="#aaa")
            self.root.after(2000, self.root.destroy)
            return

        if not data.get("_ok"):
            self._offline = True
            err = data.get("error") or "알 수 없는 오류"
            self.status_var.set(f"⚠ {err}")
            self.status_label.configure(foreground="#b00")
            self.otp_label.configure(fg="#aaa")
            return

        # 정상 응답
        self._offline = False
        self._last_totp = data.get("current_totp")
        self._last_expires_in = data.get("expires_in")
        self._last_sync_at = time.time()

        dev_name = (data.get("device") or {}).get("device_name") \
            or self.args.device_id
        self.status_var.set(f"✓ 연결됨 · {dev_name}")
        self.status_label.configure(foreground="#0a7d2a")
        self.otp_label.configure(fg="#222")
        if self._last_totp:
            self.otp_var.set(self._last_totp)

        # pending 요청 로그 — 서버가 consumed 처리한 항목만 응답에 실림
        pending = data.get("pending_requests") or []
        for p in pending:
            self._append_log_line(
                f"• {self._short_time()} 로그인 시도 "
                f"(업무기기={p.get('work_device_id') or '?'}, "
                f"ip={p.get('ip_address') or '?'}, "
                f"위치={p.get('location') or '?'}) → 이 화면의 코드를 입력하세요"
            )
            # 알림음 (OS 기본)
            try:
                self.root.bell()
            except Exception:
                pass

    # ---------- 카운트다운 ----------
    def _tick_countdown(self) -> None:
        try:
            if self._last_sync_at is None or self._last_expires_in is None:
                self.countdown_var.set("-- 초 남음")
                self.progress["value"] = 0
            else:
                elapsed = time.time() - self._last_sync_at
                remain = int(self._last_expires_in - elapsed)
                if remain < 0:
                    # 서버 재동기화 전까지 남은 시간을 0 에 고정
                    remain = 0
                    # TOTP 글자색을 약간 흐리게
                    self.otp_label.configure(fg="#888")
                else:
                    if not self._offline:
                        self.otp_label.configure(fg="#222")
                self.countdown_var.set(f"{remain} 초 남음 (30초 주기)")
                self.progress["value"] = max(0, min(30, remain))
        finally:
            self.root.after(250, self._tick_countdown)

    # ---------- 로그 ----------
    def _append_log_line(self, line: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, line + "\n")

        # 최근 MAX_LOG_LINES 만 남기기
        content = self.log_text.get("1.0", tk.END).splitlines()
        if len(content) > self.MAX_LOG_LINES:
            trimmed = "\n".join(content[-self.MAX_LOG_LINES:]) + "\n"
            self.log_text.delete("1.0", tk.END)
            self.log_text.insert(tk.END, trimmed)

        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    @staticmethod
    def _short_time() -> str:
        return time.strftime("%H:%M:%S", time.localtime())

    # ---------- 종료 ----------
    def _on_close(self) -> None:
        try:
            self.poller.stop()
        except Exception:
            pass
        self.root.destroy()


# ─────────────────────────────────────────────────────────────────────
# 엔트리 포인트
# ─────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="virtual_device",
        description="제로트러스트 토큰 기기 실행 프로그램 (Tkinter)",
    )
    p.add_argument("--account", required=True,
                   help="표시용 계정 이름 (예: alice)")
    p.add_argument("--device-id", required=True,
                   help="user_devices.device_id (예: token-001)")
    p.add_argument("--api-key", required=True,
                   help="user_devices.api_key (init_data.py 가 출력)")
    p.add_argument("--base-url", default="http://localhost:8000",
                   help="서버 베이스 URL (기본 http://localhost:8000)")
    return p.parse_args()


def launch(account: str, device_id: str, api_key: str,
           base_url: str = "http://127.0.0.1:8000") -> int:
    """
    프로그래매틱 진입점. argparse 를 거치지 않고 바로 GUI 기동한다.
    per-계정 .pyw 런처가 이 함수를 호출한다.
    """
    args = argparse.Namespace(
        account=account,
        device_id=device_id,
        api_key=api_key,
        base_url=base_url,
    )
    root = tk.Tk()
    try:
        # macOS 에서 ttk 기본 테마가 더 깔끔
        style = ttk.Style()
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    TokenDeviceApp(root, args)
    root.mainloop()
    return 0


def main() -> int:
    args = _parse_args()
    return launch(args.account, args.device_id, args.api_key, args.base_url)


if __name__ == "__main__":
    sys.exit(main())
