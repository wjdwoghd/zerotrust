from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

import zt_demo_ctl as ctl


ROOT = Path(__file__).resolve().parent


class ControlApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ZeroTrust 제어")
        self.geometry("360x230")
        self.resizable(False, False)
        self.configure(bg="#f8fafc")

        icon = ROOT / "icons" / "control_panel.ico"
        if icon.exists():
            try:
                self.iconbitmap(str(icon))
            except tk.TclError:
                pass

        self.status = tk.StringVar(value=self._status_text())

        tk.Label(
            self,
            text="ZeroTrust 시스템 제어",
            font=("Malgun Gothic", 15, "bold"),
            bg="#f8fafc",
            fg="#1e3a8a",
        ).pack(pady=(18, 4))

        tk.Label(
            self,
            textvariable=self.status,
            font=("Malgun Gothic", 9),
            bg="#f8fafc",
            fg="#475569",
        ).pack(pady=(0, 16))

        frame = tk.Frame(self, bg="#f8fafc")
        frame.pack(fill="x", padx=28)

        self.reset_btn = tk.Button(
            frame,
            text="서버 초기화",
            command=self.reset_system,
            height=2,
            bg="#fef3c7",
            activebackground="#fde68a",
            fg="#78350f",
            font=("Malgun Gothic", 10, "bold"),
            relief="flat",
        )
        self.reset_btn.pack(fill="x", pady=4)

        self.stop_btn = tk.Button(
            frame,
            text="서버 종료",
            command=self.stop_system,
            height=2,
            bg="#e2e8f0",
            activebackground="#cbd5e1",
            fg="#0f172a",
            font=("Malgun Gothic", 10, "bold"),
            relief="flat",
        )
        self.stop_btn.pack(fill="x", pady=4)

        tk.Button(
            self,
            text="상태 새로고침",
            command=self.refresh_status,
            bg="#f8fafc",
            fg="#334155",
            activebackground="#e2e8f0",
            relief="flat",
            font=("Malgun Gothic", 9),
        ).pack(pady=(12, 0))

    def _status_text(self) -> str:
        pg = "정상" if ctl.pg_ready() else "꺼짐"
        server = "정상" if ctl.health_ok() else "꺼짐"
        return f"PostgreSQL: {pg}  |  서버: {server}"

    def refresh_status(self) -> None:
        self.status.set(self._status_text())

    def _set_busy(self, busy: bool, text: str | None = None) -> None:
        state = "disabled" if busy else "normal"
        self.reset_btn.configure(state=state)
        self.stop_btn.configure(state=state)
        if text:
            self.status.set(text)

    def _run(self, label: str, func) -> None:
        self._set_busy(True, f"{label} 처리 중...")

        def work() -> None:
            try:
                func()
            except BaseException as exc:
                self.after(0, lambda: self._fail(label, exc))
                return
            self.after(0, lambda: self._done(label))

        threading.Thread(target=work, daemon=True).start()

    def _done(self, label: str) -> None:
        self._set_busy(False)
        self.refresh_status()
        particle = "가" if label in ("서버 초기화", "서버 종료") else "이"
        messagebox.showinfo("ZeroTrust 제어", f"{label}{particle} 완료되었습니다.")

    def _fail(self, label: str, exc: BaseException) -> None:
        self._set_busy(False)
        self.refresh_status()
        messagebox.showerror("ZeroTrust 제어", f"{label} 실패\n\n{exc}")

    def reset_system(self) -> None:
        ok = messagebox.askyesno(
            "서버 초기화",
            "모든 사용 흔적을 지우고 시드 데이터만 남긴 뒤 로그인 화면을 다시 열까요?",
        )
        if ok:
            self._run("서버 초기화", ctl.reset_and_start)

    def stop_system(self) -> None:
        ok = messagebox.askyesno(
            "서버 종료",
            "로그인 세션을 모두 종료하고 ZeroTrust 창을 닫은 뒤 서버와 PostgreSQL을 종료할까요?",
        )
        if ok:
            self._run("서버 종료", ctl.stop_all)


if __name__ == "__main__":
    ControlApp().mainloop()
