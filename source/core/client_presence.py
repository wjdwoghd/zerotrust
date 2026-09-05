from __future__ import annotations

import threading
import time


# Browser-window liveness is process-local on purpose. It is only a demo UX
# guard so a closed app window does not block the next login as already active.
_LOCK = threading.Lock()
_SEEN: dict[int, float] = {}
STALE_SECONDS = 15.0


def mark_session_seen(session_id: int) -> None:
    """현재 프로세스에서 브라우저 세션의 마지막 heartbeat 시각을 기록한다."""
    with _LOCK:
        _SEEN[int(session_id)] = time.monotonic()


def forget_session(session_id: int | None) -> None:
    """종료된 세션의 프로세스 로컬 heartbeat 기록을 제거한다."""
    if not session_id:
        return
    with _LOCK:
        _SEEN.pop(int(session_id), None)


def has_presence_record(session_id: int) -> bool:
    """세션의 heartbeat를 현재 프로세스가 받은 적이 있는지 반환한다."""
    with _LOCK:
        return int(session_id) in _SEEN


def is_session_stale(session_id: int) -> bool:
    """마지막 heartbeat 이후 허용 시간을 초과했는지 반환한다."""
    with _LOCK:
        seen = _SEEN.get(int(session_id))
    return seen is not None and (time.monotonic() - seen) > STALE_SECONDS
