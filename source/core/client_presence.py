from __future__ import annotations

import threading
import time


# Browser-window liveness is process-local on purpose. It is only a demo UX
# guard so a closed app window does not block the next login as already active.
_LOCK = threading.Lock()
_SEEN: dict[int, float] = {}
STALE_SECONDS = 15.0


def mark_session_seen(session_id: int) -> None:
    with _LOCK:
        _SEEN[int(session_id)] = time.monotonic()


def forget_session(session_id: int | None) -> None:
    if not session_id:
        return
    with _LOCK:
        _SEEN.pop(int(session_id), None)


def has_presence_record(session_id: int) -> bool:
    with _LOCK:
        return int(session_id) in _SEEN


def is_session_stale(session_id: int) -> bool:
    with _LOCK:
        seen = _SEEN.get(int(session_id))
    return seen is not None and (time.monotonic() - seen) > STALE_SECONDS
