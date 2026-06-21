"""
최소 런타임 메트릭 (L5-5)

Prometheus 미도입. 인프로세스 카운터만 유지 → /api/metrics 에서 JSON 으로 노출.
"""
from __future__ import annotations

import threading
from collections import Counter, defaultdict
from typing import Dict, Any


_lock = threading.Lock()
_counters: Dict[str, int] = Counter()
_labeled: Dict[str, Counter] = defaultdict(Counter)


def inc(name: str, value: int = 1) -> None:
    with _lock:
        _counters[name] += value


def inc_labeled(name: str, label_value: str, value: int = 1) -> None:
    with _lock:
        _labeled[name][label_value] += value


def snapshot() -> Dict[str, Any]:
    with _lock:
        return {
            "counters": dict(_counters),
            "labeled": {k: dict(v) for k, v in _labeled.items()},
        }


def reset() -> None:
    """테스트 전용."""
    with _lock:
        _counters.clear()
        _labeled.clear()
