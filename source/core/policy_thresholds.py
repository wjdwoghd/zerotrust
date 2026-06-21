"""
정책 임계값 동적 조회 (외부화 + 캐시)

scoring_engine 과 decision_engine 의 모든 가중치를 DB(`policy_thresholds`) 에서
조회한다. 5분 TTL 캐시로 매 결정마다 DB 왕복을 피한다.

운영자가 임계값 변경 후 즉시 적용하려면 `force_reload()` 호출.

사용:
    from core import policy_thresholds as pt
    night = pt.get('ENV_NIGHT_TIME', default=15)

설계 메모:
  - 캐시 미스 시 reload 시도. DB 연결 실패하면 default 반환 (graceful).
  - 모든 값을 한 번에 SELECT 해 메모리 dict 로 보관 → 호출당 비용 ~상수.
  - decision matrix 스냅샷 테스트가 매트릭스를 lock-down 하므로, 임의로
    이 모듈의 default 를 바꾸는 것이 정책 변경에 미치는 영향이 큼. 가능하면
    DB row 만 갱신하고 default 는 보고서 §7-3 그대로 유지.
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, Optional, Tuple


_CACHE: Dict[str, float] = {}
# multiplier 캐시 — (job_category, threshold_name) → multiplier
_OVERRIDES_CACHE: Dict[Tuple[str, str], float] = {}
_CACHE_LOADED_AT: float = 0.0
_CACHE_TTL_SEC = 300  # 5분


def _reload() -> None:
    """DB 에서 임계값 + override multiplier 모두 로드 + 캐시 갱신.

    실패 시 예외 raise — caller 가 처리. 운영 중엔 graceful fallback
    위해 get() 이 잡는다.
    """
    global _CACHE, _OVERRIDES_CACHE, _CACHE_LOADED_AT
    from database import get_db
    db = get_db()
    try:
        rows = db.execute(
            "SELECT name, value FROM policy_thresholds"
        ).fetchall()
        new_cache = {r["name"]: float(r["value"]) for r in rows}

        # override 테이블이 없을 수도 있다(첫 마이그레이션 환경). graceful.
        try:
            override_rows = db.execute(
                "SELECT job_category, threshold_name, multiplier "
                "FROM policy_overrides"
            ).fetchall()
            new_overrides = {
                (r["job_category"], r["threshold_name"]): float(r["multiplier"])
                for r in override_rows
            }
        except Exception:
            new_overrides = {}
    finally:
        try:
            db.close()
        except Exception:
            pass
    _CACHE = new_cache
    _OVERRIDES_CACHE = new_overrides
    _CACHE_LOADED_AT = time.time()


def _ensure_loaded() -> None:
    expired = (time.time() - _CACHE_LOADED_AT) > _CACHE_TTL_SEC
    if not _CACHE or expired:
        try:
            _reload()
        except Exception:
            # graceful: 캐시가 있으면 stale 사용, 없으면 caller 가 default 처리
            pass


def get(name: str, default: float = 0.0,
        categories: Optional[Iterable[str]] = None) -> float:
    """
    임계값 조회. TTL 만료 시 자동 reload.

    Parameters
    ----------
    categories :
        사용자의 job_scope 등 카테고리 리스트. 매칭되는 multiplier override
        가 있으면 base 값에 곱해서 적용한다. 매칭 여러 개면 가장 작은
        multiplier 채택 (= 가장 관대한 정책 — 사용자에게 유리한 쪽).

    DB 연결 실패 시 default fallback.
    """
    _ensure_loaded()
    base = _CACHE.get(name, default) if _CACHE else default

    if not categories:
        return base

    # multiplier 매칭
    multipliers = [
        _OVERRIDES_CACHE[(c, name)]
        for c in categories
        if (c, name) in _OVERRIDES_CACHE
    ]
    if not multipliers:
        return base
    # 가장 작은 multiplier — 사용자에게 가장 유리한 (페널티 최소화) 정책
    return base * min(multipliers)


def get_multiplier(category: str, name: str) -> Optional[float]:
    """단일 (category, name) 의 multiplier 조회. 없으면 None."""
    _ensure_loaded()
    return _OVERRIDES_CACHE.get((category, name))


def force_reload() -> None:
    """관리자가 임계값 변경 후 즉시 적용 트리거."""
    _reload()


def get_all() -> Dict[str, float]:
    """현재 캐시된 모든 임계값 (디버깅·관리 화면용)."""
    if not _CACHE:
        try:
            _reload()
        except Exception:
            return {}
    return dict(_CACHE)


def clear_cache() -> None:
    """테스트 격리용 — 다음 get() 호출 시 강제 reload."""
    global _CACHE, _OVERRIDES_CACHE, _CACHE_LOADED_AT
    _CACHE = {}
    _OVERRIDES_CACHE = {}
    _CACHE_LOADED_AT = 0.0
