"""인증 API 핸들러"""
import datetime
import json
import time
from api.base_handler import BaseHandler
from database import get_db, row_to_dict
from security.password_handler import verify_password
from security.jwt_handler import create_token, decode_token
from security.mfa_service import verify_totp, verify_totp_consume, generate_totp
from core.session_guard import check_session, _parse_ts as parse_ts
from core.client_presence import (
    forget_session,
    has_presence_record,
    is_session_stale,
    mark_session_seen,
)
from core import travel_service
from config import (
    SUSPICIOUS_TRUST_THRESHOLD,
    SUSPICIOUS_VIOLATION_THRESHOLD,
    ADMIN_GATED_SESSION_IDLE_SEC,
    ADMIN_GATED_SESSION_ABSOLUTE_SEC,
    ACCOUNT_MAX_FAILED_LOGIN,
)


class DeviceHintHandler(BaseHandler):
    """GET /api/auth/device-hint?username=X

    로그인 화면 자동 채우기용 — username 의 default 업무 기기 device_id 응답.
    인증 토큰 없이 호출 가능.

    응답:
        {"work_device_id": "<device_id>"}  (없으면 null)

    보안 영향:
        username enumeration 위험은 이미 LoginHandler 의 401 응답
        ("아이디 또는 비밀번호가 올바르지 않습니다") 이 같은 수준으로 노출.
        device_id 자체는 식별자(권한 X) 라 노출돼도 큰 영향 없음 —
        로그인 자체는 password + MFA 가 모두 필요.
    """
    def get(self):
        username = (self.get_argument("username", "") or "").strip()
        if not username:
            return self.write_json({"work_device_id": None})

        db = get_db()
        try:
            row = db.execute(
                "SELECT d.device_id FROM user_devices d "
                "JOIN users u ON u.id = d.user_id "
                "WHERE u.username=? "
                "  AND d.device_type='work' "
                "  AND d.is_active "
                "ORDER BY d.id LIMIT 1",
                (username,)
            ).fetchone()
            self.write_json({
                "work_device_id": row["device_id"] if row else None,
            })
        finally:
            db.close()


def _is_suspicious_user(user: dict) -> bool:
    """의심 계정 판정 (trust_score 또는 violation_count 기준).

    둘 중 하나라도 임계값을 넘기면 관리자 승인 게이트가 걸린다.
    """
    try:
        trust = float(user.get("trust_score") or 0)
    except (TypeError, ValueError):
        trust = 0.0
    try:
        viol = int(user.get("violation_count") or 0)
    except (TypeError, ValueError):
        viol = 0
    return (
        trust < SUSPICIOUS_TRUST_THRESHOLD
        or viol >= SUSPICIOUS_VIOLATION_THRESHOLD
    )


class LoginHandler(BaseHandler):
    """POST /api/auth/login"""
    def post(self):
        body = self.get_json_body()
        username = body.get("username", "").strip()
        password = body.get("password", "")
        device_id = body.get("device_id", self.get_device_id())
        location = body.get("location", self.get_location())

        if not username or not password:
            return self.write_error_json("아이디와 비밀번호를 입력하세요")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user:
            db.close()
            return self.write_error_json("아이디 또는 비밀번호가 올바르지 않습니다", 401)

        user = row_to_dict(user)

        # 계정 잠금 확인
        if user["is_locked"]:
            db.close()
            return self.write_error_json("계정이 잠겨있습니다. 관리자에게 문의하세요", 403)

        if not user["is_active"]:
            db.close()
            return self.write_error_json("비활성화된 계정입니다", 403)

        # 비밀번호 검증
        # ITEM 3 (감사 #3): 5 가 박혀 있어 config.ACCOUNT_MAX_FAILED_LOGIN
        # 외부화가 무효화돼 있었다. import 후 변수로 대체.
        if not verify_password(password, user["password_hash"]):
            new_count = user["failed_login_count"] + 1
            if new_count >= ACCOUNT_MAX_FAILED_LOGIN:
                db.execute("UPDATE users SET failed_login_count=?, is_locked=TRUE WHERE id=?",
                           (new_count, user["id"]))
            else:
                db.execute("UPDATE users SET failed_login_count=? WHERE id=?",
                           (new_count, user["id"]))
            db.commit()

            # 감사 로그
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("operation", "LOGIN_FAILED",
                 json.dumps({"username": username, "attempt": new_count}, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()

            remaining = ACCOUNT_MAX_FAILED_LOGIN - new_count
            if remaining <= 0:
                return self.write_error_json(
                    f"로그인 실패 {ACCOUNT_MAX_FAILED_LOGIN}회 초과 - 계정이 잠겼습니다",
                    403,
                )
            return self.write_error_json(
                f"비밀번호가 올바르지 않습니다 (남은 시도: {remaining}회)", 401)

        # 로그인 성공 → 실패 카운트 초기화
        db.execute("UPDATE users SET failed_login_count=0 WHERE id=?", (user["id"],))
        db.commit()

        # ── Zero Trust: 등록된 기기에서만 로그인 허용 ───────────────
        # device_id 가 user_devices 화이트리스트에 없으면 여기서 차단.
        # seed 로 각 사용자에게 기본 가상 기기 1개가 등록되어 있다.
        if not device_id:
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "DEVICE_MISSING",
                 json.dumps({"ip": self.get_ip_address()}, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()
            return self.write_error_json(
                "기기 식별자(device_id)가 필요합니다", 400, code="device_required")

        device_row = db.execute(
            "SELECT id, device_name, device_type FROM user_devices "
            "WHERE user_id=? AND device_id=? AND is_active",
            (user["id"], device_id)
        ).fetchone()
        # 정책 완화 (ZT 점수 기반 평가):
        #   - 미등록 업무기기 (device_row=None) → 로그인 통과 + audit
        #     DEVICE_USED_UNREGISTERED. 후속 score 단계에서
        #     ENV_UNREGISTERED_DEVICE (+20) 가 자동 가산되어 결정 단계에서
        #     보수적으로 격상.
        #   - 토큰 기기(totp_token) 로 로그인 시도는 여전히 차단. 토큰 기기는
        #     별도 OTP 수신 전용이라 업무 흐름과 분리되어야 함.
        if device_row and device_row["device_type"] == "totp_token":
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "DEVICE_NOT_REGISTERED",
                 json.dumps({
                     "device_id": device_id,
                     "ip": self.get_ip_address(),
                     "location": location,
                     "reason": "is_token_device",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()
            return self.write_error_json(
                "토큰 기기로는 로그인할 수 없습니다. 업무 기기 device_id 를 사용하세요.",
                403, code="device_is_token_device")

        if not device_row:
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "DEVICE_USED_UNREGISTERED",
                 json.dumps({
                     "device_id": device_id,
                     "ip": self.get_ip_address(),
                     "location": location,
                     "reason": "missing_in_user_devices",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()

        # ── Impossible-Travel 로그인 게이트 ──────────────────────
        # 직전(가장 최근) 세션의 위치/시각과 이번 로그인 위치/시각을 비교해
        # 물리적 이동 불가능한 위치 전환이면 로그인을 차단한다.
        # 세션이 활성 여부와 무관하게 가장 최근의 위치 흔적을 기준으로 잡는다
        # — 로그아웃 직후 다른 위치 재로그인 우회 경로를 막기 위함.
        #
        # 좌표 부재(unknown_pair) 또는 직전 세션 없음 등 판정 불가 케이스는
        # 기존 access_evaluator 와 동일하게 통과시킨다 (fail-open).
        # 시뮬 패널 옵션 7종은 모두 travel_service 에 좌표가 등록되어 있다.
        prev = db.execute(
            "SELECT last_location, last_location_time, location, last_activity "
            "FROM sessions "
            "WHERE user_id=? "
            "ORDER BY login_at DESC LIMIT 1",
            (user["id"],)
        ).fetchone()
        if prev is not None:
            prev_loc = prev["last_location"] or prev["location"]
            prev_time = prev["last_location_time"] or prev["last_activity"]
            impossible, reason = travel_service.evaluate(
                last_location=prev_loc,
                last_location_time=prev_time,
                current_location=location,
            )
            if impossible:
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "IMPOSSIBLE_TRAVEL_LOGIN_BLOCKED",
                     json.dumps({
                         "prev_location": prev_loc,
                         "prev_time": str(prev_time),
                         "current_location": location,
                         "reason": reason,
                         "device_id": device_id,
                     }, ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                return self.write_error_json(
                    "직전 접속 위치와 비교해 물리적으로 이동이 불가능한 위치입니다. "
                    "로그인이 차단되었습니다.",
                    403, code="impossible_travel_login_blocked"
                )

        # ── allowed_locations 로그인 게이트 ──────────────────────
        # 사용자의 허용 위치 목록(allowed_locations, JSONB) 에 없는 위치로
        # 로그인 시도하면 차단한다. 직전 위치 이력이 있는 경우에는 위의
        # impossible-travel 판정을 먼저 남기고, 물리적 이동이 가능하거나
        # 판정 불가한 비허용 위치는 이 게이트에서 막는다.
        #
        # 허용 목록이 비어 있는 경우(시드 데이터 오류 등)는 fail-open 통과
        # — 로그인 자체가 막혀버리면 시연/운영 차원의 영향이 크므로 보수적
        # 분기. allowed_locations 가 빈 시드는 init_data.py 기준 없음.
        allowed_locations = user.get("allowed_locations") or []
        if allowed_locations and location not in allowed_locations:
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "LOGIN_BLOCKED_LOCATION_NOT_ALLOWED",
                 json.dumps({
                     "attempted_location": location,
                     "allowed_locations": allowed_locations,
                     "device_id": device_id,
                     "ip": self.get_ip_address(),
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()
            return self.write_error_json(
                "허용된 위치 목록에 없는 위치에서의 로그인 시도입니다. "
                "로그인이 차단되었습니다.",
                403, code="location_not_allowed_login"
            )

        # ── 로그인 관리자 승인 게이트 ────────────────────────────
        # 신뢰점수 / 위반횟수 임계값을 넘는 계정과, OTP 토큰 기기를 아직
        # 등록하지 않은 계정은 로그인 자체를 보류한다. 활성 "approved"
        # 요청이 있는 경우에만 1회 통과시킨다.
        # (자원 단위 사전승인 PRE_APPROVAL 과는 별개의, 로그인 단위
        #  정책 예외이다.)
        approval_request_id = None
        has_token_device = bool(db.execute(
            "SELECT 1 FROM user_devices "
            "WHERE user_id=? AND device_type='totp_token' AND is_active LIMIT 1",
            (user["id"],)
        ).fetchone())
        is_suspicious = _is_suspicious_user(user)
        requires_login_approval = is_suspicious or not has_token_device
        if requires_login_approval:
            approved = db.execute(
                "SELECT id FROM login_approval_requests "
                "WHERE user_id=? AND status='approved' "
                "  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) "
                "ORDER BY resolved_at DESC LIMIT 1",
                (user["id"],)
            ).fetchone()
            if approved:
                # 아직 세션으로 소비되지 않은 유효한 승인이 있다.
                approval_request_id = (
                    approved["id"] if hasattr(approved, "__getitem__") else approved[0]
                )
            else:
                # 기존 pending 이 없으면 하나를 생성해 큐에 올린다.
                pending = db.execute(
                    "SELECT id FROM login_approval_requests "
                    "WHERE user_id=? AND status='pending' LIMIT 1",
                    (user["id"],)
                ).fetchone()
                if not pending:
                    reasons = []
                    if is_suspicious:
                        reasons.append(
                            f"의심 계정: trust_score={user.get('trust_score')}, "
                            f"violation_count={user.get('violation_count')}"
                        )
                    if not has_token_device:
                        reasons.append("OTP 토큰 기기 미등록")
                    justification = "로그인 관리자 승인 필요: " + "; ".join(reasons)
                    db.execute(
                        "INSERT INTO login_approval_requests "
                        "(user_id, justification) VALUES (?, ?)",
                        (user["id"], justification)
                    )
                    db.commit()
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "LOGIN_APPROVAL_REQUIRED",
                     json.dumps({
                         "trust_score": float(user.get("trust_score") or 0),
                         "violation_count": int(user.get("violation_count") or 0),
                         "is_suspicious": is_suspicious,
                         "has_token_device": has_token_device,
                         "reason": (
                             "suspicious_user"
                             if is_suspicious and has_token_device else
                             "token_device_missing"
                             if not is_suspicious and not has_token_device else
                             "suspicious_user_and_token_device_missing"
                         ),
                         "device_id": device_id,
                         "location": location,
                     }, ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                message = (
                    "OTP 토큰 기기가 등록되지 않아 로그인이 보류되었습니다. "
                    "관리자 로그인 승인 후 1회 로그인할 수 있습니다."
                    if not is_suspicious and not has_token_device else
                    "의심 계정으로 분류되고 OTP 토큰 기기도 등록되지 않아 "
                    "로그인이 보류되었습니다. 관리자 로그인 승인 후 다시 시도하세요."
                    if is_suspicious and not has_token_device else
                    "의심 계정으로 분류되어 로그인이 차단되었습니다. "
                    "관리자 로그인 승인 후 다시 시도하세요."
                )
                return self.write_error_json(
                    message,
                    403, code="admin_approval_required"
                )

        # 1차 토큰 발급 (MFA 미검증). device_id 를 토큰에 박아
        # MFA 단계에서 기기 바꿔치기를 차단한다.
        token = create_token(
            user["id"], user["username"], user["role"],
            mfa_verified=False, device_id=device_id,
            admin_gated=bool(approval_request_id),
            approval_request_id=approval_request_id,
        )

        # 토큰 기기 보유 여부 — 프런트는 이 값으로 MFA 화면 분기를 결정한다.
        # (patrol_jung 같이 토큰 기기가 아예 없는 사용자는 TOTP 입력 대신
        #  "관리자 승인이 곧 2차 인증" 경로로 즉시 verify 를 호출한다.)
        # user_devices 에 최소 1개 등록이 있으면 MFA 필수 (기기 기준)
        mfa_required = True

        # 감사 로그
        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
            ("operation", "LOGIN_SUCCESS",
             json.dumps({"device_id": device_id, "location": location}, ensure_ascii=False),
             user["id"])
        )
        db.commit()
        db.close()

        self.write_json({
            "token": token,
            "mfa_required": mfa_required,
            "has_token_device": has_token_device,
            "admin_gated": bool(approval_request_id),
            "approval_request_id": approval_request_id,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "name": user["name"],
                "department": user["department"],
                "rank": user["rank"],
                "role": user["role"],
                "trust_score": user["trust_score"],
                "violation_count": user["violation_count"],
            },
            "message": (
                "관리자 로그인 승인으로 1회 로그인 허용됨 (세션 단축)"
                if approval_request_id else
                ("MFA 인증이 필요합니다" if mfa_required else "로그인 성공")
            )
        })


class MFAVerifyHandler(BaseHandler):
    """POST /api/auth/mfa/verify"""
    def post(self):
        body = self.get_json_body()
        otp_code = body.get("otp_code", "")
        device_id = body.get("device_id", self.get_device_id())
        location = body.get("location", self.get_location())

        # 1차 토큰 검증
        auth = self.request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.write_error_json("토큰이 필요합니다", 401)

        payload = decode_token(auth[7:])
        if not payload:
            return self.write_error_json("유효하지 않은 토큰입니다", 401)

        user_id = payload["user_id"]

        # ── Zero Trust: 1차 토큰에 묶인 device_id 와 요청의 device_id 일치 요구 ──
        token_device_id = payload.get("device_id")
        if token_device_id and device_id and token_device_id != device_id:
            return self.write_error_json(
                "로그인 시도 기기와 MFA 기기가 일치하지 않습니다.",
                403, code="device_mismatch")
        # 요청에 device_id 가 없으면 토큰값을 사용 (토큰이 바인딩되어 있으므로 안전)
        effective_device_id = device_id or token_device_id
        if not effective_device_id:
            return self.write_error_json(
                "device_id 가 필요합니다", 400, code="device_required")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            db.close()
            return self.write_error_json("사용자를 찾을 수 없습니다", 404)

        user = row_to_dict(user)

        # ── 1) 업무 기기 검증 (정책 완화 — ZT 점수 기반 평가) ───────
        # effective_device_id 는 업무 기기이어야 한다.
        # 정책:
        #   - 미등록 업무기기 (work_row=None) → MFA 통과 허용 + audit
        #     DEVICE_USED_UNREGISTERED. 환경 가산은 score 단계에서 자동.
        #   - 토큰 기기(totp_token) 로 로그인 시도는 여전히 차단.
        work_row = db.execute(
            "SELECT id, device_name, device_type FROM user_devices "
            "WHERE user_id=? AND device_id=? AND is_active",
            (user["id"], effective_device_id)
        ).fetchone()
        if work_row and work_row["device_type"] == "totp_token":
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "DEVICE_NOT_REGISTERED",
                 json.dumps({
                     "device_id": effective_device_id,
                     "stage": "mfa_verify",
                     "reason": "is_token_device",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()
            return self.write_error_json(
                "토큰 기기로는 로그인 MFA 를 진행할 수 없습니다.",
                403, code="device_is_token_device")

        if not work_row:
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "DEVICE_USED_UNREGISTERED",
                 json.dumps({
                     "device_id": effective_device_id,
                     "stage": "mfa_verify",
                     "reason": "missing_in_user_devices",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()

        # ── 2) 사용자의 토큰 기기를 찾아 그 mfa_secret 으로 TOTP 검증 ──
        # 예외: 1차 토큰이 관리자 승인 게이트 경로(ag=True) 이고 이 사용자가
        #       토큰 기기를 아예 보유하지 않은 경우, 관리자 승인 자체가 제2
        #       인증 요소가 된다. → TOTP 입력을 요구하지 않고 통과시키며,
        #       해당 결정은 감사 로그에 별도 이벤트로 남긴다. 다른 사용자
        #       (토큰 기기 보유) 는 항상 TOTP 를 요구한다.
        # 하위호환: 구토큰의 "bg" 키도 허용한다.
        is_admin_gated_hint = bool(payload.get("ag") or payload.get("bg"))
        token_row = db.execute(
            "SELECT id, device_name, mfa_secret, last_otp_step FROM user_devices "
            "WHERE user_id=? AND device_type='totp_token' AND is_active "
            "ORDER BY id LIMIT 1",
            (user["id"],)
        ).fetchone()

        if not token_row or not token_row["mfa_secret"]:
            if not is_admin_gated_hint:
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "TOKEN_DEVICE_MISSING",
                     json.dumps({"stage": "mfa_verify"}, ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                return self.write_error_json(
                    "이 계정에 등록된 토큰 기기가 없습니다.",
                    403, code="token_device_missing")
            # 관리자 승인 게이트 + 토큰 기기 없음 → 관리자 승인을 2차 인증으로 간주.
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "MFA_BYPASSED_BY_ADMIN_APPROVAL",
                 json.dumps({
                     "work_device_id": effective_device_id,
                     "reason": "no_token_device; admin_approval_approved",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            token_row = None  # 이후 로직에서 토큰 기기 미참조 명시
        else:
            # RFC 6238 §5.2 — replay 방지. last_otp_step 보다 큰 step 만 통과.
            ok, used_step = verify_totp_consume(
                token_row["mfa_secret"], otp_code,
                last_used_step=token_row.get("last_otp_step"),
            )
            if not ok:
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "MFA_FAILED",
                     json.dumps({
                         "work_device_id": effective_device_id,
                         # 정책 완화 후 미등록 업무기기는 work_row=None 가능
                         "work_device_pk": (work_row["id"] if work_row else None),
                         "token_device_pk": token_row["id"],
                         "reason": (
                             "replay_or_invalid"
                             if token_row.get("last_otp_step") is not None
                             else "invalid"
                         ),
                     }, ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                return self.write_error_json(
                    "OTP 코드가 올바르지 않거나 이미 사용된 코드입니다",
                    401, code="otp_invalid_or_reused"
                )

            # 통과한 step 마킹 — 다음 검증에서 같은/이전 step 의 코드는 거부됨
            db.execute(
                "UPDATE user_devices SET last_otp_step=? WHERE id=?",
                (used_step, token_row["id"])
            )
            db.commit()

        # 미등록 업무기기 케이스: matched_device_pk = None — 후속 last_seen_at
        # 갱신 단계에서 work_row 가 None 이면 work device 갱신은 skip (해당 행이 없음).
        matched_device_pk = work_row["id"] if work_row else None
        # 이후 세션/토큰 로직에서도 effective_device_id(=업무 기기) 를 사용
        device_id = effective_device_id

        # 업무 기기 + (있는 경우) 토큰 기기 last_seen_at 갱신.
        # work_row 가 None (미등록 업무기기) 이면 work 쪽 갱신은 skip.
        if matched_device_pk is not None and token_row is not None:
            db.execute(
                "UPDATE user_devices SET last_seen_at=now() "
                "WHERE id IN (?, ?)",
                (matched_device_pk, token_row["id"])
            )
        elif matched_device_pk is not None:
            db.execute(
                "UPDATE user_devices SET last_seen_at=now() WHERE id=?",
                (matched_device_pk,)
            )
        elif token_row is not None:
            # work 미등록 + 토큰 기기 있음 — 토큰 쪽만 last_seen_at 갱신
            db.execute(
                "UPDATE user_devices SET last_seen_at=now() WHERE id=?",
                (token_row["id"],)
            )
        db.commit()

        # ── 관리자 승인 게이트 경로 여부 판정 ──────────────────
        # 1차 토큰에 ag=True 가 박혀 있으면 단축 세션 + is_admin_gated 플래그.
        # 하위호환: 구토큰의 "bg" / "bg_request_id" 도 허용.
        is_admin_gated = bool(payload.get("ag") or payload.get("bg"))
        approval_request_id = payload.get("ag_request_id") or payload.get("bg_request_id")

        if is_admin_gated:
            # 승인이 아직 유효한지(혹은 이미 used 로 전이됐는지) 재확인.
            ag_row = db.execute(
                "SELECT id, status, expires_at "
                "FROM login_approval_requests WHERE id=? AND user_id=?",
                (approval_request_id, user["id"])
            ).fetchone()
            # ITEM 5: 'used' 상태는 race 또는 재사용 시도 — 409 로 분리해
            # admin_approval_already_consumed 코드를 일관 반환.
            if ag_row and ag_row["status"] == "used":
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "ADMIN_APPROVAL_REUSE_BLOCKED",
                     json.dumps({"approval_request_id": approval_request_id,
                                 "reason": "already_used"},
                                ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                return self.write_error_json(
                    "관리자 로그인 승인이 이미 사용되었거나 만료되었습니다.",
                    409, code="admin_approval_already_consumed")
            if (not ag_row
                    or ag_row["status"] != "approved"):
                db.execute(
                    "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                    "VALUES (?,?,?,?)",
                    ("operation", "ADMIN_APPROVAL_INVALID",
                     json.dumps({"approval_request_id": approval_request_id,
                                 "reason": "not_approved_or_missing"},
                                ensure_ascii=False),
                     user["id"])
                )
                db.commit()
                db.close()
                return self.write_error_json(
                    "관리자 로그인 승인이 유효하지 않습니다.",
                    403, code="admin_approval_invalid")
            # expires_at 은 문자열/tz-aware datetime 두 경우 모두 가능 →
            # DB 측에서 재검증.
            still_valid = db.execute(
                "SELECT 1 FROM login_approval_requests "
                "WHERE id=? AND status='approved' "
                "  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
                (approval_request_id,)
            ).fetchone()
            if not still_valid:
                db.close()
                return self.write_error_json(
                    "관리자 로그인 승인이 만료되었습니다. 다시 요청하세요.",
                    403, code="admin_approval_expired")

        # ── 동시 접속 정책 (B안 + notification) ─────────────────────
        # 세션 INSERT 전에 기존 활성 세션을 검사한다.
        #   1) is_active=TRUE 인 세션 행을 조회
        #   2) check_session() 으로 실제로 유효한("live") 세션만 선별
        #      - 유휴 타임아웃 초과 / 절대 만료 초과 행은 "좀비"로 간주, is_active=FALSE 처리
        #   3) 하나라도 live 세션이 남아 있으면:
        #        a) 그 세션(들)에 pending_reauth=TRUE 를 세워 실시간 재인증 유도
        #        b) 새 세션은 만들지 않고 409 already_logged_in 을 반환
        #      → "두 번째 로그인은 재인증 요구 없이 차단되고, 기존 세션에만
        #         재인증 모달이 뜬다" 는 정책을 만족한다.
        # NOTE: sensitive_unlocked_at 은 스키마에 아직 존재하지 않는
        # 예약 컬럼이다. check_session() 은 dict.get() 으로 접근해
        # 누락 시 안전하게 무시하므로 여기서는 SELECT 대상에서 제외한다.
        existing_rows = db.execute(
            "SELECT id, last_activity, login_at, absolute_expires_at, "
            "       max_sensitivity_accessed, is_active, "
            "       pending_reauth, pending_reauth_at "
            "FROM sessions WHERE user_id=? AND is_active",
            (user["id"],)
        ).fetchall()

        live_ids: list[int] = []
        zombie_ids: list[int] = []
        presence_stale_ids: list[int] = []
        for row in (existing_rows or []):
            r = row_to_dict(row)
            chk = check_session(r)
            session_id_existing = int(r["id"])
            if chk.ok and has_presence_record(session_id_existing):
                if is_session_stale(session_id_existing):
                    presence_stale_ids.append(session_id_existing)
                else:
                    live_ids.append(session_id_existing)
            elif chk.ok:
                live_ids.append(session_id_existing)
            else:
                zombie_ids.append(session_id_existing)

        if presence_stale_ids:
            zombie_ids.extend(presence_stale_ids)
            for sid in presence_stale_ids:
                forget_session(sid)

        if zombie_ids:
            placeholders = ",".join(["?"] * len(zombie_ids))
            db.execute(
                f"UPDATE sessions SET is_active=FALSE "
                f"WHERE id IN ({placeholders})",
                tuple(zombie_ids)
            )
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "ZOMBIE_SESSION_CLEANED",
                 json.dumps({
                    "session_ids": zombie_ids,
                    "stage": "mfa_verify_concurrent_check",
                    "presence_stale_session_ids": presence_stale_ids,
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()

        if live_ids:
            # 기존 live 세션에만 pending_reauth 플래그. 새 세션은 만들지 않는다.
            placeholders = ",".join(["?"] * len(live_ids))
            db.execute(
                f"UPDATE sessions "
                f"SET pending_reauth=TRUE, pending_reauth_at=now() "
                f"WHERE id IN ({placeholders})",
                tuple(live_ids)
            )
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("audit", "CONCURRENT_SESSION_LOCKED",
                 json.dumps({
                    "locked_session_ids": live_ids,
                    "reason": "new_login_blocked_existing_flagged",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "CONCURRENT_LOGIN_REJECTED",
                 json.dumps({
                    "existing_live_session_ids": live_ids,
                    "attempted_device_id": device_id,
                    "attempted_location": location,
                    "reason": "already_logged_in",
                 }, ensure_ascii=False),
                 user["id"])
            )
            db.commit()
            db.close()
            return self.write_error_json(
                "이 계정은 이미 다른 기기/브라우저에서 로그인되어 있습니다. "
                "해당 세션에서 먼저 로그아웃한 뒤 다시 시도하세요.",
                409, code="already_logged_in"
            )

        # 세션 먼저 생성 (session_id를 JWT에 포함하기 위해)
        # admin-gated 세션은 유휴 5분 / 절대 30분. 일반은 유휴 15분 / 절대 8시간.
        if is_admin_gated:
            idle_sec = ADMIN_GATED_SESSION_IDLE_SEC
            absolute_sec = ADMIN_GATED_SESSION_ABSOLUTE_SEC
        else:
            # 일반 세션은 DB DEFAULT (003 마이그레이션: 900s / login+8h) 사용.
            # idle 는 DEFAULT 900 이 들어가므로 여기선 명시적으로 900 전달.
            idle_sec = 900
            absolute_sec = 8 * 3600

        # ITEM 5 (감사 #5): admin-gated 1회성 승인 소비를 원자화.
        # 기존: 세션 INSERT commit 후에 별 commit 으로 status='used' UPDATE 를
        # 했고 status 조건도 없어, 같은 1차 토큰의 동시 mfa/verify 호출이
        # 두 admin-gated 세션을 만들고 used_session_id 가 한쪽만 기록되었다.
        # 수정: 세션 INSERT 직전에 조건부 UPDATE 로 승인권을 선점하고,
        # claim → INSERT → used_session_id 채움 + audit 를 단일 트랜잭션
        # (한 번의 commit) 으로 묶는다.
        if is_admin_gated and approval_request_id:
            claim = db.execute("""
                UPDATE login_approval_requests
                   SET status='used', used_session_id=NULL
                 WHERE id=? AND user_id=? AND status='approved'
                   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                RETURNING id
            """, (approval_request_id, user["id"])).fetchone()
            if not claim:
                db.rollback()
                db.close()
                return self.write_error_json(
                    "관리자 로그인 승인이 이미 사용되었거나 만료되었습니다.",
                    409, code="admin_approval_already_consumed"
                )

        # ITEM 7 (감사 #7): naive 로컬 strftime 문자열을 TIMESTAMPTZ 컬럼에
        # 바인딩하면 PG 가 세션 timezone 기준으로 해석 → 서버 KST + PG 세션
        # UTC 시 9시간 어긋남. core/break_glass.py:191-206 의 패턴을 이식 —
        # tz-aware UTC datetime 을 직접 바인딩한다 (psycopg2 가 정확히 처리).
        expires = datetime.datetime.now(datetime.timezone.utc) + \
                  datetime.timedelta(seconds=absolute_sec)
        session_row = db.execute("""
            INSERT INTO sessions
                (user_id, token, device_id, ip_address, location,
                 expires_at, absolute_expires_at, idle_timeout_seconds,
                 is_admin_gated)
            VALUES (?,?,?,?,?,?,?,?,?) RETURNING id
        """, (user["id"], "pending", device_id,
              self.get_ip_address(), location,
              expires, expires, idle_sec, is_admin_gated)).fetchone()
        session_id = (session_row["id"] if isinstance(session_row, dict)
                      else session_row[0])

        # admin-gated: 위에서 status='used' 로 선점한 승인 행에 새 session_id
        # 를 채워 추적성을 확보. 동일 트랜잭션 안이라 [claim → INSERT → 채움]
        # 한 번에 commit.
        if is_admin_gated and approval_request_id:
            db.execute(
                "UPDATE login_approval_requests "
                "SET used_session_id=? WHERE id=?",
                (session_id, approval_request_id)
            )
            db.execute(
                "INSERT INTO audit_logs (layer, event_type, details, user_id) "
                "VALUES (?,?,?,?)",
                ("operation", "ADMIN_GATED_SESSION_STARTED",
                 json.dumps({"session_id": session_id,
                             "approval_request_id": approval_request_id,
                             "idle_timeout_seconds": idle_sec,
                             "absolute_timeout_seconds": absolute_sec},
                            ensure_ascii=False),
                 user["id"])
            )

        # 단일 commit: 일반 흐름은 세션 INSERT 만, admin-gated 흐름은 claim+INSERT+
        # used_session_id 채움+audit 까지 한 트랜잭션. 어느 한 쪽이 실패하면
        # claim 도 rollback 되어 status='approved' 가 복원, 재시도 가능.
        db.commit()

        # MFA 검증 완료 → session_id 포함 최종 토큰 발급
        final_token = create_token(
            user["id"], user["username"], user["role"],
            mfa_verified=True, session_id=session_id,
            admin_gated=is_admin_gated,
        )

        # 세션 레코드에 실제 토큰 반영
        db.execute("UPDATE sessions SET token=? WHERE id=?", (final_token, session_id))
        db.commit()

        # 감사 로그
        db.execute(
            "INSERT INTO audit_logs (layer, event_type, details, user_id) VALUES (?,?,?,?)",
            ("operation", "MFA_VERIFIED",
             json.dumps({"session_id": session_id,
                         "device_id": device_id,
                         "admin_gated": is_admin_gated},
                        ensure_ascii=False),
             user["id"])
        )
        db.commit()
        db.close()

        self.write_json({
            "token": final_token,
            "session_id": session_id,
            "admin_gated": is_admin_gated,
            "message": "인증 완료",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "name": user["name"],
                "department": user["department"],
                "rank": user["rank"],
                "role": user["role"],
                "trust_score": user["trust_score"],
                "violation_count": user["violation_count"],
            }
        })


class LogoutHandler(BaseHandler):
    """POST /api/auth/logout

    설계 원칙:
      로그아웃은 "이 토큰에 묶인 세션을 끝내겠다" 는 의지 표현이므로
      JWT 가 파싱·검증만 되면 **세션 상태와 무관하게 항상 성공** 시킨다.
      require_auth() 는 다음 경우에 4xx 를 던져 세션 정리를 막아버리는데,
      모두 실제로는 "세션을 닫아야 마땅한" 상황이라 막을 이유가 없다:

        - pending_reauth=TRUE  (다른 브라우저에서 동시 로그인 감지)
        - session_expired      (특히 신규 계정의 admin-gated 단축 세션)
        - account_locked       (다른 관리자가 방금 계정 비활성화/잠금)

      이 경우들에서도 같은 user_id 의 활성 세션을 모두 비활성화하고
      LOGOUT 감사 로그를 남긴 뒤 200 으로 응답한다.

      JWT 자체가 없거나 위변조이면 401 (이건 정상).
    """
    def post(self):
        # 1차 토큰만 통과한 (mfa_verified=False) 상태에서의 로그아웃도 허용한다.
        # — 신규 계정이 MFA 단계 중간에 취소하려는 경우 등.
        body = self.get_json_body()
        payload = self.get_current_user_from_token()
        if not payload and body.get("token"):
            payload = decode_token(str(body.get("token") or ""))
        if not payload:
            return self.write_error_json("토큰이 필요합니다", 401,
                                          code="token_invalid")

        user_id = payload.get("user_id")
        session_id = payload.get("session_id")
        if not user_id:
            return self.write_error_json("세션 정보가 비어있습니다", 401,
                                          code="token_invalid")

        db = get_db()
        try:
            # 가능한 한 좁게: 토큰의 session_id 가 있으면 그 세션만 종료.
            # 없으면(1차 토큰 등) 해당 사용자의 활성 세션 전체 종료.
            if session_id:
                db.execute(
                    "UPDATE sessions SET is_active=FALSE "
                    "WHERE id=? AND user_id=?",
                    (session_id, user_id)
                )
                logout_scope = "single_session"
            else:
                db.execute(
                    "UPDATE sessions SET is_active=FALSE "
                    "WHERE user_id=? AND is_active",
                    (user_id,)
                )
                logout_scope = "all_sessions"

            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("operation", "LOGOUT",
                 json.dumps({
                     "manual": not bool(body.get("beacon")),
                     "reason": body.get("reason") or "user_logout",
                     "scope": logout_scope,
                     "session_id": session_id,
                     "mfa_verified": bool(payload.get("mfa_verified")),
                 }, ensure_ascii=False),
                 user_id)
            )
            db.commit()
        finally:
            db.close()

        forget_session(int(session_id) if session_id else None)
        self.write_json({"message": "로그아웃 완료"})


class HeartbeatHandler(BaseHandler):
    """POST /api/auth/heartbeat"""

    def post(self):
        user = self.require_auth()
        if not user:
            return
        session_id = user.get("session_id")
        if not session_id:
            return self.write_error_json(
                "세션 정보가 비어있습니다", 401, code="session_missing")

        mark_session_seen(int(session_id))
        self.write_json({"status": "ok"})


class MeHandler(BaseHandler):
    """GET /api/auth/me"""
    def get(self):
        user = self.require_auth()
        if not user:
            return

        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE id=?",
                              (user["user_id"],)).fetchone()
        # JWT에 포함된 session_id로 정확한 세션 조회 (다중 세션 안전)
        session_id = user.get("session_id")
        session_row = None
        if session_id:
            session_row = db.execute(
                "SELECT * FROM sessions WHERE id=? AND user_id=?",
                (session_id, user["user_id"])
            ).fetchone()
        db.close()

        if not user_row:
            return self.write_error_json("사용자를 찾을 수 없습니다", 404)

        u = row_to_dict(user_row)
        s = row_to_dict(session_row) if session_row else None

        # 세션 타이머 계산 (#24)
        # - server_time : 클라이언트가 자기 시계 drift 를 보정할 기준 시각.
        # - idle_remaining_seconds : last_activity + idle_timeout 까지 남은 초.
        # - absolute_remaining_seconds : 절대 만료까지 남은 초.
        # 음수가 나올 경우 0 으로 클램프 (만료 직전 race 보호).
        session_payload = None
        if s:
            import datetime as _dt
            now_utc = _dt.datetime.now(tz=_dt.timezone.utc)
            idle_timeout = int(s.get("idle_timeout_seconds") or 900)
            last_act = parse_ts(s.get("last_activity"))
            abs_exp = parse_ts(s.get("absolute_expires_at"))

            idle_remaining = None
            if last_act is not None:
                elapsed = (now_utc - last_act).total_seconds()
                idle_remaining = max(0, int(idle_timeout - elapsed))

            absolute_remaining = None
            if abs_exp is not None:
                absolute_remaining = max(0, int((abs_exp - now_utc).total_seconds()))

            session_payload = {
                "id": s["id"],
                "device_id": s["device_id"],
                "location": s["location"],
                "login_at": s["login_at"],
                "last_activity": s["last_activity"],
                "max_sensitivity_accessed": s["max_sensitivity_accessed"],
                # ── #24 세션 타이머 페이로드 ────────────────────────
                "server_time": now_utc.isoformat(),
                "idle_timeout_seconds": idle_timeout,
                "idle_remaining_seconds": idle_remaining,
                "absolute_expires_at": s.get("absolute_expires_at"),
                "absolute_remaining_seconds": absolute_remaining,
                "is_admin_gated": bool(s.get("is_admin_gated")),
            }

        self.write_json({
            "user": {
                "id": u["id"],
                "username": u["username"],
                "name": u["name"],
                "department": u["department"],
                "rank": u["rank"],
                "role": u["role"],
                "trust_score": u["trust_score"],
                "violation_count": u["violation_count"],
                "registered_devices": u["registered_devices"],
                "allowed_locations": u["allowed_locations"],
                "assigned_cases": u["assigned_cases"],
            },
            "session": session_payload,
        })


class TOTPCodeHandler(BaseHandler):
    """
    GET /api/auth/totp-code - [DEPRECATED]

    기기별 시크릿 도입 전의 사용자 공용 TOTP 조회 엔드포인트.
    현재 MFA 검증은 user_devices 기반이므로 이 엔드포인트는 항상 410 을 돌려준다.
    신규 클라이언트는 POST /api/auth/mfa/otp 를 사용할 것.
    """
    def get(self):
        self.write_error_json(
            "이 엔드포인트는 제거되었습니다. POST /api/auth/mfa/otp 를 사용하세요.",
            410, code="deprecated"
        )


class MFADeviceOtpHandler(BaseHandler):
    """
    POST /api/auth/mfa/otp

    로그인 모달의 "OTP 전송" 버튼이 누르는 엔드포인트.

    동작:
      1. 1차 토큰(mfa_verified=False) 에서 user_id 와 업무 기기 device_id 추출.
      2. 해당 사용자의 토큰 기기(device_type='totp_token') 를 찾는다.
      3. otp_requests 큐에 row 를 삽입한다. 토큰 기기 앱이
         /api/device/otp-requests 를 폴링해 이 row 를 수신한다.
      4. 응답에는 OTP 코드를 절대 포함하지 않는다. 토큰 기기명만 알려주고,
         사용자는 해당 앱에서 코드를 확인해 수동 입력해야 한다.
    """
    def post(self):
        auth = self.request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.write_error_json("1차 인증 토큰이 필요합니다", 401)

        payload = decode_token(auth[7:])
        if not payload:
            return self.write_error_json("유효하지 않은 토큰입니다", 401)

        user_id = payload["user_id"]
        token_device_id_in_payload = payload.get("device_id")

        body = self.get_json_body()
        req_work_device_id = body.get("device_id") or self.get_device_id()

        # 1차 토큰의 device_id 는 "업무 기기" 이다. 요청과 일치해야 한다.
        if (token_device_id_in_payload and req_work_device_id
                and token_device_id_in_payload != req_work_device_id):
            return self.write_error_json(
                "로그인 시도 기기와 요청 기기가 일치하지 않습니다.",
                403, code="device_mismatch")

        work_device_id = token_device_id_in_payload or req_work_device_id
        if not work_device_id:
            return self.write_error_json(
                "업무 기기 device_id 가 필요합니다",
                400, code="device_required")

        db = get_db()
        try:
            # 사용자의 토큰 기기를 찾는다 (사용자당 1개 가정).
            token_row = db.execute(
                "SELECT id, device_id, device_name FROM user_devices "
                "WHERE user_id=? AND device_type='totp_token' AND is_active "
                "ORDER BY id LIMIT 1",
                (user_id,)
            ).fetchone()

            if not token_row:
                return self.write_error_json(
                    "이 계정에 등록된 토큰 기기가 없습니다. "
                    "관리자에게 토큰 기기 등록을 요청하세요.",
                    404, code="token_device_missing")

            # otp_requests 큐에 push
            ip_address = self.get_ip_address()
            location = self.get_location() or "unknown"
            db.execute(
                "INSERT INTO otp_requests "
                "(user_id, token_device_pk, work_device_id, ip_address, location, expires_at) "
                "VALUES (?,?,?,?,?, now() + INTERVAL '2 minutes')",
                (user_id, token_row["id"], work_device_id, ip_address, location)
            )
            db.commit()
        finally:
            db.close()

        self.write_json({
            "status": "sent",
            "token_device_id": token_row["device_id"],
            "token_device_name": token_row["device_name"],
            "message": (
                f"OTP 가 토큰 기기 \"{token_row['device_name']}\" 로 "
                f"전송되었습니다. 앱에서 6자리 코드를 확인해 입력하세요."
            ),
        })


class ReauthHandler(BaseHandler):
    """
    POST /api/auth/reauth

    Level 3 (REAUTH_REQUIRED) 재인증. 이미 MFA 완료된 세션에서 추가 OTP
    검증을 수행하고, 성공 시 sessions.reauth_at = now() 로 갱신해
    access_evaluator 가 force_reauth 요구를 충족한 것으로 간주하게 한다.

    요청: { "otp_code": "123456" }
    """
    def post(self):
        user = self.require_auth()
        if not user:
            return

        body = self.get_json_body()
        otp_code = (body.get("otp_code") or "").strip()
        if not otp_code:
            return self.write_error_json("OTP 코드를 입력하세요", 400,
                                          code="otp_required")

        session_id = user.get("session_id")
        if not session_id:
            return self.write_error_json(
                "유효한 세션이 없습니다", 401, code="session_missing")

        db = get_db()
        try:
            # 토큰 기기 조회
            token_row = db.execute(
                "SELECT id, device_name, mfa_secret, last_otp_step FROM user_devices "
                "WHERE user_id=? AND device_type='totp_token' AND is_active "
                "ORDER BY id LIMIT 1",
                (user["user_id"],)
            ).fetchone()

            if not token_row or not token_row["mfa_secret"]:
                # 토큰 기기 미보유 사용자는 재인증 경로를 사용할 수 없다.
                # (patrol_jung 류는 관리자 로그인 승인이 이미 2차 인증 역할을
                #  수행하며, 세션 자체가 단축 admin-gated 모드로 실행된다.)
                db.execute(
                    "INSERT INTO audit_logs "
                    "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                    ("operation", "REAUTH_FAILED",
                     json.dumps({"reason": "no_token_device",
                                 "session_id": session_id},
                                ensure_ascii=False),
                     user["user_id"])
                )
                db.commit()
                return self.write_error_json(
                    "이 계정에는 재인증에 사용할 토큰 기기가 없습니다.",
                    403, code="token_device_missing")

            # OTP 검증 — replay 방지 (RFC 6238 §5.2).
            ok, used_step = verify_totp_consume(
                token_row["mfa_secret"], otp_code,
                last_used_step=token_row.get("last_otp_step"),
            )
            if not ok:
                db.execute(
                    "INSERT INTO audit_logs "
                    "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                    ("operation", "REAUTH_FAILED",
                     json.dumps({
                         "reason": (
                             "otp_replay_or_invalid"
                             if token_row.get("last_otp_step") is not None
                             else "otp_invalid"
                         ),
                         "session_id": session_id,
                     }, ensure_ascii=False),
                     user["user_id"])
                )
                db.commit()
                return self.write_error_json(
                    "OTP 코드가 올바르지 않거나 이미 사용된 코드입니다.",
                    401, code="otp_invalid_or_reused")

            # 통과한 step 마킹 (재사용 차단)
            db.execute(
                "UPDATE user_devices SET last_otp_step=? WHERE id=?",
                (used_step, token_row["id"])
            )

            # 성공 — sessions.reauth_at 갱신 + pending_reauth 해제
            db.execute(
                "UPDATE sessions SET reauth_at=now(), "
                "  pending_reauth=FALSE, pending_reauth_at=NULL, "
                "  last_activity=now() "
                "WHERE id=? AND user_id=?",
                (session_id, user["user_id"])
            )
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("operation", "REAUTH_SUCCESS",
                 json.dumps({"session_id": session_id},
                            ensure_ascii=False),
                 user["user_id"])
            )
            db.commit()
        finally:
            db.close()

        self.write_json({
            "message": "재인증 완료",
            "session_id": session_id,
        })
