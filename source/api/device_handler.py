"""
기기 등록 / 가상 기기 핸들러

엔드포인트:
  GET    /api/devices              — 현재 사용자의 등록 기기 목록
  POST   /api/devices              — 새 가상 기기 등록 (device_id + mfa_secret 자동 생성)
  DELETE /api/devices/{id}         — 기기 삭제 (소유자 본인만)
  GET    /api/devices/{id}/totp    — 해당 기기의 현재 TOTP 코드 (가상 기기 시연용)

설계:
  - 각 기기는 고유한 mfa_secret 을 가진다 → 기기별 TOTP 검증 가능.
  - 'virtual' 타입 기기는 서버가 TOTP 코드를 돌려준다 (실제 Authenticator 앱 없이 시연).
  - 'mobile'/'desktop' 타입은 production 에서 서버가 OTP 를 돌려주지 않는다.
"""
from __future__ import annotations

import json
import os
import secrets as _secrets

from api.base_handler import BaseHandler
from database import get_db
from security.mfa_service import generate_secret, generate_totp, provisioning_uri


def _new_device_id(device_type: str) -> str:
    """
    기기 타입별 device_id 접두어.
    - totp_token → 'token-<hex>'  (별도 실행되는 Tkinter 토큰 기기 앱과 짝)
    - 그 외       → 'vdev-<hex>'
    """
    if device_type == "totp_token":
        return f"token-{_secrets.token_hex(4)}"
    return f"vdev-{_secrets.token_hex(6)}"


def _insert_device(db, user_id: int, device_id: str, device_name: str,
                   device_type: str, mfa_secret: str | None,
                   api_key: str | None = None) -> int:
    """
    user_devices 에 insert 후 id 반환.
    mfa_secret / api_key 는 NULL 가능.
    """
    row = db.execute(
        "INSERT INTO user_devices "
        "(user_id, device_id, device_name, device_type, mfa_secret, api_key) "
        "VALUES (?,?,?,?,?,?) RETURNING id",
        (user_id, device_id, device_name, device_type, mfa_secret, api_key)
    ).fetchone()
    return row["id"] if isinstance(row, dict) else row[0]


def _row_to_device(r: dict, *, reveal_secret: bool = False) -> dict:
    """user_devices row → API 응답 dict. 기본적으로 mfa_secret 은 숨긴다."""
    out = {
        "id": r["id"],
        "device_id": r["device_id"],
        "device_name": r["device_name"],
        "device_type": r["device_type"],
        "is_active": bool(r["is_active"]),
        "created_at": r["created_at"],
        "last_seen_at": r.get("last_seen_at"),
    }
    if reveal_secret:
        out["mfa_secret"] = r["mfa_secret"]
    return out


class DeviceListHandler(BaseHandler):
    """GET /api/devices, POST /api/devices"""

    def get(self):
        user = self.require_auth()
        if not user:
            return

        db = get_db()
        try:
            rows = db.execute(
                "SELECT id, device_id, device_name, device_type, is_active, "
                "created_at, last_seen_at "
                "FROM user_devices "
                "WHERE user_id=? AND is_active "
                "ORDER BY created_at DESC",
                (user["user_id"],)
            ).fetchall()
        finally:
            db.close()

        self.write_json({
            "devices": [_row_to_device(r) for r in rows],
            "count": len(rows),
        })

    def post(self):
        user = self.require_auth()
        if not user:
            return

        body = self.get_json_body()
        device_name = (body.get("device_name") or "가상 기기").strip()[:64]
        device_type = body.get("device_type", "totp_token")
        if device_type not in ("virtual", "mobile", "desktop", "totp_token"):
            return self.write_error_json("지원하지 않는 기기 종류입니다", 400)

        device_id = _new_device_id(device_type)

        # totp_token: 별도 실행되는 Tkinter 토큰 기기 앱이 api_key 로 인증.
        #             서버 mfa_secret 을 보관하고 TOTP 를 생성해 앱에 내려준다.
        # virtual: 레거시 브라우저 팝업 시연용. 서버 mfa_secret 보관 + 즉시 노출.
        # mobile/desktop: 사용자 Authenticator 앱이 mfa_secret 을 보관 — 최초 1회 노출.
        if device_type == "totp_token":
            mfa_secret = generate_secret()
            api_key = _secrets.token_hex(24)
        else:
            mfa_secret = generate_secret()
            api_key = None

        db = get_db()
        try:
            # 사용자당 기기 수 상한 (가상 기기 남용 방지)
            cnt = db.execute(
                "SELECT COUNT(*) AS c FROM user_devices "
                "WHERE user_id=? AND is_active",
                (user["user_id"],)
            ).fetchone()["c"]
            if cnt >= 10:
                return self.write_error_json(
                    "기기 등록 한도(10개)를 초과했습니다", 400)

            # totp_token 은 계정당 1개만 허용 (같은 이유로 시드에서도 1개씩 발급)
            if device_type == "totp_token":
                exists = db.execute(
                    "SELECT id FROM user_devices "
                    "WHERE user_id=? AND device_type='totp_token' "
                    "AND is_active LIMIT 1",
                    (user["user_id"],)
                ).fetchone()
                if exists:
                    return self.write_error_json(
                        "이미 토큰 기기가 등록되어 있습니다 — "
                        "기존 토큰 기기를 삭제한 뒤 다시 등록하세요", 400,
                        code="totp_token_already_exists")

            new_id = _insert_device(
                db, user["user_id"], device_id, device_name,
                device_type, mfa_secret, api_key,
            )

            # 감사 로그
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("operation", "DEVICE_REGISTERED",
                 json.dumps({
                     "device_id": device_id,
                     "device_name": device_name,
                     "device_type": device_type,
                 }, ensure_ascii=False),
                 user["user_id"])
            )
            db.commit()

            # 방금 등록한 기기 재조회
            r = db.execute(
                "SELECT id, device_id, device_name, device_type, is_active, "
                "created_at, last_seen_at, mfa_secret "
                "FROM user_devices WHERE id=?",
                (new_id,)
            ).fetchone()
        finally:
            db.close()

        # virtual 타입은 mfa_secret + provisioning_uri 를 반환 (브라우저 팝업 시연용)
        # mobile/desktop 은 Authenticator 앱 최초 등록 시에만 시크릿 노출
        # totp_token 은 api_key 를 1회성으로 노출 (Tkinter 앱 실행 인자에 사용)
        reveal = device_type in ("virtual", "totp_token")

        resp = _row_to_device(r, reveal_secret=reveal)
        if reveal and r["mfa_secret"]:
            resp["provisioning_uri"] = provisioning_uri(
                r["mfa_secret"], user["username"])
        if device_type == "totp_token":
            # api_key 는 응답에서 최초 1회만 돌려준다. 이후에는 DB 에만 남음.
            resp["api_key"] = api_key
            resp["launch_hint"] = (
                "python apps/virtual_device.py "
                f"--account {user['username']} --device-id {device_id} "
                f"--api-key {api_key}"
            )
            # 런처 .pyw / .bat 자동 생성. 단일 호스트 배포 가정.
            # 실패해도 등록 자체는 성공으로 처리 (best-effort).
            try:
                from scripts.regenerate_launchers import regenerate as _regen
                _regen()
                resp["launcher_pyw"] = (
                    f"apps/launchers/token_{user['username']}.pyw"
                )
                resp["launcher_bat"] = (
                    f"apps/launchers/token_{user['username']}.bat"
                )
            except Exception as exc:  # noqa: BLE001
                # 런처 생성 실패는 등록 흐름을 막지 않는다.
                # 사용자에게는 기존 launch_hint 로 수동 실행 안내가 유효.
                resp["launcher_warning"] = (
                    f"런처 자동 생성 실패: {type(exc).__name__}. "
                    f"수동으로 'python scripts/regenerate_launchers.py' 실행 가능."
                )
        resp["message"] = "기기 등록 완료"
        self.write_json(resp, status=201)


class DeviceItemHandler(BaseHandler):
    """DELETE /api/devices/{id}"""

    def delete(self, device_pk):
        user = self.require_auth()
        if not user:
            return

        try:
            device_pk_int = int(device_pk)
        except ValueError:
            return self.write_error_json("올바르지 않은 기기 ID 입니다", 400)

        db = get_db()
        try:
            row = db.execute(
                "SELECT id, device_id, device_type FROM user_devices "
                "WHERE id=? AND user_id=? AND is_active",
                (device_pk_int, user["user_id"])
            ).fetchone()
            if not row:
                return self.write_error_json("기기를 찾을 수 없습니다", 404)

            deleted_device_type = row["device_type"]

            # 소프트 삭제
            db.execute(
                "UPDATE user_devices SET is_active=FALSE WHERE id=?",
                (device_pk_int,)
            )
            db.execute(
                "INSERT INTO audit_logs "
                "(layer, event_type, details, user_id) VALUES (?,?,?,?)",
                ("operation", "DEVICE_DELETED",
                 json.dumps({
                     "device_id": row["device_id"],
                     "device_type": deleted_device_type,
                 }, ensure_ascii=False),
                 user["user_id"])
            )
            db.commit()
        finally:
            db.close()

        # 토큰 기기였다면 런처(.pyw/.bat) 도 함께 정리한다.
        # regenerate() 는 기존 token_*.pyw / token_*.bat 을 모두 unlink 한 뒤
        # is_active=True 인 totp_token 만 다시 생성하므로,
        # 방금 비활성화된 기기의 런처는 자연스럽게 사라진다.
        # POST 와 동일하게 best-effort: 실패해도 응답은 성공.
        resp = {"message": "기기가 삭제되었습니다"}
        if deleted_device_type == "totp_token":
            try:
                from scripts.regenerate_launchers import regenerate as _regen
                _regen()
                resp["launcher_removed"] = True
                resp["launcher_pyw"] = (
                    f"apps/launchers/token_{user['username']}.pyw"
                )
                resp["launcher_bat"] = (
                    f"apps/launchers/token_{user['username']}.bat"
                )
            except Exception as exc:  # noqa: BLE001
                # 파일 삭제 실패는 DB 삭제 자체를 무효화하지 않는다.
                # 사용자는 수동으로 'python scripts/regenerate_launchers.py' 가능.
                resp["launcher_removed"] = False
                resp["launcher_warning"] = (
                    f"런처 자동 정리 실패: {type(exc).__name__}. "
                    f"수동으로 'python scripts/regenerate_launchers.py' 실행 가능."
                )
        self.write_json(resp)


class DeviceTotpHandler(BaseHandler):
    """GET /api/devices/{id}/totp - 가상 기기의 현재 TOTP 코드 반환"""

    def get(self, device_pk):
        user = self.require_auth()
        if not user:
            return

        try:
            device_pk_int = int(device_pk)
        except ValueError:
            return self.write_error_json("올바르지 않은 기기 ID 입니다", 400)

        db = get_db()
        try:
            row = db.execute(
                "SELECT id, device_id, device_name, device_type, mfa_secret "
                "FROM user_devices "
                "WHERE id=? AND user_id=? AND is_active",
                (device_pk_int, user["user_id"])
            ).fetchone()
        finally:
            db.close()

        if not row:
            return self.write_error_json("기기를 찾을 수 없습니다", 404)

        # 보안 원칙: virtual 타입만 서버가 OTP 를 노출.
        #            mobile/desktop 은 사용자의 Authenticator 앱이 담당.
        if row["device_type"] != "virtual":
            return self.write_json({
                "device_id": row["device_id"],
                "device_name": row["device_name"],
                "hint": "Authenticator 앱에서 현재 6자리 TOTP 코드를 확인하세요",
            })

        code = generate_totp(row["mfa_secret"])
        self.write_json({
            "device_id": row["device_id"],
            "device_name": row["device_name"],
            "otp_code": code,
            # 30초 TOTP 주기상 남은 초 (서버 시간 기준)
            "expires_in": 30 - (int(__import__("time").time()) % 30),
        })


class DeviceOtpRequestsHandler(BaseHandler):
    """
    GET /api/device/otp-requests?device_id=token-XXX

    토큰 기기용 전용 엔드포인트. 별도 실행 프로그램(Tkinter 앱) 이 이 경로를
    3초 주기로 폴링해서:
      (a) 사용자 세션(JWT) 없이도 api_key 만으로 접근 가능하고,
      (b) 자신에게 쌓인 OTP 전송 요청 목록을 가져가며,
      (c) 현재 TOTP 코드(토큰 기기 자신의 mfa_secret 기반) 를 함께 받는다.

    보안:
      api_key 는 사용자 세션이 아니라 "토큰 기기" 스코프의 자격 증명이다.
      탈취되면 OTP 를 열람할 수 있으므로 장비에 저장하고 노출하지 말 것.
    """

    def get(self):
        import time as _t

        auth = self.request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.write_error_json(
                "api_key 가 필요합니다", 401, code="api_key_required")
        api_key = auth[7:].strip()

        req_device_id = self.get_argument("device_id", "")
        if not req_device_id:
            return self.write_error_json(
                "device_id 쿼리 파라미터가 필요합니다", 400,
                code="device_required")

        db = get_db()
        try:
            dev = db.execute(
                "SELECT id, user_id, device_id, device_name, device_type, "
                "       mfa_secret "
                "FROM user_devices "
                "WHERE api_key=? AND is_active",
                (api_key,)
            ).fetchone()

            if not dev:
                return self.write_error_json(
                    "유효하지 않은 api_key 입니다", 401,
                    code="api_key_invalid")

            if dev["device_type"] != "totp_token":
                return self.write_error_json(
                    "이 엔드포인트는 토큰 기기 전용입니다",
                    403, code="not_a_token_device")

            if dev["device_id"] != req_device_id:
                return self.write_error_json(
                    "api_key 와 device_id 가 일치하지 않습니다",
                    403, code="device_mismatch")

            if not dev["mfa_secret"]:
                return self.write_error_json(
                    "이 토큰 기기는 mfa_secret 이 비어 있어 코드 생성 불가",
                    500, code="mfa_secret_missing")

            # pending otp_requests 조회 — 만료 전 + 미소비
            rows = db.execute(
                "SELECT id, work_device_id, ip_address, location, "
                "       requested_at, expires_at "
                "FROM otp_requests "
                "WHERE token_device_pk=? "
                "  AND consumed_at IS NULL "
                "  AND expires_at > now() "
                "ORDER BY requested_at ASC",
                (dev["id"],)
            ).fetchall()

            pending = []
            for r in rows:
                pending.append({
                    "id": r["id"],
                    "work_device_id": r["work_device_id"],
                    "ip_address": r["ip_address"],
                    "location": r["location"],
                    "requested_at": str(r["requested_at"]),
                    "expires_at": str(r["expires_at"]),
                })

            # 조회 즉시 consumed_at 세팅 (at-most-once delivery — 단순 시연용)
            if pending:
                ids = [p["id"] for p in pending]
                placeholders = ",".join(["?"] * len(ids))
                db.execute(
                    f"UPDATE otp_requests SET consumed_at=now() "
                    f"WHERE id IN ({placeholders})",
                    tuple(ids)
                )

                # 기기 last_seen_at 갱신
                db.execute(
                    "UPDATE user_devices SET last_seen_at=now() WHERE id=?",
                    (dev["id"],)
                )
                db.commit()

            current_totp = generate_totp(dev["mfa_secret"])
            expires_in = 30 - (int(_t.time()) % 30)

            self.write_json({
                "device": {
                    "device_id": dev["device_id"],
                    "device_name": dev["device_name"],
                    "user_id": dev["user_id"],
                },
                "current_totp": current_totp,
                "expires_in": expires_in,
                "pending_requests": pending,
                "server_time": int(_t.time()),
            })
        finally:
            db.close()
