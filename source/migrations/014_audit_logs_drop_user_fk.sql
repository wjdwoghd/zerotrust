-- 014_audit_logs_drop_user_fk.sql
--
-- audit_logs.user_id 의 FK 제약을 제거한다.
--
-- 배경 / 충돌 메커니즘:
--   002 마이그레이션은 audit_logs 에 BEFORE UPDATE OR DELETE 트리거
--   (trg_audit_logs_no_update -> audit_logs_immutable()) 를 걸어 모든
--   수정·삭제를 거부한다 — append-only 무결성.
--
--   같은 테이블의 user_id 컬럼은 users.id 로의 FK 였고 ON DELETE SET NULL
--   정책을 갖고 있었다. PostgreSQL 은 users 행 DELETE 시 audit_logs.user_id
--   를 NULL 로 갱신하는 내부 UPDATE 를 발행하는데, 그 UPDATE 가 위 트리거에
--   의해 거부되어 사용자 하드 삭제 자체가 항상 500 으로 실패했다.
--
-- 정책 변경:
--   audit_logs 는 "그 시점에 어떤 user_id 가 어떤 행위를 했다" 는 사실
--   스냅샷이다. 살아있는 사용자에 대한 참조 무결성이 본질이 아니다.
--   따라서 FK 를 제거하고 user_id 는 단순 정수 컬럼으로 둔다.
--   - 삭제된 사용자의 user_id 도 audit_logs 에 그대로 남아 역사적 사실
--     기록 역할을 유지한다 (dangling integer 가 의도된 동작).
--   - 사용자별 활동 조회는 별도 SELECT 로 처리 (FK JOIN 의존 코드 없음 —
--     api/audit_handler 검증 완료).
--
-- 영향:
--   - 사용자 하드 삭제 흐름이 정상 동작.
--   - audit_logs append-only 트리거 자체는 그대로 유지됨 (변조 차단 보존).
--
-- 관련 회귀:
--   tests/scenarios/test_security_p1.py 의 사용자 삭제 시나리오가 본
--   마이그레이션 적용 후 'success path' 로 의미가 반전된다.

BEGIN;

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;

COMMIT;
