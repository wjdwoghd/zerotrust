-- 021: 담당 사건 등록 요청 플로우
-- 사용자/관리자 담당 사건 추가 요청, 관리자 OTP 요구, 요청자 OTP 인증, 최종 승인/반려 추적

CREATE TABLE IF NOT EXISTS case_assignment_requests (
    id                  BIGSERIAL PRIMARY KEY,
    requester_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_id         BIGINT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    reviewer_role       TEXT NOT NULL DEFAULT 'admin',
    status              TEXT NOT NULL DEFAULT 'pending_admin',
    reason              TEXT,
    otp_required_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    otp_required_at     TIMESTAMPTZ,
    otp_verified_at     TIMESTAMPTZ,
    final_approved_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    final_approved_at   TIMESTAMPTZ,
    rejection_reason    TEXT,
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_case_assignment_status
        CHECK (status IN ('pending_admin','otp_required','otp_verified','approved','rejected','cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_case_assignment_requests_status
    ON case_assignment_requests(status, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_case_assignment_requests_requester_resource
    ON case_assignment_requests(requester_id, resource_id);

CREATE OR REPLACE FUNCTION touch_case_assignment_requests_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_case_assignment_requests_updated_at ON case_assignment_requests;
CREATE TRIGGER trg_case_assignment_requests_updated_at
BEFORE UPDATE ON case_assignment_requests
FOR EACH ROW EXECUTE FUNCTION touch_case_assignment_requests_updated_at();
