# 수동 검증 체크리스트 — ZT 시스템 발표 전 사전 점검

자동 테스트(`scripts\run.bat test` — 179 collected / 176 passed + 3 skipped)는
백엔드 API + DB + 결정 엔진 회귀까지만 보장한다.
이 문서는 자동이 닿지 못하는 영역 — **React UI 동작 / 브라우저 UX / 페르소나 흐름 /
운영 모드 풀 사이클** — 의 발표 전 사전 점검 항목을 정리한다.

작성 기준: 2026-04-29. `static/index.html` 라우트와 conftest 시드(7명) 기준.

---

## 사전 준비

- 이 체크리스트를 시작하기 전 다음 상태를 보장한다.

```
□ PostgreSQL 서비스 가동 (운영 zerotrust 또는 시연용)
□ scripts\run.bat 실행 → "서버 8000 포트 listen" 메시지 확인
□ 브라우저 캐시 무효화 (Ctrl+Shift+R) — index.html 의 no-cache 메타가 있으나 안전 차원
□ 토큰 단말 런처 1개 이상 더블클릭 (예: token_admin_lee.pyw, token_detective_kim.pyw)
□ (선택) psql 또는 DBeaver 로 zerotrust DB 연결 — audit_logs 실시간 모니터용
□ 시계 정확 (TOTP 1분 단위 동기화 필수)
```

검증 대상 라우트(해시):
`#login`, `#dashboard`, `#case-list`, `#case-detail/{id}`, `#admin`, `#audit-log`, `#settings`

---

## 1. 운영 모드 풀 사이클 — 시연 환경 자체의 검증

자동 테스트는 `zerotrust_test` DB 만 건드리고 운영 부팅 경로(`scripts\run.bat`) 는
직접 실행하지 않는다. 발표 환경의 안정성은 사람이 한 번 통과시켜야 한다.

### 1.1 깨끗한 부팅
```
□ scripts\run.bat 실행 — 마이그레이션 014 까지 적용 메시지 출력
□ "wipe completed" 메시지 출력 (운영 DB 정리 확인 — 시연용일 때만)
□ "seed completed (7 users / 15 resources)" 출력
□ 8000 포트 listen 메시지 출력
□ http://localhost:8000/healthz 응답 200 + JSON {"ok": true}
□ http://localhost:8000/readyz 응답 200 + db: "ok"
```

### 1.2 시드 무결성
```
□ http://localhost:8000 진입 → 로그인 화면 자동 노출
□ 7명 시드 사용자 중 admin_lee, detective_kim, patrol_jung 의 trust 가
  각각 95 / 85 / 40 (psql 또는 /api/admin 패널에서 확인)
□ patrol_jung.violation_count = 5
```

**실패 단서**: 마이그레이션 메시지가 "OK" 가 아니라 traceback 으로 끝나면
`migrations/0NN_*.sql` 의 IF NOT EXISTS / OR REPLACE 누락 의심. 두 번째 실행해도 같은
오류가 나야 (멱등 원칙) 한다.

---

## 2. 페르소나 1 — detective_kim (담당자 정상 흐름)

**전제**: trust=85, role=user, 담당 카테고리 = 강력범죄.
**증명할 것**: ZT 가 정상 사용에 *방해되지 않음*.

### 2.1 로그인 + MFA
```
□ #login 화면에서 username=detective_kim / password=password123 입력
□ device_id 필드는 자동(또는 표시) → "registered-001" 가 채워지는지 확인
□ location 입력 = "본청"
□ 1차 응답 → mfa_required=true, OTP 입력 화면 전환
□ 토큰 단말(token_detective_kim) 에서 6자리 OTP 확인
□ OTP 입력 → 세션 발급 + #dashboard 자동 이동
```
실패 단서: OTP 가 30초 이내인데 거부되면 시계 동기화 또는 마이그레이션 011/012
(MFA 시드) 점검.

### 2.2 담당 자료 조회
```
□ 사이드바 "사건 목록" 클릭 → #case-list 진입
□ 본인 담당 사건 1개 이상 표시 (강력범죄 카테고리)
□ 사건 카드 클릭 → #case-detail/{id} 진입
□ 결정 배너: "허용" (level 1~2)
□ 점수 막대 4축 표시 — Object/Environment/Anomaly/Fitness
□ Fitness 음수(담당자 -30 가산) 가 시각적으로 확인됨
```

### 2.3 비담당 고민감 자료 시도
```
□ #case-list 에서 다른 카테고리(예: audit) 사건 클릭 시도
□ 응답: 등급에 따라 ADMIN_APPROVAL 요구 또는 DENY 배너
□ 한글 거부 메시지가 깨지지 않고 명확히 표시
□ 콘솔 에러(F12 Console) 0건
```

**해당 자동 테스트**: `tests/scenarios/test_smoke.py::TestSmokeResourceAccess::test_detective_lists_assigned_cases`
— 단, UI 렌더링까지는 검증하지 않음.

---

## 3. 페르소나 2 — admin_lee (관리자 승인 패널)

**전제**: trust=95, role=admin (또는 superadmin).
**증명할 것**: 관리자 권한 화면이 의도대로 분기되고, 자기-승인이 차단된다.

### 3.1 관리자 화면 진입
```
□ admin_lee 로그인 + MFA 통과
□ 사이드바에 "관리자" 항목 노출 (일반 사용자엔 미노출 비교)
□ #admin 클릭 → AdminPage 렌더링
□ "감사 로그" 항목도 사이드바에 노출 → #audit-log 진입 가능
```

### 3.2 승인 대기 패널
```
□ 다른 사용자(예: detective_kim) 가 등급 5 자료 시도해 ADMIN_APPROVAL 발생시킨 상태
□ admin_lee 의 #admin 화면에 해당 요청 카드 노출
□ 사용자명 / 자원명 / 점수 / 시각 표시 정확
□ "승인" 버튼 클릭 → 200 + 카드 사라짐 + 토스트 "승인 완료"
□ 같은 화면 새로고침해도 처리된 항목은 다시 안 나옴 (멱등)
```

### 3.3 자기-승인 차단
```
□ admin_lee 가 본인 명의로 등급 5 자료 시도
□ 본인 #admin 패널에 본인 요청이 보임
□ 본인이 본인 요청 "승인" 시도 → 403 / SELF_ACTION_BLOCKED
□ 한글 에러 토스트 표시
□ deputy_han 로 같은 요청은 정상 승인됨
```

### 3.4 감사 로그 화면
```
□ #audit-log 진입 → 최근 이벤트 목록
□ 필터 — 사용자명 / 이벤트 유형 / 기간 — 동작 확인
□ append-only 표시(편집·삭제 버튼 없음) 시각적 확인
□ deputy_han 로 같은 화면 접근해도 동일 권한 동작 (deputy_admin 권한)
```

**해당 자동 테스트**:
`tests/scenarios/test_security_p0.py::test_self_approval_blocked`,
`tests/scenarios/test_security_p2.py::test_deputy_admin_can_filter_access_logs_by_user`.

---

## 4. 페르소나 3 — patrol_jung (의심 계정 게이트)

**전제**: trust=40, violation_count=5, 신규/의심 계정 시뮬레이션.
**증명할 것**: 위험 계정의 로그인 자체가 admin 게이트로 보호된다.

### 4.1 admin 게이트
```
□ #login 에서 patrol_jung 입력
□ 1차 응답 → "관리자 승인 대기" 또는 "신규/의심 계정 게이트" 메시지
□ #dashboard 진입 안 됨 — 게이트 화면에 머무름
□ admin_lee 다른 브라우저에서 patrol_jung 의 로그인 승인
□ patrol_jung 화면 자동 또는 새로고침 시 정상 진행
```

### 4.2 게이트 통과 후 접근 제한
```
□ patrol_jung 정상 진입 후 등급 4 이상 자원 시도
□ 결정 배너: DENY 또는 ADMIN_APPROVAL (낮은 trust 반영)
□ 4축 점수 막대에서 fitness 음수가 작음 / object 양수가 큼 시각 확인
```

**해당 자동 테스트**:
`tests/scenarios/test_smoke.py::TestSmokeLogin::test_patrol_jung_blocked_by_admin_gate`,
`tests/scenarios/test_security_p0.py::test_new_account_admin_gate`.

---

## 5. React UI 공통 동작 — 라우팅·세션·오버레이

페르소나와 무관하게 SPA 자체가 깨지면 안 되는 항목.

### 5.1 해시 라우팅
```
□ #dashboard, #case-list, #admin, #audit-log, #settings 직접 입력 시 정상 렌더
□ 미인증 상태에서 위 라우트 직접 입력 → #login 으로 자동 전환
□ 권한 없는 사용자가 #admin 직접 입력 → DashboardPage 로 fallback (URL 은 #admin 유지)
□ #case-detail/{유효_id} 새로고침 후에도 같은 사건 유지
□ #case-detail/{없는_id} → 빈 상태 또는 에러 처리 (백색 화면 금지)
```

### 5.2 세션 만료 + 재인증
```
□ 로그인 후 SessionTimerBadge 가 남은 시간 표시
□ idle 타임아웃 도달 시 SessionExtendModal 자동 노출
□ "연장" 클릭 → 정상 갱신 + 모달 닫힘
□ "로그아웃" 클릭 → 토큰 무효화 + #login 자동 전환
```

### 5.3 동시 로그인 오버레이
```
□ 동일 계정으로 두 번째 브라우저(또는 시크릿 창) 로그인
□ 첫 번째 브라우저에 ConcurrentReauthOverlay 자동 노출
□ 두 세션 모두 재인증 요구
□ 한쪽 OTP 재인증 → 그쪽만 활성, 다른쪽은 잠김 상태 유지
```

### 5.4 단말 설정
```
□ #settings 진입 → DeviceSettingsPage 렌더링
□ 본인 단말 목록 표시 (registered/token 분리)
□ 단말 등록·해제 버튼 동작 (자동 테스트 없음 — 수동 필수)
```

---

## 6. UX 점검 — 한글·에러·반응형

발표 청중이 즉시 보는 영역. 자동 테스트가 절대 못 잡는다.

### 6.1 한글·메시지
```
□ 모든 페이지의 한글 깨짐 0건
□ 에러 메시지가 영문 코드만 노출되지 않고 한글 설명 동반
  - SELF_ACTION_BLOCKED → "본인 요청은 본인이 승인할 수 없습니다" 류
  - IMMEDIATE_BLOCK → "즉시 차단" + 룰 이름
  - ADMIN_APPROVAL → "관리자 승인 대기"
□ 빈 상태 화면(사건 0개 등) 한글 안내 표시
```

### 6.2 시각적 자연스러움
```
□ 발표 해상도(1920x1080 또는 1366x768) 에서 사이드바 + 본문 그리드 깨짐 없음
□ Tailwind CDN 로딩 실패 시 스타일 미적용 화면이 잠깐이라도 보이는지 확인
□ 점수 막대 4축이 모바일 좁은 화면에서도 잘리지 않음
□ 다크모드 가정 안 함(현재 미지원) — 라이트 화면만 가정
```

### 6.3 결정 배너
```
□ ALLOW(level 1) — 초록 / VIEW_ONLY(2) — 청록 / REAUTH(3) — 노랑 /
  ADMIN_APPROVAL(4) — 주황 / DENY(5) — 빨강 색상이 의도대로
□ confidence 낮을 때 배너에 "검증 필요" 부가 표시 (decision_engine.py:67-73 의도)
```

---

## 7. 시연 흐름 리허설 — PRESENTATION_DEMO.md 와 연계

PRESENTATION_DEMO.md 의 시연 1~6 을 **실제 시연 환경에서 1회 통과**시켜
타이밍과 UI 반응을 확인한다. 자동 테스트와 별개로 매번 발표 전 1회.

```
□ 시연 1: Impossible Travel — 두 번째 요청에서 즉시 IMMEDIATE_BLOCK 배너
□ 시연 2: 자기-승인 차단 — admin_lee 본인 승인 시도 토스트 + deputy_han 우회
□ 시연 3: 감사 로그 무결성 — psql 직접 UPDATE/DELETE 거부 메시지
□ 시연 4: Break-Glass + 사후심사 — trust 95 → 65, violation +1 시각 확인
□ 시연 5: 동시 로그인 잠금 — 양쪽 잠금 + 한쪽만 재인증
□ 시연 6: 사용자 하드 삭제 + 감사 로그 보존 — audit_logs.user_id 보존
```

각 시연은 30~60초 내. 막힘 없이 흐르는지 + 청중이 화면을 보고 즉시 이해할 수
있는지 확인.

---

## 8. 발표 전 정리

```
□ scripts\run.bat 한 번 더 실행 → 시연 중 누적된 audit_logs 정리 + 시드 복원
□ 모든 브라우저 탭 닫기, 토큰 단말 런처 1~2개만 남기기
□ 콘솔 창 정리 (긴 traceback 노출 방지)
□ 화면 공유 사전 테스트 (특히 폰트 크기, 배경색)
```

---

## 알려진 한계 — 이 체크리스트가 *못 잡는* 것

정직하게 적어둔다.

- **시각 회귀** (예: 색상이 미묘하게 바뀜) — 사람 눈이 매번 비교하지 않으면 못 잡음.
  Phase 2 에서 Playwright screenshot diff 도입 검토.
- **장시간 idle 동작** — TTL/만료를 실시간으로 기다려 검증하지 않음. 자동 테스트의
  `test_pending_reauth_expires_after_timeout` 가 일부 커버.
- **다른 시계 환경** — 발표 PC 가 KST 가 아닌 환경일 때의 TZ 함정. ITEM 9 회귀
  테스트로 일부 커버되나 UI 표시 시각은 별도 확인 필요.
- **네트워크 지연** — 로컬에서만 테스트하면 잘 안 보임. 시연 PC 의 실제 환경에서
  최소 한 번 통과 권장.

---

## 갱신 규칙

- 새 페르소나·라우트·시연이 추가되면 이 문서도 동일 시점에 갱신.
- 자동 테스트로 승격된 항목은 본 체크리스트에서 제거(또는 "자동화됨" 표시).
- 마지막 통과 일자를 발표 전 기록해 두면 회귀 추적이 쉬움.

```
마지막 전체 통과 일자: ____________________
검증자: ____________________
실패 항목: ____________________
```
