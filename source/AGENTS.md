# ZeroTrust 캡스톤 — Codex 작업 가이드

## 1. 프로젝트 정체

- Zero Trust 정책 엔진(인증·인가·감사 통합). 학부 캡스톤.
- 스택: Python 3 (Tornado) + PostgreSQL + React SPA(별도 디렉터리)
- 진입점:
  - `scripts\run.bat` — 운영 시연 (마이그레이션 + wipe + reseed + 서버 기동)
  - `scripts\run.bat test` — pytest (zerotrust_test DB, 2026-04-29 기준 179 collected / 176 passed + 3 skipped / 15 파일 / 약 3분 30초)
- 핵심 모듈: `core/` (정책·점수·결정·BG·세션) / `api/` (Tornado 핸들러) / `security/` (JWT·MFA·secrets) / `migrations/` (forward-only SQL)

## 2. 절대 원칙 (위배되면 작업 중단)

1. **운영 모드 단일** — DB 는 PostgreSQL 전용. 다른 DB 백엔드나 별도 실행 모드 분기를 새로 만들지 말 것 (`config.py:1-7` 명시).
2. **감사 로그 append-only** — `audit_logs` / `sensitive_logs` 의 UPDATE·DELETE 시도 금지. `audit_logs_immutable()` 트리거가 거부하며, 트리거 거부는 트랜잭션 전체를 롤백시킨다.
3. **마이그레이션 forward-only** — 기존 `migrations/0NN_*.sql` 수정 금지. 변경은 다음 번호의 새 파일로(현재 014 까지). down 스크립트 없음.
4. **운영 DB 직접 조작 금지** — TRUNCATE/DROP 직접 실행 금지. 데이터 정리는 `scripts/wipe_traces.py` 또는 테스트 격리(`zerotrust_test`)만 사용.
5. **시드 데이터 의미 보존** — `init_data.py` 의 페르소나(detective_kim trust=85, admin_lee trust=95, patrol_jung trust=40·violation=5)는 시연 시나리오의 전제. 임의로 trust/violation/job_scope 값을 바꾸면 발표 시연이 깨진다.

## 3. 작업 전 점검 순서

새 기능·수정 요청을 받으면 코딩 전:

1. 영향 영역의 모듈을 Read 로 실제 확인 (코드 유추 금지).
2. 관련 테스트(`tests/unit/test_decision_matrix.py`, `tests/scenarios/test_smoke.py`, `test_security_p0.py`, `test_security_p1.py`, `test_infra_sanity.py`) 의 현 동작 확인.
3. 정책·점수 변경이면 `core/scoring_engine.py` 의 "보고서 §7-3 Table 21" 주석 라인을 인용 근거로 보존.
4. DB 스키마 변경이면 새 마이그레이션 파일(다음 번호)로만. `migrations/002_audit_split.sql` 의 RLS·트리거 정책을 깨지 않는지 확인.
5. 변경 후 반드시 `scripts\run.bat test` 통과 확인.

## 4. 인지된 약점 — 손대는 방식 주의

### 점수 임계값 경험적 보정 부재
`scoring_engine.py` 의 모든 가중치(sens 등급별 +10~+50 / 야간 +15 / 미등록 단말 +20 / 비허용 위치 +20 / 담당 -30 / 부서 -15 / 직무 -20 / 사전승인 -15)는 **보고서 설계 추정치**다. 실증 ROC 보정이 안 됐다.

- 새 가중치를 단언적으로 정하지 말 것.
- 변경이 불가피하면 (a) 보고서 §7-3 근거 인용 또는 (b) "임계값 외부화 후 운영 데이터로 보정 예정" 표시.
- 결정 경계(0/25/50/75/90) 변경은 시연 시나리오의 의도된 결과를 바꾸므로 매우 신중.

### 가용성 SPOF (Phase 2 영역, 캡스톤 발표 전엔 손대지 말 것)
PG 단일 / Tornado 단일 / JWT 회수는 sessions.is_active 로만 보완 / 마이그레이션 단방향 / run.bat wipe 가 운영에 묶여 있음 / 트리거 거부의 트랜잭션 롤백.

발표 전 작업은 정책 모델·결정 엔진·테스트 보강에 한정. 위 영역은 발표 후 Phase 2.

### Confidence-aware 결정 (이미 구현됨)
`core/decision_engine.py:67-73`. 경계 거리 + 4축 분산 + anomaly + travel inactive 종합으로 confidence 산출. 임계값 0.85. **이 로직은 작동 중이며, 새로 비슷한 보정 레이어를 추가하지 말 것.**

## 5. 코드 작성 기준

- **사실 확인 우선** — 모듈 동작·함수 시그니처·DB 컬럼은 Read/Grep 으로 직접 확인. 추측한 채로 단언 금지.
- **변경 격리** — 한 PR/커밋은 한 가지 관심사. scoring 변경과 감사 로그 변경 동시 X.
- **테스트가 먼저 깨진다면 그 자체가 신호** — 기존 테스트의 의도를 이해한 뒤 깨야 한다. 무비판적 수정 금지.
- **마이그레이션 작성** — 멱등성 보장(`IF NOT EXISTS` / `OR REPLACE`). 트리거·RLS 정책 충돌 사전 검사.
- **로깅** — 사용자가 직접 식별 가능한 원본 민감 정보는 `sensitive_logs` 로, 결정·정책 발동은 `audit_logs` 로, 앱 트레이스는 `operation_logs` 로 (3계층 분리 유지).

## 6. 응답·보고 스타일 (사용자 선호 반영)

- 한국어. 단정적 표현 회피, 근거/판단 기준을 함께 제시.
- 불확실하면 "확실하지 않음", "추측입니다", "검증 필요" 로 명시. 모르는 걸 만들어내지 말 것.
- 작업 보고는 다음 3구간으로 구조화:
  1. **변경 사항** — 무엇을 어디에 (파일:라인)
  2. **근거** — 왜 이 방식 (보고서 §, 기존 테스트, 인용 라인)
  3. **검증** — 실행한 테스트 결과 / 수동 확인 절차
- 자동 commit·push 금지. 사용자가 명시적으로 요청할 때만.
- 시연 시나리오에 영향 가는 변경은 미리 그 영향을 구체적으로 짚어 알릴 것.

## 7. 검증 체크리스트 (변경 완료 전 필수)

- [ ] `scripts\run.bat test` 통과
- [ ] 마이그레이션이라면 `python scripts/run_migrations.py` 멱등 동작 확인 (두 번 실행해도 에러 없음)
- [ ] `git diff --stat` 으로 의도하지 않은 파일 변경 없는지 확인
- [ ] 시연 영향 가는 변경이라면 페르소나별 핵심 흐름 1회 수동 검증
  - detective_kim: 담당 카테고리 자료 정상 접근
  - admin_lee: 관리자 승인 패널 동작
  - patrol_jung: 의심 계정 게이트 동작
- [ ] 새 기능이면 그에 대응하는 테스트 추가 (단위 또는 시나리오)

## 8. 막히면

- 정책 의도가 모호하면 사용자에게 보고서 §7-3 또는 시연 시나리오 의도를 먼저 묻기.
- 코드 동작이 헷갈리면 추측 답변 대신 "Read 로 확인 필요" 라고 명시.
- 이 가이드와 충돌하는 사용자 지시가 있으면 충돌을 명시하고 사용자에게 결정권 넘기기.
