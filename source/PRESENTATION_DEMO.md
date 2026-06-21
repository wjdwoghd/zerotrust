# 발표 시연 스크립트 — ZT 시스템 라이브 데모

기본 시연 1~6은 30~60초 내외. "공격 → 시스템 반응 → 감사 로그" 3단 구조.
아래의 "내부자 공격 재현형 상세 시나리오"는 실제 공개 사례의 공격 패턴을
합성 데이터 위에서 재현하는 8~12분 발표용 확장판이다.

## 사전 준비 (발표 5분 전)

```
1. PostgreSQL 서비스 가동 확인
2. scripts\run.bat  → 깨끗한 시드 + 서버 8000 포트 기동
   (또는 PowerShell: scripts\run.ps1)
3. 토큰 기기 런처 더블클릭 (token_admin_lee.pyw 등)
4. 브라우저로 http://localhost:8000 진입
5. (선택) DB 뷰 별도 창: psql -U ztuser -d zerotrust 로 audit_logs 실시간 모니터
```

---

## 내부자 공격 재현형 상세 시나리오 (8~12분)

### 공통 운영 원칙

- 실제 유출 행위는 재현하지 않는다. 외부 메신저/메일 전송 대신 합성 사건 자료의
  조회, 다운로드 버튼, 승인 요청, 감사 로그만 사용한다.
- 브라우저 A: 공격자 또는 정상 사용자. 브라우저 B: `admin_lee` 또는 `deputy_han`.
- 화면 오른쪽 또는 별도 창에 `#audit-log` 를 열어 `ACCESS_DECISION`,
  `IMMEDIATE_BLOCK`, `ADMIN_APPROVAL_*`, `SELF_ACTION_BLOCKED`,
  `BREAK_GLASS_*` 이벤트를 즉시 보여준다.
- 가용성 메시지는 매 시나리오마다 반드시 같이 말한다. "막는다"만 보여주면
  현장 업무가 멈추는 시스템처럼 보이므로, 정당한 경로가 어떻게 열리는지도 보여준다.

### 사례 A — 수사정보 유출형: 이선균 수사정보 유출 의혹 패턴

**공개 사례 요지**: 2024년 인천경찰청 소속 간부급 경찰관이 배우 이선균 씨
마약 수사 관련 내부 보고서 유출 혐의로 체포됐고, 경찰은 이후 수사자료
워터마크·DLP·징계 강화 방안을 발표했다.

**공격 재현 목표**: "업무 계정은 맞지만 해당 수사 라인이 아닌 경찰관이
마약/조직범죄 내사 자료에 접근해 외부 유출을 시도한다"를 재현한다.

**사용 계정/자료**
- 공격자: `officer_choi / password123`  
  교통과, trust 70, `job_scope=["traffic"]`, 등록기기 `registered-006`
- 표적 자료: `2026-DRG-0022 마약사범 내사 자료` 또는
  `2026-ORG-0015 조직범죄 수사 자료`  
  등급 4, `requires_approval=true`, 강력범죄수사대/마약·조직범죄 태그
- 정상 사용자 대비: `detective_kim / password123`  
  강력범죄수사대, trust 85, `job_scope=["violent_crime","drug","organized_crime"]`

**시연 단계**
1. `officer_choi` 로 본청, `registered-006` 에서 정상 로그인한다.
2. 사건 목록에서 등급 4 자료를 열어 본다.
3. 결정 배너가 `관리자 승인 후 허용` 또는 이에 준하는 제한 상태임을 보여준다.
4. "승인 요청 보내기"를 누른다. 사유는 의도적으로 모호하게 둔다:
   `언론 문의 대응을 위해 확인 필요`.
5. 브라우저 B에서 `admin_lee` 로 관리자 패널을 열고 승인 대기 카드를 확인한다.
6. `officer_choi` 요청을 반려한다. 이유:
   `교통과 업무 범위와 무관한 마약 내사 자료`.
7. 같은 자료를 `detective_kim` 이 정당한 사건 공조 사유로 요청한다.
8. `admin_lee` 가 먼저 "열람 전용 승인"을 선택한다. 다운로드 버튼이 막힌 채
   워터마크 열람만 가능한지 확인한다.
9. 필요하면 동일 요청을 다시 만들거나 다른 자료에서 "다운로드 허용 승인"을 선택해,
   관리자 승인 플래그가 열람/다운로드 권한을 분리한다는 점을 보여준다.

**보안 포인트**
- 등급 4 이상 + 비담당 + 타부서 접근은 `check_admin_approval_required()` 로
  강제 L4가 된다.
- 접근만으로 대기열이 쌓이지 않고, 사용자가 명시적으로 "승인 요청"을 눌러야
  `approvals` 행이 생긴다. 우발적 탐색과 실제 승인 요청을 구분한다.
- `download_allowed=false` 승인은 열람 전용이다. 보고서 확인은 가능하지만
  파일 반출은 막는다.

**가용성 포인트**
- `officer_choi` 의 교통 자료 접근은 계속 가능하다.
- `detective_kim` 처럼 직무 연관성이 있는 사용자는 완전 차단이 아니라 승인 절차로
  업무를 계속할 수 있다.

**선택 고위험 변형(API 보조 시연)**
- 동일 토큰으로 `X-Device-Id` 를 미등록 값, `X-Location` 을 `비허용위치`,
  요청 경로를 `/api/resources/cases/{id}/file` 로 바꾸면
  `HIGH_RISK_DOWNLOAD` 즉시차단을 보여줄 수 있다.
- 이 변형은 UI에서 기기 변경을 지원하지 않으므로 curl/Postman 보조 장면으로만 쓴다.

### 사례 B — 호기심/스토킹형 개인정보 조회: 유명인 주소 무단 조회 패턴

**공개 사례 요지**: 2024년 충남 소속 경찰관이 경찰 내부망으로 유명 가수의
주소를 조회하고 거주지를 찾아간 사건이 보도됐다. 핵심은 권한 있는 내부망
사용자가 업무 목적 없이 개인정보를 조회한 것이다.

**공격 재현 목표**: "순찰 업무 계정이 피해자 진술서 또는 개인정보 포함 자료를
업무 목적 없이 조회하려 한다"를 재현한다.

**사용 계정/자료**
- 공격자: `patrol_jung / password123`  
  생활안전과, trust 40, violation 5, 토큰 기기 없음, 관리자 로그인 승인 게이트 대상
- 표적 자료: `2026-VCT-0108 개인정보 포함 피해자 진술서`  
  등급 3, 강력범죄수사대, `job_tags=["violent_crime"]`
- 정상 업무 자료: `2026-PTR-0001 생활안전과 순찰 편성안`  
  등급 2, 생활안전과, `job_tags=["patrol"]`

**시연 단계**
1. `patrol_jung` 로 `은평서`, `registered-007` 에서 로그인한다.
2. 즉시 대시보드로 들어가지 않고 "관리자 승인 대기" 화면에 머무는지 보여준다.
3. 브라우저 B에서 `admin_lee` 가 관리자 패널의 로그인 승인 요청을 확인한다.
4. 첫 번째는 반려한다. 메시지:
   `의심 계정은 관리자 승인 없이 내부망 접근 불가`.
5. 다시 로그인 요청을 만들고, 이번에는 "현장 순찰 편성 확인"이라는 사유로 승인한다.
6. `patrol_jung` 이 `2026-PTR-0001 생활안전과 순찰 편성안` 을 조회한다.
   정상 업무 자료는 통과해야 한다.
7. 이어서 `2026-VCT-0108 개인정보 포함 피해자 진술서` 를 조회한다.
8. 결정 배너, 마스킹/워터마크, 접근 로그를 보여준다. 결과가 재인증/열람전용/제한
   중 어느 쪽으로 보이더라도, 핵심은 "개인정보 자료 접근이 기록되고 제한된다"이다.

**보안 포인트**
- trust 40 + violation 5 계정은 로그인 자체가 관리자 승인 게이트를 통과해야 한다.
- 토큰 기기가 없는 의심 계정은 일반 MFA 경로로 슬쩍 통과할 수 없다.
- 비담당 개인정보 자료 접근은 `access_logs` 와 `audit_logs` 에 남는다.

**가용성 포인트**
- 의심 계정이라도 모든 업무가 영구 차단되는 것은 아니다. 관리자가 맥락을 확인하면
  생활안전과 정상 자료는 열람 가능하다.
- "위험 계정 격리"와 "현장 업무 지속"을 동시에 보여준다.

### 사례 C — 개인정보 판매형: 교통사고 피해자 연락처 판매 패턴

**공개 사례 요지**: 미국 워싱턴 D.C. MPD 전직 경찰관은 비공개 교통사고
보고서의 피해자 연락처를 조회해 외부 브로커에게 넘긴 혐의로 2024년 유죄
평결을 받았다. DOJ 발표에는 피해자 정보 2,316건이 언급된다.

**공격 재현 목표**: "교통과 사용자의 첫 조회는 정상 업무지만, 짧은 시간 반복
조회/다운로드는 판매 또는 대량 수집 징후로 감사 대상이 된다"를 재현한다.

**사용 계정/자료**
- 사용자: `officer_choi / password123`
- 정상 자료: `2026-TRF-0042 교통사고 수사 보고서`,
  `2026-TRF-0100 교통과 중대사고 디지털 증거`,
  `2026-ADM-0200 교통과 특별 행정처분 기록`

**시연 단계**
1. `officer_choi` 로 본청, `registered-006` 에서 로그인한다.
2. `2026-TRF-0042` 를 열고 정상 업무 접근이 허용되는지 보여준다.
3. 다운로드 버튼이 허용되는 경우 한 번 다운로드한다. 이 장면은 "업무상 반출"이다.
4. 5분 안에 여러 교통 자료를 반복 조회한다. 가능하면 5회 이상 반복해
   `HIGH_FREQUENCY` 주의 신호를 만든다.
5. 감사 로그 또는 접근 로그에서 같은 사용자·같은 시간대의 접근이 누적되는지 보여준다.
6. 발표 시간이 충분하면 API로 `/api/admin/access-logs/{id}/review` 에
   `label=false_negative` 를 넣어 사후 라벨링을 수행한다.
7. 사용자 trust 가 -10, violation +1 되는 흐름을 설명한다.

**보안 포인트**
- 정상 업무 접근은 곧 무감사 접근이 아니다. 모든 접근은 `access_logs` 와
  `ACCESS_DECISION` 으로 남는다.
- 5분 내 5회 이상은 고빈도 접근 주의, 10회 이상은 고빈도 접근 위험으로 점수에
  반영된다.
- 사후 라벨링은 `false_positive`, `false_negative`, `justified` 로 분리되고,
  미탐(`false_negative`)이면 trust -10 + violation +1 이 트리거로 적용된다.

**가용성 포인트**
- 교통과 담당자가 교통사고 자료를 조회하는 정상 행위는 막지 않는다.
- 위험은 "한 번 조회"가 아니라 반복성, 다운로드, 비업무 맥락, 사후 판단으로
  점진적으로 커진다.

### 사례 D — 특권 내부자 수사대상 통보형: MPD 정보부서 유출 패턴

**공개 사례 요지**: 전 MPD 정보부서 감독관 Shane Lamond는 수사 대상자에게
수사 기밀과 체포영장 정보를 알려준 혐의로 2024년 유죄가 인정됐고, 2025년
18개월형이 보도됐다. 핵심은 고권한 내부자가 자기 판단으로 민감 수사 정보를
외부 대상자에게 흘린 것이다.

**공격 재현 목표**: "관리자 또는 고권한 사용자가 등급 5 자료에 접근하려 하고,
자기 승인 또는 긴급 우회로 통제를 피하려 한다"를 재현한다.

**사용 계정/자료**
- 고권한 사용자: `admin_lee / password123`, trust 95
- 견제자: `deputy_han / password123`
- 표적 자료: `2026-TOP-0003 극비 수사 첩보 보고서` 또는
  `2026-VIP-0001 VIP 관련 극비 보고서`

**시연 단계**
1. `admin_lee` 로 등급 5 자료를 연다.
2. 관리자 승인 요청이 필요한 상태에서 `admin_lee` 본인이 승인하려 한다.
3. `403 / SELF_ACTION_BLOCKED` 토스트와 감사 로그를 확인한다.
4. `deputy_han` 으로 같은 요청을 열람 전용 승인한다.
5. 긴급 상황 변형을 보여준다. `admin_lee` 가 등급 5 자료에서
   Break-Glass 를 발동한다.
6. OTP와 10자 이상 정당화 사유를 넣어 발동한다.
7. 자료 열람/다운로드가 즉시 가능해지는지 확인한다.
8. `deputy_han` 이 Break-Glass 탭에서 `unjustified` 로 사후 리뷰한다.
9. `admin_lee` trust 95 → 65, violation +1 을 보여준다.

**보안 포인트**
- 관리자도 자기 승인·자기 리뷰를 할 수 없다.
- Break-Glass 는 "우회 허용"이지만 "무감사 허용"이 아니다.
- 부당 판정 시 trust -30과 violation +1로 페널티가 크다.

**가용성 포인트**
- 긴급 상황에서는 결재 대기 때문에 현장 대응이 멈추지 않는다.
- 대신 사후 리뷰와 페널티가 있어 남용 비용이 높다.

### 사례 E — 흔적 삭제형: 감사 로그 변조 시도

**공개 사례 공통점**: 내부자 사건은 접근 자체보다 사후 추적 가능성이 중요하다.
감사 로그를 지울 수 있다면 모든 정책 판단의 증거가 사라진다.

**공격 재현 목표**: "공격자가 DB 직접 접근으로 자신의 흔적을 바꾸거나 지우려
해도 append-only 트리거가 차단한다"를 재현한다.

**시연 단계**
1. 앞선 사례 중 하나를 실행해 `audit_logs` 에 이벤트를 만든다.
2. psql 창에서 다음을 실행한다.
   ```sql
   UPDATE audit_logs SET event_type='TAMPERED' WHERE id=1;
   ```
3. `audit_logs is append-only` 오류를 보여준다.
4. 다음도 실행한다.
   ```sql
   DELETE FROM audit_logs WHERE id=1;
   ```
5. 동일하게 거부되는지 확인한다.

**보안 포인트**
- 변조 방지는 애플리케이션 버튼 숨김이 아니라 PostgreSQL 트리거다.
- 공격자가 앱을 우회해 SQL을 직접 실행해도 UPDATE/DELETE가 거부된다.

**가용성 포인트**
- 운영 시연 초기화는 직접 TRUNCATE가 아니라 `scripts\run.bat` 또는
  `scripts/wipe_traces.py` 경로를 사용한다. 발표 환경은 깨끗하게 만들 수 있지만,
  일반 운영 중 감사 로그 무결성은 유지된다.

### 발표 순서 추천

1. 정상 기준선: `detective_kim` 정상 로그인 + 담당 자료 조회.
2. 사례 A: `officer_choi` 의 수사정보 접근 요청 반려, `detective_kim` 의 정당 요청 승인.
3. 사례 B: `patrol_jung` 로그인 게이트 + 정상 순찰 자료 허용 + 개인정보 자료 제한.
4. 사례 C: `officer_choi` 교통자료 정상 접근 + 반복 조회 감사.
5. 사례 D: `admin_lee` 자기승인 차단 + Break-Glass 사후 페널티.
6. 사례 E: `audit_logs` 변조 거부.

**한 줄 결론**: "이 시스템은 내부자를 전부 막는 시스템이 아니라, 업무는 흐르게 두고
업무 목적·기기·위치·민감도·행위·사후 책임을 계속 검증하는 시스템이다."

**공개 사례 출처**
- 이선균 수사정보 유출 의혹: https://en.yna.co.kr/view/AEN20240323002200315
- 경찰 수사정보 유출 방지 대책: https://koreajoongangdaily.joins.com/news/2024-05-09/national/socialAffairs/Police-to-sack-officers-who-leak-mishandle-investigative-details/2042458
- 유명 가수 주소 무단 조회 보도: https://www.allkpop.com/article/2024/06/a-female-police-officer-illegally-accessed-personal-information-on-a-famous-singer-and-visited-the-singers-residence
- MPD 교통사고 피해자 개인정보 판매 사건: https://www.justice.gov/usao-dc/pr/former-mpd-officer-found-guilty-bribery-scheme-sell-personal-identifying-information
- MPD 정보부서 유출 사건: https://www.justice.gov/usao-dc/pr/former-mpd-intelligence-supervisor-guilty-obstructing-investigation-and-making-false

---

## 시연 1 — Impossible Travel 즉시차단 (45초)

**스토리**: "관리자 admin_lee 가 서울 본청에서 로그인했는데, 30초 뒤 부산 IP 로 자원 접근. 세션 탈취가 의심되는 상황."

**시연 단계**:
1. admin_lee 로 본청에서 정상 로그인 + 등급 3 자료 조회 → 통과
2. 두 번째 브라우저 (또는 curl) 에서 같은 토큰 + `X-Location: 지청-부산` + `X-IP-Address: 59.6.31.100` 으로 등급 4 자원 요청
3. **응답**: `403 / IMMEDIATE_BLOCK / impossible_travel`
4. audit_logs 모니터에서 `IMMEDIATE_BLOCK` + `rule="impossible_travel"` 이벤트 즉시 출력 확인

**메시지**: "위치 시그널이 단순 자가신고가 아니라 Haversine 거리 + 임계 속도(800km/h) 로 검증된다. 1분에 본청→부산 이동(약 325km/h… 아니, 19,500km/h) 은 물리적으로 불가능."

**해당 테스트**: `tests/scenarios/test_security_p0.py::test_impossible_travel_immediate_block`

---

## 시연 2 — 자기-승인 차단 (이중감독, 30초)

**스토리**: "관리자가 자기 신청을 본인이 승인하면 이중감독 원칙이 깨진다."

**시연 단계**:
1. admin_lee 로 등급 5 자원 조회 시도 → ADMIN_APPROVAL 요구
2. admin_lee 자신이 `/api/admin/approvals/pending` → 자기 요청 보임
3. admin_lee 가 자기 요청을 승인 시도
4. **응답**: `403 / SELF_ACTION_BLOCKED`
5. deputy_han 로 같은 요청 승인 → 통과

**메시지**: "ZT 의 이중감독은 audit 룰뿐 아니라 코드 단계에서 강제. admin 1인일 때도 부관리자(deputy_admin) 가 동등 권한으로 처리해 교착을 방지."

**해당 테스트**: `tests/scenarios/test_security_p0.py::test_self_approval_blocked`

---

## 시연 3 — 감사 로그 무결성 (30초)

**스토리**: "공격자가 DB 직접 접근으로 자기 흔적을 지울 수 있다면 ZT 가 무의미."

**시연 단계**:
1. 별도 psql 창에서 직접 SQL 실행:
   ```sql
   UPDATE audit_logs SET event_type='TAMPERED' WHERE id=1;
   ```
2. **응답**: `ERROR: audit_logs is append-only (trigger audit_logs_immutable)`
3. ```sql
   DELETE FROM audit_logs WHERE id=1;
   ```
4. **응답**: 동일 거부

**메시지**: "감사 로그 무결성은 애플리케이션 레이어가 아니라 PostgreSQL 트리거로 강제. SQL 직접 접속도 변조 불가. 운영자가 신뢰하는 audit trail."

**해당 테스트**: `tests/scenarios/test_security_p0.py::test_audit_log_update_blocked_by_trigger`, `test_audit_log_delete_blocked_by_trigger`

---

## 시연 4 — Break-Glass 자가발동 + 사후심사 (60초)

**스토리**: "긴급 상황에서 admin이 등급 5 자료를 정상 정책 우회로 접근. 다만 사후 심사가 필수."

**시연 단계**:
1. admin_lee 로 평소처럼 등급 5 자원 시도 → ADMIN_APPROVAL (시간 걸림)
2. 토큰 기기에서 OTP 확인
3. `/api/break-glass/activate` 로 발동 — `scope=broad`, `min_grade=4`, `justification="긴급 사건 X 대응"`, `otp_code=...`
4. 즉시 등급 5 자원 다운로드 통과
5. 30초 후 deputy_han 로 사후심사 → `verdict=unjustified`
6. admin_lee 의 trust_score 변화 확인:
   - 발동 전: 95
   - unjustified 후: 65 (-30 페널티)
7. violation_count 도 +1

**메시지**: "긴급 우회는 막지 않되, 페널티가 비대칭. 정당한 사용은 무비용, 부당한 사용은 trust 30점 손실 + 위반 누적. NIST SP 800-207 §7 emergency access 컨셉 준수."

**해당 테스트**: `tests/scenarios/test_security_p0.py::test_break_glass_unjustified_penalty`

---

## 시연 5 — 동시 로그인 양쪽 잠금 (30초)

**스토리**: "공격자가 토큰 탈취 시도 — 서로 다른 IP 에서 같은 계정 로그인."

**시연 단계**:
1. 브라우저 1: admin_lee 로그인 (IP A) → 정상 사용
2. 브라우저 2 (또는 curl): admin_lee 로 다시 로그인 (IP B)
3. 브라우저 1 에서 다음 요청 시도 → `401 / concurrent_session_detected`
4. 둘 다 재인증 필요. 한쪽만 OTP 재인증해도 그 세션만 활성화, 다른 쪽은 계속 잠김

**메시지**: "동시 접속 자체는 허용 — 모바일 + PC 정상 사용도 있음. 하지만 양쪽 모두 MFA 재인증 후에야 활성화. 공격자는 OTP 토큰을 못 가지므로 자동 차단."

**해당 테스트**: `tests/scenarios/test_security_p0.py::test_concurrent_login_locks_both_sessions`

---

## 시연 6 — 사용자 하드 삭제 + 감사 로그 보존 (40초)

**스토리**: "관리자가 잘못 만든 신규 계정을 삭제. 그 사용자의 활동 기록은 사라지면 안 된다."

**시연 단계**:
1. admin_lee 가 관리자 패널에서 임시 계정 `temp_user` 생성
2. `temp_user` 첫 로그인 (LOGIN_SUCCESS 등 audit 기록 발생)
3. admin_lee 가 `temp_user` 하드 삭제 (DELETE /api/admin/users/{id})
4. **응답**: `200 OK` (마이그레이션 014 적용 후)
5. `users` 테이블에서 `temp_user` 사라짐 확인
6. `audit_logs` 에 `temp_user` 의 user_id 가 그대로 남아있는지 SQL 확인:
   ```sql
   SELECT event_type, user_id FROM audit_logs WHERE user_id = {temp_user_id};
   ```
   → 행이 그대로 있음. user_id 도 보존.

**메시지**: "감사 로그는 '그 시점의 사실 기록'이지 '살아있는 사용자 참조'가 아니다. 사용자가 사라져도 그가 한 행위의 기록은 영원히 남는다. NIST SP 800-207 §6.7 의 '감사 로그는 immutable history' 원칙."

**해당 테스트**: `tests/scenarios/test_security_p1.py::test_audit_user_id_preserved_after_delete`

**기술 메모**: 014 마이그레이션 이전엔 audit_logs.user_id FK 의 ON DELETE SET NULL 이 append-only 트리거와 충돌해 사용자 삭제 자체가 500 으로 실패했음. FK 제거로 dangling integer 를 의도된 동작으로 받아들이며 양 정책을 양립시킴.

---

## 백업 시연 — 결정 매트릭스 + Confidence (60초)

만약 라이브 데모가 깨지면:

```
$ pytest tests/unit/test_decision_matrix.py -v
......................................... [100%]
37 passed
```

**메시지**: "37개 결정 케이스가 자동 회귀 검증. trust × sensitivity × time × location × device × action 모든 조합. 정책 코드 한 줄 잘못 바꾸면 즉시 빨간불."

추가로 confidence-aware 결정 시연 (decision_engine.py 코드 직접 보여주기):

```python
# 점수 92 (DENY 경계) + 4축 한쪽 극단 + 위치 신호 비활성
confidence = 0.65  # < 0.85 threshold
level: 5 → 4  (DENY → ADMIN_APPROVAL)
"""불확실하면 차단이 아니라 검증으로"""
```

---

## Q&A 대비 — 주요 질문 응답

**Q: 어떻게 정확도를 보장하나?**  
A: 5개 독립 레이어(scoring → policy → anomaly → session_guard → masking) 직렬 검증 + 264개 테스트 회귀 안전망. 단일 결정 함수가 아님.

**Q: 오탐률 (FP)을 어떻게 낮추나?**  
A: confidence-aware 결정. 확신 부족 시 차단이 아니라 "추가 검증" 방향으로 결정 이동. DENY → ADMIN_APPROVAL → REAUTH 단계적 완화.

**Q: 이미 알려진 한계는?**  
A: (1) X-Location 자가신고 의존 — Phase 2 GeoIP2 도입 계획. (2) JWT stateless 회수 한계 — 서버 재시작 또는 sessions.is_active 플래그로 보완. (3) 일부 TOCTOU 경합(self-approval admin_count 재조회) — 트랜잭션 격리 강화 후속 과제.

---

## 시연 후 정리

```
1. Ctrl+C 로 서버 종료
2. (다음 시연 전) scripts\run.bat 다시 실행 → 깨끗한 시드로 초기화
```
