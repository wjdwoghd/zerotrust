import fs from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const depsNodeModules =
  "C:/Users/woghd/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules";
const require = createRequire(`${depsNodeModules}/`);
const { SpreadsheetFile, Workbook } = await import(
  pathToFileURL(require.resolve("@oai/artifact-tool")).href
);

const outputPath =
  process.argv[2] ??
  "C:/Users/woghd/Desktop/zerotrust/outputs/policy_tables_latest/zerotrust_policy_access_tables.xlsx";
const outputDir = path.dirname(outputPath);

const labels = {
  1: "완전 허용",
  2: "조회만 허용",
  3: "추가 인증 후 허용",
  4: "관리자 승인 후 허용",
  5: "차단",
};

const permissions = {
  1: "열람/다운로드/복사/인쇄",
  2: "열람/인쇄 허용, 다운로드/복사 제한",
  3: "재인증 전 열람/다운로드/복사/인쇄 제한",
  4: "관리자 승인 전 열람/다운로드/복사/인쇄 제한",
  5: "접근 차단",
};

const objectBase = { 1: 10, 2: 20, 3: 30, 4: 40, 5: 50 };
const dataTypeBonus = {
  summary: 5,
  original: 10,
  evidence: 15,
  internal_memo: 20,
};

const users = [
  {
    id: 1,
    username: "detective_kim",
    name: "김형사",
    department: "강력범죄수사대",
    rank: "형사",
    role: "user",
    workDevice: "registered-001",
    tokenDevice: "token-001",
    allowedLocations: ["본청", "강남서"],
    assignedCases: [3, 4, 5, 8, 9, 11, 15],
    jobScope: ["violent_crime", "drug", "organized_crime", "national_security"],
    trustScore: 85,
    violationCount: 0,
    loginGate: "OTP 토큰 보유",
  },
  {
    id: 2,
    username: "investigator_park",
    name: "박수사관",
    department: "사이버수사대",
    rank: "수사관",
    role: "user",
    workDevice: "registered-003",
    tokenDevice: "token-002",
    allowedLocations: ["본청", "판교센터"],
    assignedCases: [7, 10],
    jobScope: ["cyber", "forensic"],
    trustScore: 78,
    violationCount: 1,
    loginGate: "OTP 토큰 보유",
  },
  {
    id: 3,
    username: "admin_lee",
    name: "이관리자",
    department: "정보보안과",
    rank: "관리자",
    role: "admin",
    workDevice: "registered-004",
    tokenDevice: "token-003",
    allowedLocations: ["본청"],
    assignedCases: [],
    jobScope: [
      "infosec",
      "audit",
      "violent_crime",
      "drug",
      "organized_crime",
      "cyber",
      "forensic",
      "traffic",
      "national_security",
      "patrol",
    ],
    trustScore: 95,
    violationCount: 0,
    loginGate: "OTP 토큰 보유",
  },
  {
    id: 4,
    username: "officer_choi",
    name: "최순경",
    department: "교통과",
    rank: "순경",
    role: "user",
    workDevice: "registered-006",
    tokenDevice: "token-004",
    allowedLocations: ["본청", "동대문서"],
    assignedCases: [1, 2, 6, 12, 14],
    jobScope: ["traffic"],
    trustScore: 70,
    violationCount: 0,
    loginGate: "OTP 토큰 보유",
  },
  {
    id: 5,
    username: "patrol_jung",
    name: "정민호",
    department: "생활안전과",
    rank: "순경",
    role: "user",
    workDevice: "registered-007",
    tokenDevice: "없음",
    allowedLocations: ["은평서"],
    assignedCases: [13],
    jobScope: ["patrol"],
    trustScore: 40,
    violationCount: 5,
    loginGate: "OTP 없음: 로그인 시 관리자 승인 게이트",
  },
  {
    id: 6,
    username: "deputy_han",
    name: "한부관",
    department: "정보보안과",
    rank: "부관리자",
    role: "deputy_admin",
    workDevice: "registered-008",
    tokenDevice: "token-006",
    allowedLocations: ["본청"],
    assignedCases: [],
    jobScope: [
      "infosec",
      "audit",
      "violent_crime",
      "drug",
      "organized_crime",
      "cyber",
      "forensic",
      "traffic",
      "national_security",
      "patrol",
    ],
    trustScore: 90,
    violationCount: 0,
    loginGate: "OTP 토큰 보유",
  },
  {
    id: 7,
    username: "deputy_oh",
    name: "오부관",
    department: "감사팀",
    rank: "부관리자",
    role: "deputy_admin",
    workDevice: "registered-009",
    tokenDevice: "token-007",
    allowedLocations: ["본청"],
    assignedCases: [],
    jobScope: [
      "audit",
      "infosec",
      "violent_crime",
      "drug",
      "organized_crime",
      "cyber",
      "forensic",
      "traffic",
      "national_security",
      "patrol",
    ],
    trustScore: 90,
    violationCount: 0,
    loginGate: "OTP 토큰 보유",
  },
];

const resources = [
  {
    id: 1,
    caseNumber: "2026-ADM-0001",
    title: "일반 교통 행정 통계",
    grade: 1,
    dataType: "summary",
    department: "교통과",
    requiresApproval: false,
    jobTags: ["traffic"],
  },
  {
    id: 2,
    caseNumber: "2026-TRF-0042",
    title: "교통사고 수사 보고서",
    grade: 2,
    dataType: "original",
    department: "교통과",
    requiresApproval: false,
    jobTags: ["traffic"],
  },
  {
    id: 3,
    caseNumber: "2026-VCT-0108",
    title: "개인정보 포함 피해자 진술서",
    grade: 3,
    dataType: "original",
    department: "강력범죄수사대",
    requiresApproval: false,
    jobTags: ["violent_crime"],
  },
  {
    id: 4,
    caseNumber: "2026-ORG-0015",
    title: "조직범죄 수사 자료",
    grade: 4,
    dataType: "evidence",
    department: "강력범죄수사대",
    requiresApproval: true,
    jobTags: ["drug", "organized_crime"],
  },
  {
    id: 5,
    caseNumber: "2026-TOP-0003",
    title: "극비 수사 첩보 보고서",
    grade: 5,
    dataType: "internal_memo",
    department: "강력범죄수사대",
    requiresApproval: true,
    jobTags: ["national_security"],
  },
  {
    id: 6,
    caseNumber: "2026-ADM-0099",
    title: "일반 행정 공문",
    grade: 1,
    dataType: "summary",
    department: "교통과",
    requiresApproval: false,
    jobTags: ["traffic"],
  },
  {
    id: 7,
    caseNumber: "2026-CYB-0077",
    title: "사이버범죄 증거자료",
    grade: 3,
    dataType: "evidence",
    department: "사이버수사대",
    requiresApproval: false,
    jobTags: ["cyber", "forensic"],
  },
  {
    id: 8,
    caseNumber: "2026-DRG-0022",
    title: "마약사범 내사 자료",
    grade: 4,
    dataType: "original",
    department: "강력범죄수사대",
    requiresApproval: true,
    jobTags: ["drug"],
  },
  {
    id: 9,
    caseNumber: "2026-VIP-0001",
    title: "VIP 관련 극비 보고서",
    grade: 5,
    dataType: "evidence",
    department: "강력범죄수사대",
    requiresApproval: true,
    jobTags: ["violent_crime"],
  },
  {
    id: 10,
    caseNumber: "2026-CYB-0088",
    title: "사이버수사대 내부 감사 자료",
    grade: 3,
    dataType: "evidence",
    department: "사이버수사대",
    requiresApproval: false,
    jobTags: ["cyber", "forensic", "audit"],
  },
  {
    id: 11,
    caseNumber: "2026-VCT-0200",
    title: "강력범죄 공동 수사 증거물",
    grade: 3,
    dataType: "evidence",
    department: "강력범죄수사대",
    requiresApproval: false,
    jobTags: ["violent_crime", "patrol"],
  },
  {
    id: 12,
    caseNumber: "2026-TRF-0100",
    title: "교통과 중대사고 디지털 증거",
    grade: 3,
    dataType: "evidence",
    department: "교통과",
    requiresApproval: false,
    jobTags: ["traffic", "forensic"],
  },
  {
    id: 13,
    caseNumber: "2026-PTR-0001",
    title: "생활안전과 순찰 편성안",
    grade: 2,
    dataType: "original",
    department: "생활안전과",
    requiresApproval: false,
    jobTags: ["patrol"],
  },
  {
    id: 14,
    caseNumber: "2026-ADM-0200",
    title: "교통과 특별 행정처분 기록",
    grade: 2,
    dataType: "original",
    department: "교통과",
    requiresApproval: true,
    jobTags: ["traffic"],
  },
  {
    id: 15,
    caseNumber: "2026-VCT-0300",
    title: "광역수사 공조 증거자료",
    grade: 3,
    dataType: "evidence",
    department: "강력범죄수사대",
    requiresApproval: false,
    jobTags: ["violent_crime", "organized_crime"],
  },
];

function yn(value) {
  return value ? "Y" : "N";
}

function scoreLevel(score) {
  if (score <= 25) return 1;
  if (score <= 50) return 2;
  if (score <= 75) return 3;
  if (score <= 90) return 4;
  return 5;
}

function intersects(left, right) {
  const values = new Set(left);
  return right.some((value) => values.has(value));
}

function formatList(values) {
  return values.length ? values.join(", ") : "";
}

function evaluate(user, resource) {
  const assigned = user.assignedCases.includes(resource.id);
  const sameDepartment = user.department === resource.department;
  const jurisdictionMatch = sameDepartment;
  const jobRelevance = intersects(user.jobScope, resource.jobTags);
  const objectScore = objectBase[resource.grade] + dataTypeBonus[resource.dataType];
  const environmentScore = 0;
  let behaviorScore = 0;
  const behaviorFactors = [];
  if (!assigned) {
    behaviorScore += 10;
    behaviorFactors.push("비담당 사건 접근(+10)");
  }
  if (!assigned && resource.grade >= 4) {
    behaviorScore += 5;
    behaviorFactors.push("4~5등급 비담당 추가(+5)");
  }
  if (!behaviorFactors.length) behaviorFactors.push("정상 행위(+0)");

  let fitnessScore = 0;
  const fitnessFactors = [];
  if (assigned) {
    fitnessScore -= 20;
    fitnessFactors.push("담당 사건(-20)");
  }
  if (sameDepartment) {
    fitnessScore -= 10;
    fitnessFactors.push("동일 부서(-10)");
  }
  if (jurisdictionMatch) {
    fitnessScore -= 5;
    fitnessFactors.push("관할 일치(-5)");
  }
  if (jobRelevance) {
    fitnessScore -= 10;
    fitnessFactors.push("직무 연관성(-10)");
  }
  if (!fitnessFactors.length) fitnessFactors.push("업무 연관 없음(0)");

  const risk = Math.max(
    0,
    Number((objectScore + environmentScore + behaviorScore - Math.abs(fitnessScore)).toFixed(1))
  );
  const baseLevel = scoreLevel(risk);

  const exceptionParts = [];
  const reauthRequired = resource.grade >= 4 && !assigned;
  const adminRequired =
    resource.requiresApproval ||
    (resource.grade >= 4 && !assigned && !sameDepartment);

  let appliedLevel = baseLevel;
  if (reauthRequired && appliedLevel < 3) {
    appliedLevel = 3;
    exceptionParts.push("추가 인증 필요");
  }
  if (adminRequired && appliedLevel < 4) {
    appliedLevel = 4;
    exceptionParts.push("관리자 승인 필요");
  }

  const exception = exceptionParts.length ? exceptionParts.join("; ") : "없음";
  const formula = `${objectScore} + ${environmentScore} + ${behaviorScore} - ${Math.abs(
    fitnessScore
  )} = ${risk}`;
  const note =
    exception === "없음"
      ? "총점 구간과 점수기반 레벨 일치"
      : `총점 구간은 L${baseLevel}, 예외로 적용 레벨 L${appliedLevel}`;

  return {
    assigned,
    sameDepartment,
    jurisdictionMatch,
    jobRelevance,
    objectScore,
    environmentScore,
    behaviorScore,
    behaviorFactors,
    fitnessScore,
    fitnessFactors,
    risk,
    scoreLevel: baseLevel,
    appliedLevel,
    exception,
    actionPermission: permissions[appliedLevel],
    formula,
    note,
  };
}

function colName(index) {
  let n = index + 1;
  let name = "";
  while (n > 0) {
    const rem = (n - 1) % 26;
    name = String.fromCharCode(65 + rem) + name;
    n = Math.floor((n - 1) / 26);
  }
  return name;
}

function applyCommonStyle(sheet, values, tableName, widths = []) {
  const rows = values.length;
  const cols = values[0].length;
  const used = sheet.getRangeByIndexes(0, 0, rows, cols);
  used.format = {
    font: { name: "맑은 고딕", size: 10, color: "#111827" },
    wrapText: true,
    verticalAlignment: "top",
  };
  used.format.borders = { preset: "all", style: "thin", color: "#CBD5E1" };
  const header = sheet.getRangeByIndexes(0, 0, 1, cols);
  header.format = {
    fill: "#1F4E78",
    font: { bold: true, color: "#FFFFFF" },
    wrapText: true,
    horizontalAlignment: "center",
    verticalAlignment: "middle",
  };
  header.format.rowHeightPx = 34;
  sheet.freezePanes.freezeRows(1);
  sheet.showGridLines = false;

  widths.forEach((width, index) => {
    if (!width) return;
    sheet.getRangeByIndexes(0, index, rows, 1).format.columnWidthPx = width;
  });

  const address = `A1:${colName(cols - 1)}${rows}`;
  try {
    const table = sheet.tables.add(address, true, tableName);
    table.style = "TableStyleMedium2";
  } catch {
    // Table styling is non-essential; the range formatting above remains.
  }
}

function addSheet(workbook, name, values, tableName, widths) {
  const sheet = workbook.worksheets.add(name);
  sheet.getRangeByIndexes(0, 0, values.length, values[0].length).values = values;
  applyCommonStyle(sheet, values, tableName, widths);
  return sheet;
}

const policyRows = [
  ["구분", "정책/조건", "점수/범위", "접근 레벨/효과", "비고"],
  ["판단점수 매핑", "0 <= risk_score <= 25", "0~25", "Level 1 / 완전 허용", "경계값 포함"],
  ["판단점수 매핑", "25 < risk_score <= 50", "25 초과~50", "Level 2 / 조회만 허용", "다운로드/복사 제한"],
  ["판단점수 매핑", "50 < risk_score <= 75", "50 초과~75", "Level 3 / 추가 인증 후 허용", "재인증 필요"],
  ["판단점수 매핑", "75 < risk_score <= 90", "75 초과~90", "Level 4 / 관리자 승인 후 허용", "승인 워크플로"],
  ["판단점수 매핑", "risk_score > 90", "90 초과", "Level 5 / 차단", "접근 제한"],
  ["행동 권한", "Level 1", "점수 0~25", permissions[1], "점수기반 기본 권한"],
  ["행동 권한", "Level 2", "점수 25초과~50", permissions[2], "점수기반 기본 권한"],
  ["행동 권한", "Level 3", "점수 50초과~75", permissions[3], "재인증 성공 시 별도 예외로 해제 가능"],
  ["행동 권한", "Level 4", "점수 75초과~90", permissions[4], "관리자 승인 성공 시 별도 예외로 해제 가능"],
  ["행동 권한", "Level 5", "점수 90초과", permissions[5], "차단"],
  ["객체 민감도", "등급 1/2/3/4/5", "+10/+20/+30/+40/+50", "위험점수 가산", "OBJECT_SENS_GRADE_*"],
  ["객체 민감도", "summary/original/evidence/internal_memo", "+5/+10/+15/+20", "위험점수 가산", "OBJECT_DATA_TYPE_*"],
  ["환경 위험도", "미등록 단말", "+20", "위험점수 가산", "ENV_UNREGISTERED_DEVICE"],
  ["환경 위험도", "장기 미사용 등록 단말", "+10", "위험점수 가산", "ENV_LONG_UNUSED_DEVICE"],
  ["환경 위험도", "비허용 위치", "+20", "위험점수 가산 + 즉시차단 예외 가능", "ENV_DISALLOWED_LOCATION / LOCATION_NOT_ALLOWED"],
  ["환경 위험도", "예외 허용 위치", "+10", "위험점수 가산", "ENV_EXCEPTION_LOCATION"],
  ["환경 위험도", "심야 22:00~06:00", "+15", "위험점수 가산", "직무 multiplier 없이 항상 +15"],
  ["환경 위험도", "완화구간 06~09 / 18~22", "+5", "위험점수 가산", "ENV_RELAXED_TIME"],
  ["환경 위험도", "세션 중 단말 변경", "+10", "위험점수 가산 + 재인증 예외", "ENV_DEVICE_CHANGED"],
  ["환경 위험도", "비현실적 위치 전환", "+15", "위험점수 가산 + 즉시차단 예외", "ENV_IMPOSSIBLE_TRAVEL"],
  ["행동 위험도", "5분 내 5~9회 접근", "+10", "위험점수 가산", "BEH_HIGH_FREQ_ACCESS"],
  ["행동 위험도", "5분 내 10회 이상 접근", "+20", "위험점수 가산", "BEH_HIGH_FREQ_ACCESS_CRITICAL"],
  ["행동 위험도", "비담당 사건 상세 접근", "+10", "위험점수 가산", "BEH_UNAUTHORIZED_ACCESS"],
  ["행동 위험도", "비담당 사건 목록 반복 클릭", "첫 클릭 0, 두 번째부터 회당 +10", "위험점수 가산", "UI 경고 후 세션 단위 누적"],
  ["행동 위험도", "4~5등급 비담당 사건 접근", "+5", "위험점수 가산", "BEH_HIGH_SENS_UNASSIGNED"],
  ["행동 위험도", "민감 자료 다운로드 시도", "+20", "위험점수 가산", "BEH_DOWNLOAD_SENSITIVE"],
  ["행동 위험도", "복사 시도", "+20", "위험점수 가산", "BEH_COPY_ATTEMPT"],
  ["행동 위험도", "대량 조회", "+20", "위험점수 가산", "BEH_BULK_QUERY"],
  ["행동 위험도", "인증 실패 누적", "+15", "위험점수 가산", "BEH_AUTH_FAIL_REPEAT"],
  ["업무 적합도", "담당 사건", "-20", "위험점수 차감", "FIT_ASSIGNED_CASE"],
  ["업무 적합도", "동일 부서", "-10", "위험점수 차감", "FIT_SAME_DEPARTMENT"],
  ["업무 적합도", "관할 일치", "-5", "위험점수 차감", "현재 구현은 동일 부서와 동일하게 판정"],
  ["업무 적합도", "직무 연관성", "-10", "위험점수 차감", "users.job_scope ∩ resources.job_tags"],
  ["업무 적합도", "관리자 사전 승인", "-15", "위험점수 차감", "FIT_PRE_APPROVED 유지"],
  ["최종 점수식", "객체 + 환경 + 행동 - abs(업무적합도)", "최소 0", "risk_score 산출", "정책 보정 항목 없음"],
  ["확신도", "confidence", "진단값", "레벨 보정 없음", "confidence_adjusted=false"],
  ["예외: 즉시차단", "동시접속 + 단말불일치 + 인증실패", "조건 충족", "Level 5 적용", "CONCURRENT_DEVICE_AUTH"],
  ["예외: 즉시차단", "비허용위치 + 미등록단말 + Grade>=4 + 다운로드", "조건 충족", "Level 5 적용", "HIGH_RISK_DOWNLOAD"],
  ["예외: 즉시차단", "비현실적 위치 전환", "조건 충족", "Level 5 적용", "IMPOSSIBLE_TRAVEL"],
  ["예외: 즉시차단", "비허용 위치", "조건 충족", "Level 5 적용 + 세션 재인증 대기", "LOCATION_NOT_ALLOWED"],
  ["예외: 재인증", "단말 변경 / 위치 변경 / Grade>=4 비담당", "조건 충족", "최소 Level 3 적용", "score_level은 별도 보존"],
  ["예외: 관리자 승인", "requires_approval=True", "조건 충족", "최소 Level 4 적용", "명시적 자원 승인 플래그"],
  ["예외: 관리자 승인", "Grade>=4 + 비담당 + 타부서", "조건 충족", "최소 Level 4 적용", "승인 워크플로"],
  ["예외: 사전 승인", "관리자 승인 완료(download_allowed=false)", "TTL 내", "Level 2 열람 전용", "PRE_APPROVAL_TTL_SEC"],
  ["예외: 사전 승인", "관리자 승인 완료(download_allowed=true)", "TTL 내", "Level 1 다운로드 포함 허용", "PRE_APPROVAL_TTL_SEC"],
  ["예외: Break-Glass", "토큰 기기 + MFA + 정당화 사유 10자 이상 + Grade>=4", "30분/유휴 5분", "Level 1 우회", "감사 로그와 사후 리뷰 필수"],
  ["사건 목록 마스킹", "비담당 사건", "사건명 표시, 등급/번호/세부내용 마스킹", "담당 사건 등록 요청 가능", "등급 필터는 담당 사건에만 적용"],
  ["신규 계정", "관리자 생성 직후", "담당 사건 0, OTP 기기 없음", "OTP 등록 전 로그인 관리자 승인 필요", "담당 사건 등록 요청은 자기 부서/직무 태그 범위"],
];

const accountRows = [
  [
    "username",
    "이름",
    "소속 부서",
    "계급",
    "role",
    "업무 기기",
    "OTP 토큰 기기",
    "허용 근무지",
    "담당 문서 ID",
    "직무 범위",
    "trust_score",
    "violation_count",
    "로그인/MFA 상태",
  ],
  ...users.map((user) => [
    user.username,
    user.name,
    user.department,
    user.rank,
    user.role,
    user.workDevice,
    user.tokenDevice,
    formatList(user.allowedLocations),
    formatList(user.assignedCases),
    formatList(user.jobScope),
    user.trustScore,
    user.violationCount,
    user.loginGate,
  ]),
];

const resourceRows = [
  ["문서 ID", "사건번호", "문서명", "민감도", "자료유형", "부서", "승인필요", "직무 태그"],
  ...resources.map((resource) => [
    resource.id,
    resource.caseNumber,
    resource.title,
    resource.grade,
    resource.dataType,
    resource.department,
    yn(resource.requiresApproval),
    formatList(resource.jobTags),
  ]),
];

const detailedHeader = [
  "계정",
  "이름",
  "문서 ID",
  "사건번호",
  "문서명",
  "민감도",
  "자료유형",
  "승인필요",
  "담당",
  "동일부서",
  "관할일치",
  "직무연관",
  "객체점수",
  "환경점수",
  "행동점수",
  "업무적합도",
  "총 위험 점수",
  "점수기반 레벨",
  "예외 적용",
  "적용 레벨",
  "행동 권한",
  "산정식",
  "메모",
];

const detailedRows = [detailedHeader];
const matrixRows = [
  [
    "계정",
    "이름",
    "부서",
    ...resources.map((resource) => `${resource.id}. ${resource.title}`),
  ],
];

for (const user of users) {
  const matrixRow = [user.username, user.name, user.department];
  for (const resource of resources) {
    const result = evaluate(user, resource);
    detailedRows.push([
      user.username,
      user.name,
      resource.id,
      resource.caseNumber,
      resource.title,
      resource.grade,
      resource.dataType,
      yn(resource.requiresApproval),
      yn(result.assigned),
      yn(result.sameDepartment),
      yn(result.jurisdictionMatch),
      yn(result.jobRelevance),
      result.objectScore,
      result.environmentScore,
      result.behaviorScore,
      result.fitnessScore,
      result.risk,
      `L${result.scoreLevel} ${labels[result.scoreLevel]}`,
      result.exception,
      `L${result.appliedLevel} ${labels[result.appliedLevel]}`,
      result.actionPermission,
      result.formula,
      result.note,
    ]);

    const scoreText = `${result.risk.toFixed(1)}점 / 점수 L${result.scoreLevel}`;
    const appliedText =
      result.exception === "없음"
        ? `${scoreText} ${labels[result.scoreLevel]}`
        : `${scoreText} -> 적용 L${result.appliedLevel} ${labels[result.appliedLevel]} (${result.exception})`;
    matrixRow.push(appliedText);
  }
  matrixRows.push(matrixRow);
}

const generatedAt = new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  dateStyle: "medium",
  timeStyle: "medium",
}).format(new Date());

const criteriaRows = [
  ["항목", "내용"],
  ["최신화 일시", generatedAt],
  ["소스 기준", "C:/Users/woghd/Desktop/zerotrust/source 최신 코드 및 migrations 020/022/023 반영"],
  ["권한표 기준 상황", "등록 업무기기 + 허용 위치 + 근무시간(10시) + 열람(view) + 이상행동 없음 + 사전승인 없음 + Break-Glass 없음"],
  ["총점-레벨 원칙", "총 위험 점수는 4축만으로 산출하고, 점수기반 레벨은 반드시 해당 점수 구간과 일치한다."],
  ["예외 표기 원칙", "재인증/관리자 승인/즉시차단/Break-Glass는 점수 산정이 아니라 별도 예외 적용으로 분리해 표기한다."],
  ["정책 보정", "사용하지 않음. UI/표 모두 객체/환경/행동/업무적합도 4축만 표시한다."],
  ["업무 적합도 최신 기준", "담당 사건 -20 + 동일 부서 -10 + 관할 일치 -5 + 직무 연관성 -10 = 최대 -45, 사전 승인 -15는 별도 유지"],
  ["심야 위험도", "22:00~06:00 ENV_NIGHT_TIME은 모든 직무에서 정확히 +15로 반영된다."],
  ["비담당 사건 목록", "사건명은 표시하되 등급/번호/세부내용은 마스킹한다. 등급 필터는 담당 사건에만 적용해 비담당 등급 유출을 막는다."],
  ["비담당 사건 클릭", "목록에서 첫 비담당 클릭은 경고만 표시하고, 두 번째 클릭부터 세션 기준 회당 행동 위험도 +10을 누적한다."],
  ["담당 사건 등록 요청", "사용자는 자기 부서 및 직무 태그가 맞는 사건에 대해서만 담당 등록 요청을 보낼 수 있다."],
  ["신규 계정 정책", "관리자가 만든 신규 계정은 담당 사건 0, OTP 기기 없음으로 시작한다. OTP 등록 전 로그인은 관리자 승인 게이트를 통과해야 한다."],
  ["계정 생성 옵션: 부서", "강력범죄수사대, 사이버수사대, 교통과, 생활안전과, 정보보안과, 감사팀"],
  ["계정 생성 옵션: 계급", "순경, 경장, 경사, 경위, 경감, 형사, 수사관"],
  ["계정 생성 옵션: 근무지", "본청, 강남서, 판교센터, 동대문서, 은평서, 해외"],
  ["계정 생성 옵션: 직무", "violent_crime, drug, organized_crime, cyber, forensic, traffic, national_security, patrol, infosec, audit"],
  ["Break-Glass", "토큰 기기 보유자가 OTP 재확인과 10자 이상 사유를 제출해야 하며, Grade>=4 범위에서 30분/유휴 5분 동안 Level 1 우회가 가능하다."],
  ["사후 평가", "Break-Glass 종료 후 관리자/부관리자 리뷰가 필요하며, 본인 리뷰와 본인 강제종료는 차단된다."],
  ["주의", "다운로드, 복사, 야간, 위치 변경, 미등록 단말, 대량 조회, 승인 완료, Break-Glass 상태에 따라 실시간 결과가 바뀐다."],
];

const workbook = Workbook.create();

addSheet(workbook, "정책표", policyRows, "PolicyTable", [130, 280, 160, 210, 330]);
addSheet(workbook, "계정", accountRows, "AccountsTable", [
  150,
  90,
  140,
  80,
  110,
  120,
  120,
  180,
  160,
  460,
  90,
  110,
  260,
]);
addSheet(workbook, "문서", resourceRows, "ResourcesTable", [
  80,
  130,
  260,
  70,
  120,
  140,
  80,
  260,
]);
addSheet(workbook, "접근권한표", matrixRows, "AccessMatrixTable", [
  140,
  90,
  140,
  ...resources.map(() => 260),
]);
addSheet(workbook, "상세산정", detailedRows, "DetailedScoringTable", [
  140,
  90,
  70,
  130,
  250,
  70,
  110,
  80,
  60,
  70,
  70,
  70,
  80,
  80,
  80,
  90,
  100,
  140,
  170,
  150,
  280,
  190,
  260,
]);
addSheet(workbook, "산정기준", criteriaRows, "CriteriaTable", [210, 780]);

await fs.mkdir(outputDir, { recursive: true });

for (const sheetName of ["정책표", "계정", "문서", "접근권한표", "상세산정", "산정기준"]) {
  const preview = await workbook.render({
    sheetName,
    autoCrop: "all",
    scale: 1,
    format: "png",
  });
  const safeName = sheetName.replace(/[\\/:*?"<>|]/g, "_");
  await fs.writeFile(
    path.join(outputDir, `preview-${safeName}.png`),
    new Uint8Array(await preview.arrayBuffer())
  );
}

const check = await workbook.inspect({
  kind: "table",
  range: "정책표!A1:E20",
  include: "values",
  tableMaxRows: 20,
  tableMaxCols: 5,
  maxChars: 6000,
});
console.log(check.ndjson);

const errorScan = await workbook.inspect({
  kind: "match",
  searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
  options: { useRegex: true, maxResults: 100 },
  summary: "final formula error scan",
});
console.log(errorScan.ndjson);

const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);
console.log(`saved=${outputPath}`);
