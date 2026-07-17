/**
 * Icarus-Tether 공유 타입 계약
 *
 * 이 파일은 proxy(A) · policy-engine(B) · dashboard(C) 세 워크스페이스가
 * 공통으로 import해서 쓰는 "1주차 계약"입니다.
 *
 * 이 파일을 바꿔야 할 일이 생기면, 혼자 고치지 말고 팀 채팅에 먼저 알려주세요 —
 * 세 파트가 전부 이 타입에 의존하기 때문에, 조용히 바뀌면 다른 사람 빌드가 깨집니다.
 */

// ---------------------------------------------------------------------------
// 1. 오염 태그 (① 브레인이 정의하고, ②③ 모두가 참조)
// ---------------------------------------------------------------------------

/** 데이터에 붙는 위험 태그. 도구 호출 결과에 소스 분류 규칙으로 부착된다. */
export enum ToolRiskTag {
  /** 민감 데이터 소스에서 온 값 (고객 DB, 내부 문서 등) */
  SENSITIVE = "SENSITIVE",
  /** 신뢰할 수 없는 소스에서 온 값 (웹 fetch, 이메일 본문, 외부 문서 등) */
  UNTRUSTED_ORIGIN = "UNTRUSTED_ORIGIN",
}

/** 도구를 정적으로 분류하는 싱크 등급. ToolRegistry(policy-engine)가 관리한다. */
export enum SinkClass {
  /** 읽기 전용 (조회) */
  READ = "READ",
  /** 내부 시스템에만 쓰는 작업 (외부로 안 나감) */
  WRITE_INTERNAL = "WRITE_INTERNAL",
  /** 외부로 나가는 작업 (이메일 전송, 외부 HTTP, 웹훅, 파일 쓰기 등) */
  OUTBOUND_SINK = "OUTBOUND_SINK",
}

// ---------------------------------------------------------------------------
// 2. 프록시(A) → 브레인(B)으로 넘기는 도구 호출 컨텍스트
// ---------------------------------------------------------------------------

/** 프록시가 에이전트의 tool call 하나를 가로챌 때마다 생성하는 불변 객체. */
export interface ToolCallContext {
  /** 이 대화(세션)를 식별하는 ID */
  sessionId: string;
  /** 호출하려는 도구 이름 (예: "query_customer_db", "send_email") */
  toolName: string;
  /** 도구에 전달되는 인자 (원본 JSON) */
  args: Record<string, unknown>;
  /** 인자에 실린 태그를 수집한 결과 = 전파(propagation) */
  argTags: ToolRiskTag[];
  /** 요청 발생 시각 (ISO 8601) */
  timestamp: string;
}

/**
 * [사용자용 설명] 차단 시 사용자가 취할 수 있는 선택지.
 * 결정론 번역 계층(policy-engine explain.ts)이 사실 기반으로만 생성한다 — AI 없음.
 */
export interface UserAction {
  kind: "SANITIZE" | "REQUEST_APPROVAL" | "INSPECT_SOURCE";
  /** 버튼에 쓸 짧은 말 (예: "민감 정보를 가리고 보내기") */
  label: string;
  /** 사람 말 설명 — 기술 용어 없음 */
  description: string;
  /** 지금 이 선택지가 실제로 가능한가 (사실로만 결정) */
  available: boolean;
  /** 실행에 필요한 기계용 정보 (approvalId·정화 method 등 — 여기만 기술 값 허용) */
  detail?: string;
}

/** [사용자용 설명] "왜 위험한지 + 뭘 할 수 있는지"의 구조화 번역. 문자열 파싱 불필요. */
export interface UserFacingExplanation {
  /** 한 줄 요약 (예: "민감한 정보가 외부로 나가려 해서 막았어요") */
  summary: string;
  /** 무엇이 섞여 있는지 — 사람 말 (도구는 라벨로, 노드 id 노출 없음) */
  reason: string;
  /** 왜 위험한지 (사람 말) */
  risks: string[];
  /** 뭘 할 수 있는지 (선택지) */
  actions: UserAction[];
}

/** 브레인이 ToolCallContext를 검사한 뒤 프록시에 돌려주는 판정 결과. */
export interface PolicyDecision {
  sessionId: string;
  toolName: string;
  /** true면 통과, false면 차단 */
  allowed: boolean;
  /** 차단된 경우 그 이유 (감사로그·대시보드 표시용) */
  reason?: string;
  /** 이 판정에 이르기까지 겹친 태그들 (트라이펙타 조건 확인용) */
  matchedTags: ToolRiskTag[];
  /**
   * [HITL] 이 차단을 사람 승인으로 오버라이드할 수 있는가.
   * 결정론 규칙(hitlPolicy)이 판정하며, 생략 또는 false = 오버라이드 불가(확정 차단).
   * true인 경우에만 approvalId로 승인 요청이 가능하다.
   */
  canOverride?: boolean;
  /** [HITL] canOverride=true일 때 requestApproval에 넘길 승인 id */
  approvalId?: string;
  /**
   * [사용자용 설명] 차단(계보 판정) 시 채워지는 사람 말 번역.
   * reason(개발자용)은 그대로 유지되고, 이 필드는 UI 표시용 별도 계층이다.
   */
  explanation?: UserFacingExplanation;
}

// ---------------------------------------------------------------------------
// 3. 세션 오염 상태 (브레인이 세션별로 누적 관리)
// ---------------------------------------------------------------------------

export interface SessionTaintState {
  sessionId: string;
  /** 지금까지 이 세션에서 관측된 태그 집합 */
  tags: ToolRiskTag[];
  /** 마지막 갱신 시각 */
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// 4. 트라이펙타 탐지 이벤트 (브레인이 발행 → 대시보드·감사로그가 구독)
// ---------------------------------------------------------------------------

export interface TrifectaEvent {
  id: string;
  sessionId: string;
  toolName: string;
  /** 겹친 태그들. SENSITIVE + UNTRUSTED_ORIGIN 둘 다 있으면 트라이펙타 성립 */
  matchedTags: ToolRiskTag[];
  sinkClass: SinkClass;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// 5. 검증된 정화 (declassification) — lilith-zero에 없는 우리만의 차별화 지점
// ---------------------------------------------------------------------------

/** 정화(태그 안전 해제)에 쓸 수 있는 검증된 방법들 */
export enum SanitizationMethod {
  /** 값을 불투명 토큰으로 치환 (원본은 별도 볼트에만 존재) */
  TOKENIZATION = "TOKENIZATION",
  /** 스키마 기반으로 안전한 필드만 구조화 추출 */
  STRUCTURED_EXTRACTION = "STRUCTURED_EXTRACTION",
}

export interface SanitizationResult {
  sessionId: string;
  /** 정화 전 태그 */
  originalTags: ToolRiskTag[];
  /** 어떤 방법으로 정화했는지 */
  method: SanitizationMethod;
  /** 정화 후 남는 태그 (보통 비어있음 = 태그 해제 성공) */
  resultTags: ToolRiskTag[];
  timestamp: string;
}

// ---------------------------------------------------------------------------
// 6. 승인 게이트 (C가 관리하는 HITL 워크플로우)
// ---------------------------------------------------------------------------

export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED";

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  toolName: string;
  args: Record<string, unknown>;
  status: ApprovalStatus;
  requestedAt: string;
  resolvedAt?: string;
  /** 승인/거부한 사람 (데모에서는 임의 문자열이어도 됨) */
  resolvedBy?: string;
}

// ---------------------------------------------------------------------------
// 7. 감사 로그 (C가 저장·전시)
// ---------------------------------------------------------------------------

export interface AuditLogEntry {
  id: string;
  sessionId: string;
  toolName: string;
  decision: "ALLOWED" | "BLOCKED";
  matchedTags: ToolRiskTag[];
  timestamp: string;
  /** 위변조 방지용 서명 (해시 등). MVP에서는 비워둬도 됨 */
  signature?: string;
    /**
   * 직전 로그 항목의 signature. 각 줄을 사슬로 엮어, 나중에 줄을 지우거나
   * 순서를 바꾸면 체인이 끊겨 탐지된다. 첫 줄은 제네시스라 값이 없다(선택).
   */
  prevHash?: string;
}
