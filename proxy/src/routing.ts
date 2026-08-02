/**
 * 프록시의 순수 라우팅·분류 헬퍼.
 * index.ts에서 분리한 이유: 이들은 부작용 없는 순수 함수라 단독으로 속성 기반
 * 테스트(fast-check 퍼징)가 가능하다. index.ts는 최하단에서 main()을 실행하므로
 * 그대로 import하면 프록시가 떠버린다 — 그래서 순수 로직만 여기로 뺐다.
 *
 * 불변식(퍼징이 지키는 성질):
 *  - classifyMethod:  어떤 문자열이 와도 예외 없이 "SINK"|"HARMLESS"|"UNCLASSIFIED" 중 하나 반환
 *  - splitAgentToolName: 어떤 문자열이 와도 예외 없이 [string, string] 반환, 두 조각이 원본을 복원
 *
 * (URI 신뢰 판정 isResourceTrusted는 C-7로 엔진에 이관 — registry의 trustedResourceUris를
 *  엔진의 isResourceUriTrusted가 판정한다. 프록시엔 더 이상 신뢰 휴리스틱이 없다.)
 */

// ── (사) 메서드 위험도 분류 ──────────────────────────────────────────────
//   SINK     : 데이터가 밖으로 나갈 수 있는 메서드 → tools/call처럼 검사 대상
//   HARMLESS : 목록·메타·수명주기 조회 → 데이터를 나르지 않음, 그냥 통과 OK
//   (그 외)  : 미분류 → 일단 통과하되 정식 기록

// 외부로 데이터가 나갈 수 있는 메서드.
export const SINK_METHODS = new Set<string>([
  "sampling/createMessage", // 서버가 클라의 LLM에 컨텍스트를 보냄 = 외부 유출구
]);

// 데이터를 나르지 않는 메타/목록/수명주기 메서드 (무검사 통과해도 안전).
export const HARMLESS_METHODS = new Set<string>([
  "ping",
  "initialize",
  "tools/list",
  "resources/list",
  "resources/templates/list",
  "prompts/list",
  "roots/list",
  "logging/setLevel",
  "completion/complete",
]);

export type MethodRisk = "SINK" | "HARMLESS" | "UNCLASSIFIED";

// 메서드명 → 위험도. 알림(notifications/*)은 상태 통지일 뿐이라 무해로 본다.
export function classifyMethod(method: string): MethodRisk {
  if (SINK_METHODS.has(method)) return "SINK";
  if (HARMLESS_METHODS.has(method)) return "HARMLESS";
  if (method.startsWith("notifications/")) return "HARMLESS";
  return "UNCLASSIFIED";
}

// 'db.query_customer_db' → ['db', 'query_customer_db']. 접두사(첫 '.') 기준. 없으면 ['', name].
export function splitAgentToolName(agentName: string): [string, string] {
  const dot = agentName.indexOf(".");
  if (dot < 0) return ["", agentName];
  return [agentName.slice(0, dot), agentName.slice(dot + 1)];
}
