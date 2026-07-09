/**
 * ① 브레인 — B 담당
 *
 * 역할: 세션별 오염 태그를 추적하고, "SENSITIVE + UNTRUSTED_ORIGIN이 동시에
 * OUTBOUND_SINK로 나가려 하는가"를 결정론적 규칙으로 판정한다.
 *
 * 이 파일은 1주차 기준 "동작하는 최소 버전"이다. 실제 프로젝트에서는:
 * TODO(B): ToolRegistry를 설정 파일(YAML/JSON)로 분리해 하드코딩 제거
 * TODO(B): SessionTaintState를 인메모리 Map 대신 Redis 등으로 교체 (다중 인스턴스 대응)
 * TODO(B): 정화(sanitizeAndDeclassify) 로직을 실제 토큰화/구조화 추출 방식으로 구현
 */

import {
  ToolRiskTag,
  SinkClass,
  type ToolCallContext,
  type PolicyDecision,
  type SessionTaintState,
  type TrifectaEvent,
  type SanitizationResult,
  SanitizationMethod,
} from "@icarus-tether/types";

// ---------------------------------------------------------------------------
// 도구 정적 분류 (임시 하드코딩 — 나중에 설정 파일로 뺄 것)
// ---------------------------------------------------------------------------

const SENSITIVE_SOURCE_TOOLS = new Set(["query_customer_db", "read_internal_file"]);
const UNTRUSTED_SOURCE_TOOLS = new Set(["fetch_web_page", "read_email"]);
const OUTBOUND_SINK_TOOLS = new Set(["send_email", "http_post", "write_external_file"]);

function classifySink(toolName: string): SinkClass {
  if (OUTBOUND_SINK_TOOLS.has(toolName)) return SinkClass.OUTBOUND_SINK;
  return SinkClass.READ;
}

// ---------------------------------------------------------------------------
// 세션별 오염 상태 저장소 (1주차: 인메모리 / 나중에 Redis로 교체)
// ---------------------------------------------------------------------------

const sessionStore = new Map<string, SessionTaintState>();

function getOrCreateSession(sessionId: string): SessionTaintState {
  const existing = sessionStore.get(sessionId);
  if (existing) return existing;
  const fresh: SessionTaintState = { sessionId, tags: [], updatedAt: new Date().toISOString() };
  sessionStore.set(sessionId, fresh);
  return fresh;
}

/** 도구 결과가 도착했을 때 소스를 분류해 세션 오염 상태를 갱신한다. (Image 3 왼쪽 흐름) */
export function tagToolResult(sessionId: string, toolName: string): void {
  const session = getOrCreateSession(sessionId);
  const newTags: ToolRiskTag[] = [];

  if (SENSITIVE_SOURCE_TOOLS.has(toolName)) newTags.push(ToolRiskTag.SENSITIVE);
  if (UNTRUSTED_SOURCE_TOOLS.has(toolName)) newTags.push(ToolRiskTag.UNTRUSTED_ORIGIN);

  for (const tag of newTags) {
    if (!session.tags.includes(tag)) session.tags.push(tag);
  }
  session.updatedAt = new Date().toISOString();
}

/**
 * 검증된 정화 — lilith-zero의 세션 단위 boolean 태그와 달리,
 * 명시된 검증 방법을 통과한 흐름은 태그를 안전하게 해제해 세션을 계속 쓸 수 있게 한다.
 *
 * 1주차 스텁: 항상 정화 실패로 처리. 실제 토큰화/구조화 추출 로직은 여기에 구현.
 */
export function attemptSanitization(
  sessionId: string,
  method: SanitizationMethod
): SanitizationResult {
  const session = getOrCreateSession(sessionId);
  // TODO(B): 실제 정화 로직 (예: PII 토큰화 검증, 스키마 기반 구조화 추출 검증)
  const sanitized = false;

  return {
    sessionId,
    originalTags: [...session.tags],
    method,
    resultTags: sanitized ? [] : [...session.tags],
    timestamp: new Date().toISOString(),
  };
}

/** 도구 호출 시도 시 트라이펙타 여부를 판정한다. (Image 3 오른쪽 흐름) */
export function evaluateToolCall(ctx: ToolCallContext): PolicyDecision {
  const session = getOrCreateSession(ctx.sessionId);
  const sinkClass = classifySink(ctx.toolName);

  // 인자에 실린 태그 + 세션 누적 태그를 합쳐 "전파된 태그"로 본다
  const effectiveTags = new Set<ToolRiskTag>([...session.tags, ...ctx.argTags]);

  if (sinkClass !== SinkClass.OUTBOUND_SINK) {
    return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
  }

  const hasSensitive = effectiveTags.has(ToolRiskTag.SENSITIVE);
  const hasUntrusted = effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN);

  if (hasSensitive && hasUntrusted) {
    const matchedTags = [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN];
    emitTrifectaEvent(ctx, sinkClass, matchedTags);
    return {
      sessionId: ctx.sessionId,
      toolName: ctx.toolName,
      allowed: false,
      reason: "lethal trifecta 감지: 민감 데이터 + 비신뢰 입력이 외부 유출 시도와 겹침",
      matchedTags,
    };
  }

  return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
}

function emitTrifectaEvent(
  ctx: ToolCallContext,
  sinkClass: SinkClass,
  matchedTags: ToolRiskTag[]
): TrifectaEvent {
  const event: TrifectaEvent = {
    id: crypto.randomUUID(),
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    matchedTags,
    sinkClass,
    timestamp: new Date().toISOString(),
  };
  // TODO(B/C): dashboard·audit-log 쪽으로 이 이벤트를 발행 (HTTP/이벤트버스 등)
  console.log("[policy-engine] TrifectaEvent 발행:", event);
  return event;
}
