/**
 * ① 브레인 — B 담당
 *
 * 역할: 세션별 오염 태그를 추적하고, "SENSITIVE + UNTRUSTED_ORIGIN이 동시에
 * OUTBOUND_SINK로 나가려 하는가"를 결정론적 규칙으로 판정한다.
 *
 * 남은 TODO:
 * TODO(B): SessionTaintState를 인메모리 Map 대신 Redis 등으로 교체 (다중 인스턴스 대응)
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
} from "@taintguard/types";
import { getToolRegistry } from "./registry.js";
import { extractStructured, tokenizePII } from "./sanitization.js";

export { loadToolRegistry, getToolRegistry, type ToolRegistry } from "./registry.js";
export {
  extractStructured,
  tokenizePII,
  resolveToken,
  ALLOWED_RECORD_TYPES,
  NAME_MAX_LENGTH,
  type ExtractedRecord,
  type SanitizeOutcome,
} from "./sanitization.js";

// ---------------------------------------------------------------------------
// 도구 정적 분류 — config/tool-registry.json 에서 로드 (registry.ts)
// ---------------------------------------------------------------------------

function classifySink(toolName: string): SinkClass {
  return getToolRegistry().sinks.get(toolName) ?? SinkClass.READ;
}

function classifySourceTags(toolName: string): ToolRiskTag[] {
  const registry = getToolRegistry();
  const tags: ToolRiskTag[] = [];
  if (registry.sensitiveSources.has(toolName)) tags.push(ToolRiskTag.SENSITIVE);
  if (registry.untrustedSources.has(toolName)) tags.push(ToolRiskTag.UNTRUSTED_ORIGIN);
  return tags;
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

  for (const tag of classifySourceTags(toolName)) {
    if (!session.tags.includes(tag)) session.tags.push(tag);
  }
  session.updatedAt = new Date().toISOString();
}

// ---------------------------------------------------------------------------
// 세션별 오염 페이로드 저장소 — 정화(declassification)의 대상이 되는 실제 데이터.
// attemptSanitization(sessionId, method) 시그니처에는 페이로드 인자가 없으므로,
// 프록시(A)가 도구 결과 본문을 이 저장소에 먼저 기록해 둬야 정화를 검증할 수 있다.
// ---------------------------------------------------------------------------

interface RecordedPayload {
  toolName: string;
  /** 이 페이로드가 아직 지니고 있는 태그 (정화 성공 시 해당 태그 제거) */
  tags: ToolRiskTag[];
  payload: unknown;
}

const payloadStore = new Map<string, RecordedPayload[]>();

/**
 * 도구 결과 본문을 세션에 기록하고 태그를 갱신한다.
 * tagToolResult의 상위 호환 — 페이로드까지 넘기면 나중에 attemptSanitization이
 * 이 데이터를 실제로 정화·검증할 수 있다.
 */
export function recordToolPayload(sessionId: string, toolName: string, payload: unknown): void {
  tagToolResult(sessionId, toolName);

  const tags = classifySourceTags(toolName);
  if (tags.length === 0) return; // 깨끗한 소스는 정화 대상이 아니므로 기록 불필요

  const records = payloadStore.get(sessionId) ?? [];
  records.push({ toolName, tags, payload });
  payloadStore.set(sessionId, records);
}

// ---------------------------------------------------------------------------
// 검증된 정화 (declassification)
// ---------------------------------------------------------------------------

/**
 * 각 정화 방법이 해제를 검증할 수 있는 태그.
 * - 토큰화: PII를 불투명 토큰으로 치환했음을 검증 → SENSITIVE 해제
 * - 구조화 추출: 좁은 스키마 필드만 남겼음을 검증 → UNTRUSTED_ORIGIN 해제
 */
const METHOD_CLEARS: Record<SanitizationMethod, ToolRiskTag> = {
  [SanitizationMethod.TOKENIZATION]: ToolRiskTag.SENSITIVE,
  [SanitizationMethod.STRUCTURED_EXTRACTION]: ToolRiskTag.UNTRUSTED_ORIGIN,
};

/**
 * 검증된 정화 — lilith-zero의 세션 단위 boolean 태그와 달리,
 * 명시된 검증 방법을 통과한 흐름은 태그를 안전하게 해제해 세션을 계속 쓸 수 있게 한다.
 *
 * 동작 (전부 결정론적 규칙, AI 판단 없음):
 * 1. method가 해제할 수 있는 태그(targetTag)를 지닌 기록 페이로드를 모두 찾는다.
 * 2. 각 페이로드에 정화를 적용하고 검증한다 (sanitization.ts).
 * 3. "전부" 검증을 통과했을 때만 세션과 페이로드에서 targetTag를 해제한다.
 *    하나라도 실패하거나, 검증할 페이로드가 기록돼 있지 않으면 태그 유지 (fail-safe).
 */
export function attemptSanitization(
  sessionId: string,
  method: SanitizationMethod
): SanitizationResult {
  const session = getOrCreateSession(sessionId);
  const originalTags = [...session.tags];
  const targetTag = METHOD_CLEARS[method];

  const records = (payloadStore.get(sessionId) ?? []).filter((r) => r.tags.includes(targetTag));

  let sanitized = false;
  if (session.tags.includes(targetTag) && records.length > 0) {
    const outcomes = records.map((r) =>
      method === SanitizationMethod.TOKENIZATION
        ? tokenizePII(r.payload)
        : extractStructured(r.payload)
    );

    if (outcomes.every((o) => o.ok)) {
      // 검증 통과 — 페이로드를 정화된 값으로 교체하고 태그 해제
      records.forEach((record, i) => {
        const outcome = outcomes[i];
        if (outcome.ok) record.payload = outcome.value;
        record.tags = record.tags.filter((t) => t !== targetTag);
      });
      session.tags = session.tags.filter((t) => t !== targetTag);
      session.updatedAt = new Date().toISOString();
      sanitized = true;
    }
  }

  return {
    sessionId,
    originalTags,
    method,
    resultTags: [...session.tags],
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
