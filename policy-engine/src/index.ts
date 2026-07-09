/**
 * ① 브레인 — B 담당
 *
 * 역할: 세션별 오염 태그를 추적하고, "SENSITIVE + UNTRUSTED_ORIGIN이 동시에
 * OUTBOUND_SINK로 나가려 하는가"를 결정론적 규칙으로 판정한다.
 *
 * 5원칙:
 *   1. 판단은 결정론 코드가 (AI 호출 없음)
 *   2. 그릇을 좁게 (스키마 밖 값은 담길 자리 없음 — sanitization.ts)
 *   3. 행동으로 판단 (코드는 도구 이름이 아니라 분류·성질만 다룬다; 이름은 설정에)
 *   4. 모르면 의심 — 미분류 도구는 default-deny (unknownToolPolicy로 튜닝 가능)
 *   5. 실패는 안전하게 — 정화·검증 실패 시 태그 유지 → 차단
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
import { getPolicyConfig, type PolicyConfig } from "./config.js";
import { detectSecrets } from "./secret-detection.js";
import { extractStructured, tokenizePII } from "./sanitization.js";
import { createTaintNode, declassifyNodeTag, type TaintNode } from "./lineage.js";
import { runShadowEvaluation } from "./shadow.js";

export {
  loadPolicyConfig,
  getPolicyConfig,
  NAMED_CHARSETS,
  type PolicyConfig,
  type UnknownToolPolicy,
  type PropagationMode,
  type SecretDetectionConfig,
  type ExtractionSchemaConfig,
  type FieldSpec,
  type PatternSpec,
} from "./config.js";
export { loadToolRegistry, getToolRegistry, type ToolRegistry } from "./registry.js";
export {
  detectSecrets,
  shannonEntropy,
  type DetectedSecret,
} from "./secret-detection.js";
export {
  extractStructured,
  tokenizePII,
  resolveToken,
  ALLOWED_RECORD_TYPES,
  NAME_MAX_LENGTH,
  type ExtractedRecord,
  type SanitizeOutcome,
} from "./sanitization.js";
export { getShadowLog, type ShadowLogEntry, type ShadowEvidence } from "./shadow.js";
export {
  addNodeTags,
  getSessionLineage,
  getTaintNode,
  MATCH_TOKEN_MIN_LENGTH,
  STRONG_TOKEN_MIN_LENGTH,
  type TaintNode,
  type ParentLink,
  type LinkMethod,
} from "./lineage.js";

// ---------------------------------------------------------------------------
// 도구 분류 — 값은 설정(config/*.json)에서, 코드는 분류 로직만
// ---------------------------------------------------------------------------

/** 설정의 어느 목록에든 등장하는(= 우리가 성질을 아는) 도구인가 */
function isClassifiedTool(cfg: PolicyConfig, toolName: string): boolean {
  return (
    cfg.sensitiveSourceTools.has(toolName) ||
    cfg.untrustedSourceTools.has(toolName) ||
    cfg.sinks.has(toolName)
  );
}

function classifySink(toolName: string): SinkClass {
  const cfg = getPolicyConfig();
  const explicit = cfg.sinks.get(toolName);
  if (explicit) return explicit;
  if (isClassifiedTool(cfg, toolName)) return SinkClass.READ; // 소스로는 알지만 싱크 미등록 → 읽기

  // 원칙 4 default-deny: 미분류 도구는 외부 유출 능력이 있다고 가정
  if (cfg.unknownToolPolicy === "warn") {
    console.warn(
      `[policy-engine] 미분류 도구 "${toolName}" — unknownToolPolicy=warn이라 READ로 취급 (차단 안 함)`
    );
    return SinkClass.READ;
  }
  return SinkClass.OUTBOUND_SINK;
}

function classifySourceTags(toolName: string): ToolRiskTag[] {
  const cfg = getPolicyConfig();
  const tags: ToolRiskTag[] = [];

  // 1순위 출처 기반: 민감 소스면 내용 무관 전부 SENSITIVE (sensitiveSourcePolicy: tag_all)
  const bySource = cfg.secretDetection?.bySource ?? true;
  if (bySource && cfg.sensitiveSourceTools.has(toolName)) tags.push(ToolRiskTag.SENSITIVE);

  if (cfg.untrustedSourceTools.has(toolName)) tags.push(ToolRiskTag.UNTRUSTED_ORIGIN);

  // 원칙 4 default-deny: 미분류 도구의 결과는 신뢰할 수 없다
  if (!isClassifiedTool(cfg, toolName) && !tags.includes(ToolRiskTag.UNTRUSTED_ORIGIN)) {
    tags.push(ToolRiskTag.UNTRUSTED_ORIGIN);
  }
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

function addSessionTags(session: SessionTaintState, tags: ToolRiskTag[]): void {
  for (const tag of tags) {
    if (!session.tags.includes(tag)) session.tags.push(tag);
  }
  session.updatedAt = new Date().toISOString();
}

/** 도구 결과가 도착했을 때 소스를 분류해 세션 오염 상태를 갱신한다. (Image 3 왼쪽 흐름) */
export function tagToolResult(sessionId: string, toolName: string): void {
  const tags = classifySourceTags(toolName);
  addSessionTags(getOrCreateSession(sessionId), tags);
  // 계보 병행 기록 — args/result가 없으므로 연결은 3순위(TEMPORAL_FALLBACK)/NONE으로 떨어진다
  createTaintNode(sessionId, toolName, tags, {});
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
  /** 대응하는 계보 노드 id — 정화 성공 시 그 노드의 태그도 함께 해제하기 위한 연결 고리 */
  nodeId?: string;
}

const payloadStore = new Map<string, RecordedPayload[]>();

/** 출처 기반(1순위) + 내용 기반(2·3순위) 태그를 계산한다 */
function computeResultTags(toolName: string, payload: unknown): ToolRiskTag[] {
  const tags = classifySourceTags(toolName);

  // 내용 기반(2·3순위): 출처가 민감 소스가 아니어도 페이로드에 비밀(고엔트로피
  // 문자열·유명 키 포맷)이 실려 있으면 SENSITIVE — "GitHub 이슈에 유출된 AWS 키" 케이스
  const det = getPolicyConfig().secretDetection;
  if (det && !tags.includes(ToolRiskTag.SENSITIVE) && detectSecrets(payload, det).length > 0) {
    tags.push(ToolRiskTag.SENSITIVE);
  }
  return tags;
}

/**
 * 도구 결과 본문을 세션에 기록하고 태그를 갱신한다.
 * tagToolResult의 상위 호환 — 페이로드까지 넘기면 (a) 내용 기반 비밀 탐지
 * (2·3순위: 엔트로피·정규식)가 동작하고, (b) 나중에 attemptSanitization이
 * 이 데이터를 실제로 정화·검증할 수 있다.
 */
export function recordToolPayload(sessionId: string, toolName: string, payload: unknown): void {
  recordToolResult(sessionId, toolName, undefined, payload);
}

/**
 * recordToolPayload의 풀 기능 확장 — 호출 인자(args)까지 받는 새 진입점.
 * 기존 동작(태깅·세션 갱신·payloadStore 기록)에 더해 계보(lineage) 노드를 만들어
 * 반환한다. args가 있어야 1순위(MCP 참조)·2순위(값 매칭) parent 연결이 가능하다.
 * 계보는 아직 판정에 영향을 주지 않는 병행 기록이다 (전파·정화 연동은 다음 단계).
 */
export function recordToolResult(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown> | undefined,
  result: unknown
): TaintNode {
  const tags = computeResultTags(toolName, result);
  addSessionTags(getOrCreateSession(sessionId), tags);

  // 노드를 먼저 만들어 payload 레코드에 id를 심는다 (정화 ↔ 계보 연동 고리)
  const node = createTaintNode(sessionId, toolName, tags, { args, result });

  if (tags.length > 0) {
    // 깨끗한 소스·내용은 정화 대상이 아니므로 payloadStore에는 기록하지 않는다
    const records = payloadStore.get(sessionId) ?? [];
    records.push({ toolName, tags, payload: result, nodeId: node.id });
    payloadStore.set(sessionId, records);
  }

  return node;
}

// ---------------------------------------------------------------------------
// 검증된 정화 (declassification)
// ---------------------------------------------------------------------------

/**
 * 각 정화 방법이 해제를 검증할 수 있는 태그.
 * - 토큰화: PII·비밀을 불투명 토큰으로 치환했음을 검증 → SENSITIVE 해제
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
 * 2. 각 페이로드에 활성 설정 기준의 정화를 적용하고 검증한다 (sanitization.ts).
 * 3. "전부" 검증을 통과했을 때만 세션과 페이로드에서 targetTag를 해제한다.
 *    하나라도 실패하거나, 검증할 페이로드가 기록돼 있지 않거나, 설정에 해당
 *    방법의 근거(스키마·패턴)가 없으면 태그 유지 (fail-safe).
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
        // 계보 연동: 정화 검증을 통과한 "그 노드"의 태그만 해제.
        // 자식 노드는 절대 건드리지 않는다 — 각자 정화를 통과해야 풀린다 (비대칭).
        if (record.nodeId) declassifyNodeTag(sessionId, record.nodeId, targetTag);
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

  // ---- toy 판정 (실제 차단 결정 — 기존 로직 그대로) ----
  // 인자에 실린 태그 + 세션 누적 태그를 합쳐 "전파된 태그"로 본다
  const effectiveTags = new Set<ToolRiskTag>([...session.tags, ...ctx.argTags]);

  let decision: PolicyDecision;
  if (sinkClass !== SinkClass.OUTBOUND_SINK) {
    decision = { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
  } else {
    const hasSensitive = effectiveTags.has(ToolRiskTag.SENSITIVE);
    const hasUntrusted = effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN);

    if (hasSensitive && hasUntrusted) {
      const matchedTags = [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN];
      emitTrifectaEvent(ctx, sinkClass, matchedTags);
      const unclassified = !isClassifiedTool(getPolicyConfig(), ctx.toolName);
      decision = {
        sessionId: ctx.sessionId,
        toolName: ctx.toolName,
        allowed: false,
        reason:
          "lethal trifecta 감지: 민감 데이터 + 비신뢰 입력이 외부 유출 시도와 겹침" +
          (unclassified ? " (미분류 도구 — default-deny로 OUTBOUND_SINK 취급)" : ""),
        matchedTags,
      };
    } else {
      decision = { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
    }
  }

  // ---- real(계보) 섀도 판정 — 로그 전용 ----
  // toy 결정(decision)은 이 위에서 이미 완성됐다. runShadowEvaluation은 void 반환 +
  // 내부 전체 try/catch + 읽기 전용이므로, 이 호출이 decision을 바꾸거나 예외로
  // 판정 흐름을 깨뜨릴 방법이 없다. 실제 차단은 언제나 toy가 결정한다.
  runShadowEvaluation(ctx, sinkClass, decision.allowed);

  return decision;
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
