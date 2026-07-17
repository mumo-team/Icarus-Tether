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

} from "@icarus-tether/types";
import { getPolicyConfig, type PolicyConfig } from "./config.js";
import { detectSecrets } from "./secret-detection.js";
import { extractStructured, tokenizePII } from "./sanitization.js";
import { createTaintNode, declassifyNodeTag, sessionHasLiveTag, type TaintNode } from "./lineage.js";
import { collectLineageEvidence, runShadowEvaluation } from "./shadow.js";
import { consumeApprovalIfMatching, evaluateOverridability, offerOverride } from "./hitl.js";
import { buildFailSafeExplanation, buildUserExplanation } from "./explain.js";

export { buildUserExplanation, buildFailSafeExplanation, type ExplainInput } from "./explain.js";

export {
  requestApproval,
  resolveApproval,
  getOverrideAuditLog,
  type OverrideAuditEntry,
} from "./hitl.js";

export {
  loadPolicyConfig,
  getPolicyConfig,
  NAMED_CHARSETS,
  type PolicyConfig,
  type UnknownToolPolicy,
  type PropagationMode,
  type JudgmentMode,
  type HitlPolicy,
  type PruningPolicy,
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
export {
  getShadowLog,
  type ShadowLogEntry,
  type ShadowEvidence,
  type LineageEvidence,
} from "./shadow.js";
export {
  addNodeTags,
  getSessionLineage,
  getTaintNode,
  pruneSessionLineage,
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

/** toy 판정 — 세션 boolean(sessionStore) 기준. 순수 계산(이벤트 발행 없음). */
function computeSessionDecision(ctx: ToolCallContext, sinkClass: SinkClass): PolicyDecision {
  const session = getOrCreateSession(ctx.sessionId);

  // 인자에 실린 태그 + 세션 누적 태그를 합쳐 "전파된 태그"로 본다
  const effectiveTags = new Set<ToolRiskTag>([...session.tags, ...ctx.argTags]);

  if (sinkClass !== SinkClass.OUTBOUND_SINK) {
    return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
  }

  const hasSensitive = effectiveTags.has(ToolRiskTag.SENSITIVE);
  const hasUntrusted = effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN);

  if (hasSensitive && hasUntrusted) {
    const unclassified = !isClassifiedTool(getPolicyConfig(), ctx.toolName);
    return {
      sessionId: ctx.sessionId,
      toolName: ctx.toolName,
      allowed: false,
      reason:
        "lethal trifecta 감지: 민감 데이터 + 비신뢰 입력이 외부 유출 시도와 겹침" +
        (unclassified ? " (미분류 도구 — default-deny로 OUTBOUND_SINK 취급)" : ""),
      matchedTags: [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN],
    };
  }

  return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
}

/** 정화 방법 안내 — 차단 reason에 "뭘 하면 풀리는지"를 담기 위한 역매핑 (HITL 대비) */
const CLEAR_HINT = `[해제: ${ToolRiskTag.SENSITIVE}→${SanitizationMethod.TOKENIZATION}, ${ToolRiskTag.UNTRUSTED_ORIGIN}→${SanitizationMethod.STRUCTURED_EXTRACTION}]`;

/**
 * real 판정 — "지금 나가려는 값(호출 인자)의 계보"만 본다.
 * 세션 전체가 아니라 그 값의 부모 노드들의 태그 합집합 + argTags로 트라이펙타 판정:
 *  - 정화된 노드는 태그가 없어 자동 제외
 *  - 나가는 값과 무관한 다른 갈래의 오염은 판정에 영향 없음
 * 계산 실패 시 fail-safe로 차단한다 — 실전 결정자이므로 조용한 통과는 금지
 * (로그 전용인 섀도의 실패 처리와 방향이 반대).
 */
function computeLineageDecision(ctx: ToolCallContext, sinkClass: SinkClass): PolicyDecision {
  try {
    if (sinkClass !== SinkClass.OUTBOUND_SINK) {
      return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
    }

    const evidence = collectLineageEvidence(ctx);
    const effectiveTags = new Set<ToolRiskTag>([...evidence.unionTags, ...ctx.argTags]);

    // ★ 비대칭 위협 모델: lethal trifecta = (이 값이 실제로 민감 데이터를 담음)
    //   AND (세션이 비신뢰 입력에 노출됨). 근거:
    //   - 민감(S)은 "실제로 나가는가"의 문제라 값-계보(+argTags)로 판정한다.
    //     → 값이 비신뢰-only 갈래(N4/N5)면 민감이 안 나가므로 통과(정밀함 유지).
    //   - 비신뢰(U)는 "제어흐름을 조작해 유출을 유도했는가"의 문제라 body에 그
    //     본문을 안 실어도 위험하다 → 세션-존재로 판정(sessionHasLiveTag).
    //     이것이 "민감 데이터를 그대로 실어 보내는 현실적 exfil"(값은 S 매칭,
    //     비신뢰 본문은 미포함)을 잡아낸다 — 대칭 규칙이 놓치던 경로.
    //   정화로 비신뢰가 노드에서 제거되면 sessionHasLiveTag가 false가 되어
    //   과차단되지 않는다.
    const valueSensitive = effectiveTags.has(ToolRiskTag.SENSITIVE);
    const sessionUntrusted =
      effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN) ||
      sessionHasLiveTag(ctx.sessionId, ToolRiskTag.UNTRUSTED_ORIGIN);

    if (valueSensitive && sessionUntrusted) {
      const hitlPolicy = getPolicyConfig().hitlPolicy;

      // HITL 소비: "이 호출"과 지문이 일치하는 APPROVED·미사용 승인이 있고,
      // ★제안 시점 계보 지문이 현재 evidence와 여전히 일치하면(TOCTOU 재검증)
      // 1회 통과. 그 외(OFFERED/PENDING/REJECTED/불일치/이미 사용/계보 변화)는
      // 전부 아래 차단으로 — "응답 없음 → 통과" 경로가 없다 (fail-safe).
      if (hitlPolicy === "weak-only") {
        const consumed = consumeApprovalIfMatching(ctx, evidence);
        if (consumed) {
          return {
            sessionId: ctx.sessionId,
            toolName: ctx.toolName,
            allowed: true,
            matchedTags: [],
            reason: `HITL 오버라이드 승인으로 1회 통과 (approvalId: ${consumed.approvalId}${consumed.resolvedBy ? `, 승인자: ${consumed.resolvedBy}` : ""})`,
          };
        }
      }

      // b안: 어느 노드가 왜 오염인지 + 뭘 정화하면 풀리는지를 reason에 담는다
      const taintedNodes = evidence.nodes.filter((n) => n.tags.length > 0);
      const nodeDesc = taintedNodes
        .map((n) => `${n.nodeId}(${n.toolName}: ${n.tags.join("+")})`)
        .join(", ");
      const argDesc = ctx.argTags.length > 0 ? ` (인자 태그: ${ctx.argTags.join("+")})` : "";
      const unclassified = !isClassifiedTool(getPolicyConfig(), ctx.toolName);
      // 값 자체가 비신뢰를 안 실었는데 세션-존재로 트리거된 경우(현실적 exfil):
      // 근거에 U 노드가 없을 수 있으므로 "세션 비신뢰 노출"을 명시한다.
      const untrustedInValue = evidence.unionTags.has(ToolRiskTag.UNTRUSTED_ORIGIN) ||
        ctx.argTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN);
      const sessionNote = untrustedInValue
        ? ""
        : " (세션이 비신뢰 입력에 노출됨 — 제어흐름 조작으로 민감 데이터가 유출될 수 있어 차단)";
      const decision: PolicyDecision = {
        sessionId: ctx.sessionId,
        toolName: ctx.toolName,
        allowed: false,
        reason:
          `lethal trifecta 감지(계보 판정): 이 값의 계보에 정화되지 않은 오염 노드가 남아 있어 외부 유출 차단 — ${nodeDesc || "근거 없음"}${argDesc} ${CLEAR_HINT}` +
          sessionNote +
          (unclassified ? " (미분류 도구 — default-deny로 OUTBOUND_SINK 취급)" : ""),
        matchedTags: [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN],
      };

      // HITL 제안: 승인 가능 여부는 결정론 규칙(evaluateOverridability — weak 연결
      // 판정)이 정한다. AI 판단 없음. 차단(allowed:false)은 그대로 유지된다.
      if (hitlPolicy === "weak-only") {
        if (evaluateOverridability(evidence, ctx.argTags)) {
          const approvalId = offerOverride(ctx, evidence); // 제안 시점 계보 지문 저장
          decision.canOverride = true;
          decision.approvalId = approvalId;
          decision.reason += ` [HITL: 승인 요청 가능 — ${approvalId}]`;
        } else {
          decision.canOverride = false; // strong 연결이 오염을 실음 — 사람도 못 여는 확정 차단
        }
      }

      // 사용자용 설명 계층 — 개발자용 reason은 그대로 두고, 사람 말 번역을 별도 필드로.
      // 결정론 템플릿 매핑(explain.ts)이라 AI 판단 없음.
      decision.explanation = buildUserExplanation({
        evidence,
        argTags: ctx.argTags,
        canOverride: decision.canOverride ?? false,
        approvalId: decision.approvalId,
      });
      return decision;
    }

    return { sessionId: ctx.sessionId, toolName: ctx.toolName, allowed: true, matchedTags: [] };
  } catch (err) {
    // fail-safe: real이 실전 결정자일 때 계산 실패는 차단이다. 조용한 통과 경로 없음.
    console.error("[policy-engine] 계보 판정 계산 실패 — fail-safe 차단:", err);
    return {
      sessionId: ctx.sessionId,
      toolName: ctx.toolName,
      allowed: false,
      reason: "계보 판정 계산 실패 — fail-safe 차단 (오류 시 통과 금지)",
      matchedTags: [],
      explanation: buildFailSafeExplanation(),
    };
  }
}

/** 도구 호출 시도 시 트라이펙타 여부를 판정한다. (Image 3 오른쪽 흐름) */
export function evaluateToolCall(ctx: ToolCallContext): PolicyDecision {
  const sinkClass = classifySink(ctx.toolName);
  const mode = getPolicyConfig().judgmentMode;

  // 실제 차단 결정자 선택 — 기본 "session"(toy). "lineage"(real)는 설정으로 명시해야 켜진다.
  const decision =
    mode === "lineage"
      ? computeLineageDecision(ctx, sinkClass)
      : computeSessionDecision(ctx, sinkClass);

  // 실제 차단이 확정된 트라이펙타에만 이벤트 발행
  // (fail-safe 차단은 탐지가 아니라 운영 오류이므로 matchedTags가 비어 있고, 발행하지 않는다)
  if (!decision.allowed && decision.matchedTags.length > 0) {
    emitTrifectaEvent(ctx, sinkClass, decision.matchedTags);
  }

  // session·shadow 모드: real(계보) 섀도 판정을 로그로만 남긴다 (비교 데이터 수집).
  // runShadowEvaluation은 void + 전체 try/catch + 읽기 전용이라 decision에 관여 불가.
  // lineage 모드에서는 생략 — "toy가 결정자"라는 비교 로그의 전제가 성립하지 않고,
  // 판정 근거는 decision.reason에 직접 담긴다.
  if (mode !== "lineage") {
    runShadowEvaluation(ctx, sinkClass, decision.allowed);
  }

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
