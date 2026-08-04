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
  type OutputScanEvent,
  type SanitizationResult,
  SanitizationMethod,

} from "@icarus-tether/types";
import { getPolicyConfig, type PolicyConfig } from "./config.js";
import { detectSecrets } from "./secret-detection.js";
import {
  extractStructured,
  tokenizePII,
  containsVaultOriginal,
  countVaultTokens,
  hasNonTokenContent,
} from "./sanitization.js";
import {
  scanOutputForSensitive,
  type OutputScanFinding,
  type SensitivePayload,
} from "./output-scan.js";
import {
  collectLiveTagHolders,
  createTaintNode,
  declassifyNodeTag,
  type TaintNode,
} from "./lineage.js";
import { collectLineageEvidence, runShadowEvaluation, type LineageEvidence } from "./shadow.js";
import {
  consumeApprovalIfMatching,
  evaluateOverridability,
  offerOverride,
  peekApprovalMatches,
} from "./hitl.js";
import {
  buildDestructiveExplanation,
  buildFailSafeExplanation,
  buildOutboundExfilExplanation,
  buildUserExplanation,
} from "./explain.js";

export {
  buildUserExplanation,
  buildFailSafeExplanation,
  buildDestructiveExplanation,
  buildOutboundExfilExplanation,
  type ExplainInput,
  type DestructiveExplainInput,
} from "./explain.js";

export {
  requestApproval,
  resolveApproval,
  getOverrideAuditLog,
  type OverrideAuditEntry,
} from "./hitl.js";

export {
  loadPolicyConfig,
  getPolicyConfig,
  reloadPolicyConfig,
  NAMED_CHARSETS,
  type PolicyConfig,
  type UnknownToolPolicy,
  type PropagationMode,
  type JudgmentMode,
  type HitlPolicy,
  type PruningPolicy,
  type DestructivePolicy,
  type SecretDetectionConfig,
  type ExtractionSchemaConfig,
  type FieldSpec,
  type PatternSpec,
} from "./config.js";
export { loadToolRegistry, type ToolRegistry } from "./registry.js";
export {
  detectSecrets,
  shannonEntropy,
  type DetectedSecret,
} from "./secret-detection.js";
export {
  canExtractStructured,
  canTokenize,
  extractStructured,
  tokenizePII,
  resolveToken,
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
  collectLiveTagHolders,
  getSessionLineage,
  getTaintNode,
  getTombstoneTags,
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

/** 설정의 어느 목록에든 등장하는(= 우리가 성질을 아는) 도구인가.
 *  ★ destructiveTools도 포함 (자기-오염 수정): 파괴 목록에만 등록된 도구를
 *  미분류 취급하면 그 결과에 UNTRUSTED_ORIGIN이 자동 부착돼(원칙 4 default-deny),
 *  사용자 직접 지시 삭제 1회만으로 세션이 U-오염되어 두 번째 직접 삭제가 파괴
 *  게이트에 차단된다 — "사용자가 시킨 삭제는 통과" 요구사항의 위반. */
function isClassifiedTool(cfg: PolicyConfig, toolName: string): boolean {
  return (
    cfg.sensitiveSourceTools.has(toolName) ||
    cfg.untrustedSourceTools.has(toolName) ||
    cfg.sinks.has(toolName) ||
    cfg.destructiveTools.has(toolName)
  );
}

function classifySink(toolName: string): SinkClass {
  const cfg = getPolicyConfig();
  const explicit = cfg.sinks.get(toolName);
  if (explicit) return explicit;

  // ★ 원칙 4(모르면 의심 = default-deny)를 싱크 축에도 적용 (fail-open #2 수정):
  // 싱크 등급이 명시되지 않았으면 "외부 유출 능력이 없다는 보장"이 없다. 소스로
  // 등록된 도구라도(웹 fetch처럼 GET URL로 유출 가능한 이중능력일 수 있으므로)
  // READ로 강등하지 않는다 — 이전 구현은 소스면 무조건 READ라 소스 도구를 통한
  // 유출이 트라이펙타 검사를 통째로 건너뛰었다(미탐). read-only임을 확신하는
  // 소스는 설정의 sinks에 "READ"(또는 "WRITE_INTERNAL")로 명시할 것.
  if (cfg.unknownToolPolicy === "warn") {
    console.warn(
      `[policy-engine] 싱크 미선언 도구 "${toolName}" — unknownToolPolicy=warn이라 READ로 취급 (차단 안 함)`
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

/**
 * ★ 비신뢰 노출이력 (F1 세탁 방지) — grow-only. 세션이 UNTRUSTED_ORIGIN을 한 번이라도
 * 획득하면 여기에 기록되고, 이후 절대 제거되지 않는다(정화 불변). 정화(attemptSanitization)
 * 는 session.tags·계보 노드 태그만 떼고 이 집합은 건드리지 않으므로, "정화로 세션 U축을
 * 꺼서 무관한 유출·삭제를 여는" 미탐(C1/P6)이 막힌다.
 *
 * 판정에서의 역할 (비대칭 위협 모델의 U축을 이걸로 판정):
 *  - 유출: sessionUntrusted = 노출이력. 단 valueSensitive AND 유지 → S를 토큰화하면
 *    통과(RE35), U-only는 S가 없어 통과(RE36), "U 정화 후 무관 S 전송"(C1)만 차단.
 *  - 파괴: 발동 = 노출이력 (정화로 못 품, HITL 승인만 해제 — P6 완전 차단).
 * 형식모델: TaintLineage.tla exposure(ExfilSafety·ExposureMonotone),
 * TaintDestructiveHITL.tla exposure(DestructiveSafety·ExposureMonotone) — TLC 위반 0.
 */
const sessionExposure = new Set<string>();

/** 세션이 비신뢰에 노출된 적 있는가 (정화 불변). shadow.ts 등 판정 밖 소비자용 읽기 접근. */
export function isSessionExposed(sessionId: string): boolean {
  return sessionExposure.has(sessionId);
}

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
  // ★ 노출이력 세팅 (grow-only) — U가 세션에 들어오는 단일 통로가 여기다.
  // 정화는 session.tags를 직접 필터링(이 함수 미경유)하므로 노출이력은 정화 불변.
  if (tags.includes(ToolRiskTag.UNTRUSTED_ORIGIN)) sessionExposure.add(session.sessionId);
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

/**
 * TIER3 출력-스캔용: 이 세션이 실제로 읽은 "아직 민감한(정화 안 된)" 원본값 목록.
 * 정화(attemptSanitization)를 통과한 레코드는 tags에서 SENSITIVE가 벗겨지므로 자동
 * 제외된다 → "정화 후 정상 공유"는 스캔 대상이 아니라 과차단되지 않는다.
 */
function getSensitivePayloads(sessionId: string): SensitivePayload[] {
  const records = payloadStore.get(sessionId) ?? [];
  const out: SensitivePayload[] = [];
  for (const r of records) {
    if (r.tags.includes(ToolRiskTag.SENSITIVE)) out.push({ toolName: r.toolName, payload: r.payload });
  }
  return out;
}

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

/**
 * ★ 도구가 아닌 외부 콘텐츠 유입(SOURCE) 진입점 — resources/read·prompts/get 대응.
 *
 * 배경(파트1 확정): 프록시는 tools/call만 엔진에 넘기고 resources/read·prompts/get은
 * 무검사 중계했다 → 외부 비신뢰 콘텐츠가 exposure(U축)를 못 켜서, 같은 lethal-trifecta
 * 유출이 채널만 바꾸면 통과했다(출력스캔까지 무력화 — U축 의존). 이 API가 그 콘텐츠를
 * recordToolResult와 동일한 파이프라인(태깅 → addSessionTags[exposure] → createTaintNode)
 * 에 흘려보내 미탐을 막는다.
 *
 * 태깅(미탐-0 = default-deny, 원칙 4): trusted가 아니면 UNTRUSTED_ORIGIN(외부 콘텐츠는
 * 기본 비신뢰 → exposure 진입). 추가로 content에 비밀 패턴이 있으면 SENSITIVE도
 * (computeResultTags와 동일 내용 기반 규칙). trusted:true는 명시적 신뢰(내부 리소스 등)로
 * U를 붙이지 않는다.
 *
 * ★ tools/call 판정 로직 무변경(완전 additive) — recordToolResult가 타는 것과 같은 전이다.
 * 형식모델: TaintLineage.tla CreateNode(exposure' = exposure ∨ UNTRUSTED∈newTags)가 이미
 * 이 의미론을 커버한다(own 비결정 → own={UNTRUSTED} 생성은 모델된 전이). 모델 무수정.
 *
 * 프록시(②)는 fallbackRequestHandler에서 resources/read·prompts/get 응답을 받은 직후
 * 이 함수를 부르면 된다(값-계보를 위해 content 원형을 그대로 넘긴다). uri는 감사·계보 라벨.
 *
 * ★ C-7: opts.trusted를 안 넘기면 엔진이 설정(trustedResourceUris)의 URI 접두사로
 * 신뢰를 판정한다 — URI 신뢰는 정책 판단이므로 registry가 소유한다("성질로 판단,
 * 설정으로"). 프록시가 명시하면 그 값을 존중한다(하위호환 — 단 trusted:true 오전달은
 * 프록시 책임: 엔진은 명시값을 검증하지 않는다).
 */
export function recordExternalContent(
  sessionId: string,
  channel: "resources/read" | "prompts/get",
  uri: string,
  content: unknown,
  opts?: { trusted?: boolean }
): TaintNode {
  const tags = computeExternalContentTags(content, opts?.trusted ?? isResourceUriTrusted(uri));
  addSessionTags(getOrCreateSession(sessionId), tags);

  // 라벨은 채널+uri — '/'·':'를 포함해 실제 도구명과 충돌하지 않는다(감사로그·계보 표시용).
  const label = `${channel}:${uri}`;
  // args가 없어 계보 연결은 3순위(안전바닥)/NONE으로 떨어진다 — 도구 소스와 동일 취급.
  // content는 result로 넘겨 resultTokens를 뽑는다(이후 이 콘텐츠가 나갈 때 VALUE_MATCH용).
  const node = createTaintNode(sessionId, label, tags, { result: content });

  if (tags.length > 0) {
    const records = payloadStore.get(sessionId) ?? [];
    records.push({ toolName: label, tags, payload: content, nodeId: node.id });
    payloadStore.set(sessionId, records);
  }
  return node;
}

/**
 * ★ C-7: 리소스 URI 신뢰 판정 — registry(trustedResourceUris)의 접두사 매칭.
 *
 * 의도적으로 URL 파싱을 하지 않는다: 파서마다 해석이 갈리는 병리 URI(퍼센트 인코딩·
 * 유저인포 `corp@evil.com`·대소문자 스킴 등)가 파서 차이 공격면이 되므로, 문자열
 * 접두사 매칭만 쓴다. 위장의 위험 방향(원격을 신뢰로 오판)은 로드 시 경계 규칙
 * ("://" 포함 + "/" 종료, config.ts)이 막고, 안전 방향(신뢰 자원을 비신뢰로 오판 —
 * 예: "FILE:///" 대문자 스킴)은 default-deny라 과태깅으로 끝난다(우회 아님).
 * 미매칭 = 비신뢰 (원칙 4 default-deny). 기본 설정은 빈 목록 — 아무것도 신뢰하지 않음.
 */
export function isResourceUriTrusted(uri: string): boolean {
  return getPolicyConfig().trustedResourceUris.some((prefix) => uri.startsWith(prefix));
}

/**
 * 외부 콘텐츠(resources/read·prompts/get)의 태그 계산 — default-deny + 내용 기반 SENSITIVE.
 * classifySourceTags(도구명 기반)와 달리 도구 레지스트리를 안 본다: 리소스/프롬프트는
 * "도구"가 아니므로 URI 분류가 아직 없으면 기본 비신뢰다(안전 바닥). URI 기반 신뢰/민감
 * 정련은 후속(설정 trustedResourceUris 등) — 1단계는 미탐만 먼저 막는다.
 */
function computeExternalContentTags(content: unknown, trusted: boolean): ToolRiskTag[] {
  const tags: ToolRiskTag[] = [];
  if (!trusted) tags.push(ToolRiskTag.UNTRUSTED_ORIGIN);
  const det = getPolicyConfig().secretDetection;
  if (det && detectSecrets(content, det).length > 0) tags.push(ToolRiskTag.SENSITIVE);
  return tags;
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
/**
 * "토큰화가 실제로 값을 바꿨나" 비교 — attemptSanitization의 S4 no-op 게이트 전용.
 * fail-safe: 직렬화가 던지면(순환 페이로드 — collectStrings 견고화로 기록은 가능)
 * "안 바뀜"으로 보고해 태그 해제를 막는다. 오류로 태그가 벗겨지는 경로는 없어야 한다.
 */
function payloadChanged(before: unknown, after: unknown): boolean {
  try {
    return JSON.stringify(before) !== JSON.stringify(after);
  } catch {
    return false;
  }
}

export function attemptSanitization(
  sessionId: string,
  method: SanitizationMethod
): SanitizationResult {
  const session = getOrCreateSession(sessionId);
  const originalTags = [...session.tags];
  const targetTag = METHOD_CLEARS[method];

  const records = (payloadStore.get(sessionId) ?? []).filter((r) => r.tags.includes(targetTag));

  let sanitized = false;
  // 보고 전용(판정 무관): TOKENIZATION 성공 시에만 채워진다.
  let maskedCount: number | undefined;
  let residualSensitiveData: boolean | undefined;
  if (session.tags.includes(targetTag) && records.length > 0) {
    const outcomes = records.map((r) =>
      method === SanitizationMethod.TOKENIZATION
        ? tokenizePII(r.payload)
        : extractStructured(r.payload)
    );

    // ★ TOKENIZATION "실제 변경" 게이트 (S4 정화 악용 수정):
    // tokenizePII는 내용에 PII/비밀이 없으면 "아무것도 안 바꾸고 ok:true"를 낸다
    // (그 함수의 순수 계약 — 단위 테스트가 요구). 하지만 그 no-op 성공으로 태그를
    // 해제하면, 출처 기반 SENSITIVE(tag_all — 이름·등급 등 PII 아닌 값)가 데이터는
    // 그대로인 채 태그만 벗겨져 유출된다. 그래서 호출부에서 "대상 레코드가 실제로
    // 바뀌었을 때만" 해제한다. STRUCTURED_EXTRACTION은 '스키마 필드만 남김' 자체가
    // 안전 증명이라(불변이어도 안전) 이 게이트를 적용하지 않는다.
    const tokenizationEffective =
      method !== SanitizationMethod.TOKENIZATION ||
      records.every((r, i) => outcomes[i].ok && payloadChanged(r.payload, (outcomes[i] as { value: unknown }).value));

    if (outcomes.every((o) => o.ok) && tokenizationEffective) {
      // 검증 통과 — 페이로드를 정화된 값으로 교체하고 태그 해제
      records.forEach((record, i) => {
        const outcome = outcomes[i];
        if (outcome.ok) {
          // ★ 정화 보고 정직화 (판정 영향 0 — 보고 전용 계산):
          //  - maskedCount: 이번 치환으로 늘어난 토큰 자리 수.
          //  - residualSensitiveData: 출처 기반(tag_all) 민감 페이로드에서 토큰 밖 내용이
          //    남았는가 = 패턴으로 못 가린 비중화 민감 잔존("부분 정화"). 내용 기반
          //    SENSITIVE(비밀 탐지)는 비밀만 가리면 완화되므로 잔존 판정에서 제외한다.
          if (method === SanitizationMethod.TOKENIZATION) {
            maskedCount = (maskedCount ?? 0) + countVaultTokens(outcome.value) - countVaultTokens(record.payload);
            if (
              classifySourceTags(record.toolName).includes(ToolRiskTag.SENSITIVE) &&
              hasNonTokenContent(outcome.value)
            ) {
              residualSensitiveData = true;
            }
          }
          record.payload = outcome.value;
        }
        record.tags = record.tags.filter((t) => t !== targetTag);
        // 계보 연동: 정화 검증을 통과한 "그 노드"의 태그만 해제.
        // 자식 노드는 절대 건드리지 않는다 — 각자 정화를 통과해야 풀린다 (비대칭).
        if (record.nodeId) declassifyNodeTag(sessionId, record.nodeId, targetTag);
      });
      if (method === SanitizationMethod.TOKENIZATION) residualSensitiveData ??= false;
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
    // 정화 성공(TOKENIZATION) 시에만 채워지는 보고 필드 — 실패/타 방법이면 생략
    ...(maskedCount !== undefined ? { maskedCount } : {}),
    ...(residualSensitiveData !== undefined ? { residualSensitiveData } : {}),
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
  // ★ U축은 노출이력(정화 불변)으로 판정 — 정화로 session.tags의 U가 빠져도
  // 노출됐던 세션은 여전히 U로 본다 (F1 세탁 방지). argTags/이 호출의 U도 포함.
  const hasUntrusted =
    effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN) || sessionExposure.has(ctx.sessionId);

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
    //     본문을 안 실어도 위험하다 → 세션 노출이력(sessionExposure)으로 판정.
    //     이것이 "민감 데이터를 그대로 실어 보내는 현실적 exfil"(값은 S 매칭,
    //     비신뢰 본문은 미포함)을 잡아낸다 — 대칭 규칙이 놓치던 경로.
    //   ★ F1(C1 세탁 방지): 노출이력은 grow-only라 정화로 꺼지지 않는다. 이전엔
    //     live 노드 존재(sessionHasLiveTag)로 봐서, 비신뢰 노드를 정화하면 U축이
    //     꺼져 무관한 S 유출이 열렸다(C1). 이제 정화해도 U축이 유지된다 — 재개방은
    //     S를 토큰화(valueSensitive를 끔)해야만 되며, U 정화로는 안 된다(의도된
    //     트레이드오프: 노출 세션은 영구 U 취급).
    //
    // ★ 원본 재전송 탐지(S4 정화 악용 #2): 정화는 노드 태그만 벗기므로, 정화 후
    //   "정화 전 원본"을 그대로 재전송하면 계보상 깨끗해 통과한다. 나가는 값에
    //   볼트 원본(실제로 토큰화된 PII/비밀)이 들어 있으면 값-민감으로 본다.
    const resendsSanitizedOriginal = containsVaultOriginal(ctx.args);

    // ★ TIER3 출력-스캔 (미탐 #1 벡터 A): 값-계보가 세탁으로 놓친 민감을 값의 *내용*에서
    //   직접 잡는다. (1) 세션이 읽은 민감 원본이 출력에 포함(청크 재조립 포함)되었거나
    //   (2) 출력에 verbatim 비밀 키 패턴이 있으면 값-민감으로 본다. 엔트로피는 안 쓴다
    //   (고엔트로피 정상값 SHA/UUID/JWT 과차단 방지). OUTBOUND_SINK 경로에서만 실행.
    const outputScanFinding = scanOutputForSensitive(
      getSensitivePayloads(ctx.sessionId),
      ctx.args,
      getPolicyConfig().secretDetection
    );

    const valueSensitive =
      effectiveTags.has(ToolRiskTag.SENSITIVE) || resendsSanitizedOriginal || outputScanFinding !== null;
    // ★ U축 = 노출이력(정화 불변, F1 세탁 방지). 이전엔 sessionHasLiveTag(정화로
    // 꺼짐)라, 공격자가 비신뢰 노드를 정화해 U축을 세탁하면 무관한 S 유출이 열렸다(C1).
    // valueSensitive AND는 유지되므로 S 토큰화 시엔 여전히 통과(RE35 과차단 없음).
    const sessionUntrusted =
      effectiveTags.has(ToolRiskTag.UNTRUSTED_ORIGIN) || sessionExposure.has(ctx.sessionId);

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
      const resendNote = resendsSanitizedOriginal
        ? " (정화 전 원본 값이 나가는 값에 감지됨 — 정화된 값이 아닌 원본 재전송 차단)"
        : "";
      const outputScanNote = outputScanFinding
        ? outputScanFinding.kind === "containment"
          ? outputScanFinding.normalized
            ? " (출력-스캔: 세션이 읽은 민감 원본이 재포맷/인코딩돼 나가는 값에 포함됨 — 정규화 매칭으로 세탁 유출 차단)"
            : " (출력-스캔: 세션이 읽은 민감 원본이 나가는 값에 포함됨 — 세탁 유출 차단)"
          : " (출력-스캔: 나가는 값에서 비밀 키 패턴 감지 — 유출 차단)"
        : "";
      const decision: PolicyDecision = {
        sessionId: ctx.sessionId,
        toolName: ctx.toolName,
        allowed: false,
        reason:
          `lethal trifecta 감지(계보 판정): 이 값의 계보에 정화되지 않은 오염 노드가 남아 있어 외부 유출 차단 — ${nodeDesc || "근거 없음"}${argDesc} ${CLEAR_HINT}` +
          sessionNote +
          resendNote +
          outputScanNote +
          (unclassified ? " (미분류 도구 — default-deny로 OUTBOUND_SINK 취급)" : ""),
        matchedTags: [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN],
      };

      // TIER3 출력-스캔이 차단에 기여했으면 이벤트를 방출하고 판정에 실어 프록시가
      // 대시보드로 전달하게 한다 (③가 type:"output_scan" 구독).
      if (outputScanFinding) {
        decision.outputScan = emitOutputScanEvent(ctx, sinkClass, outputScanFinding);
      }

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

// ---------------------------------------------------------------------------
// 파괴적 액션 게이트 — 유출과 직교인 additive 축: "삭제 자체"가 아니라
// "비신뢰가 유발한 파괴"만 차단한다. 의미론의 선행 확정본:
// formal/TaintDestructiveHITL.tla (DestructiveSafety·ApprovalFreshness·
// GateIsolation, TLC 위반 0).
// ---------------------------------------------------------------------------

interface DestructiveGateState {
  holders: Array<{ nodeId: string; toolName: string; tags: ToolRiskTag[] }>;
  /** HITL 승인 지문 입력 — "승인은 이 U-그림에만 유효" (ApprovalFreshness) */
  evidence: LineageEvidence;
}

/**
 * 게이트 발동 여부 계산 (읽기 전용).
 * null = 게이트 무관(미등록 도구/policy off) 또는 통과(살아있는 U 없음).
 *
 * U 판정은 세션-존재 축만 쓴다 — 비대칭 위협 모델(computeLineageDecision)의 U축과
 * 동일 근거: 인젝션이 유발한 삭제는 호출 args에 비신뢰 바이트를 싣지 않는 경우가
 * 대부분이라 값-계보로는 못 잡는다. 사용자 채팅 지시는 오염 그래프에 들어오지
 * 않으므로(노드는 도구 결과에서만 생성) "사용자 직접 지시 삭제"는 구조적으로
 * U가 없어 통과한다. 정화(구조화 추출)가 U를 해제하면 다시 통과된다.
 *  - lineage 모드: 살아있는 U-보유자(live 노드 + 묘비 잔존) 존재
 *  - session/shadow 모드: 세션 boolean 태그 (toy 판정과 같은 소스)
 *  - argTags의 U는 모드 무관 발동 (프록시가 확정 전파한 증거)
 */
function destructiveGateState(ctx: ToolCallContext): DestructiveGateState | null {
  const cfg = getPolicyConfig();
  if (cfg.destructivePolicy === "off" || !cfg.destructiveTools.has(ctx.toolName)) return null;

  // ★ 발동 = 노출이력(정화 불변, 모드 무관). 정화로 live U를 다 떼도 노출됐던
  // 세션의 삭제는 여전히 차단 — HITL 승인만 해제(P6 완전 차단). holders는 여전히
  // 승인 지문(evidence)용으로 현재 live U를 스냅샷한다(TOCTOU freshness — 모델 dSnap=uSet).
  const holders = collectLiveTagHolders(ctx.sessionId, ToolRiskTag.UNTRUSTED_ORIGIN);
  const sessionUntrusted = sessionExposure.has(ctx.sessionId);
  if (!sessionUntrusted && !ctx.argTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN)) return null;

  // 스냅샷을 LineageEvidence 모양으로 접어 기존 lineageFingerprintOf에 태운다 —
  // 검증된 TOCTOU 수명주기의 동형 재사용. weak:true 균일 — 세션-존재 판정에는
  // 연결 신뢰도 개념이 없다 (결정론 상수라 지문 결정성에 영향 없음).
  const evidence: LineageEvidence = {
    linkMethod: "NONE",
    nodes: holders.map((h) => ({ nodeId: h.nodeId, toolName: h.toolName, tags: h.tags, weak: true })),
    unionTags: new Set(holders.flatMap((h) => h.tags)),
  };
  return { holders, evidence };
}

/** 파괴 차단 결정 조립 — "hitl"이면 낡은 승인 정리 후 제안 발급(항상 오버라이드 가능). */
function destructiveBlockDecision(ctx: ToolCallContext, gate: DestructiveGateState): PolicyDecision {
  const policy = getPolicyConfig().destructivePolicy;
  const holderDesc = gate.holders.map((h) => `${h.nodeId}(${h.toolName})`).join(", ");
  const decision: PolicyDecision = {
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    allowed: false,
    reason:
      `파괴적 액션 차단(비신뢰-유발 의심): 세션이 신뢰할 수 없는 외부 입력에 노출된 상태의 ` +
      `되돌리기 어려운 도구 호출 — ${holderDesc || "인자 태그 근거"} ` +
      `[해제: ${ToolRiskTag.UNTRUSTED_ORIGIN}→${SanitizationMethod.STRUCTURED_EXTRACTION}]`,
    // TrifectaEvent(두 태그 합류)와 구분되는 단일-태그 사실 기록. 발행 경로는
    // evaluateToolCall이 유출 판정에만 바인딩하므로 이 값으로 오발행되지 않는다.
    matchedTags: [ToolRiskTag.UNTRUSTED_ORIGIN],
  };
  if (policy === "hitl") {
    // 유출의 weak-only와 달리 항상 오버라이드 가능 — 게이트의 목적이 "사용자가
    // 정말 시킨 게 맞는지"의 사람 확인이기 때문(설계 결정). 낡은(지문 불일치)
    // 승인이 남아 있으면 이 소비 시도가 소각·감사(OVERRIDE_STALE)한다 — 소비
    // "성공"이 없음은 호출부(peek)가 이미 확인한 상태다.
    consumeApprovalIfMatching(ctx, gate.evidence, "destructive");
    const approvalId = offerOverride(ctx, gate.evidence, "destructive");
    decision.canOverride = true;
    decision.approvalId = approvalId;
    decision.reason += ` [HITL: 승인 요청 가능 — ${approvalId}]`;
  } else {
    decision.canOverride = false; // "block": 확정 차단
  }
  decision.explanation = buildDestructiveExplanation({
    holders: gate.holders,
    canOverride: decision.canOverride ?? false,
    approvalId: decision.approvalId,
  });
  return decision;
}

/** 파괴 게이트 fail-safe 차단 — 유출 판정의 fail-safe와 동일 방향(조용한 통과 금지). */
function destructiveFailSafe(ctx: ToolCallContext, err: unknown): PolicyDecision {
  console.error("[policy-engine] 파괴 게이트 계산 실패 — fail-safe 차단:", err);
  return {
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    allowed: false,
    reason: "파괴 게이트 계산 실패 — fail-safe 차단 (오류 시 통과 금지)",
    matchedTags: [],
    explanation: buildFailSafeExplanation(),
  };
}

/**
 * session/shadow 모드용 파괴 게이트 적용 — 유출(toy) 통과 뒤에 합성한다.
 * null = 게이트 무관/통과 (호출부가 유출 결정을 그대로 반환).
 * session 모드에는 유출 승인 소비 경로가 없으므로(HITL은 lineage 전용) 승인
 * 소각(burn) 우려가 없어 peek 없이 바로 소비를 시도한다.
 */
function applyDestructiveGate(ctx: ToolCallContext): PolicyDecision | null {
  const gate = destructiveGateState(ctx);
  if (!gate) return null;
  try {
    if (getPolicyConfig().destructivePolicy === "hitl") {
      const consumed = consumeApprovalIfMatching(ctx, gate.evidence, "destructive");
      if (consumed) {
        return {
          sessionId: ctx.sessionId,
          toolName: ctx.toolName,
          allowed: true,
          matchedTags: [],
          reason: `파괴 게이트: HITL 승인으로 1회 통과 (approvalId: ${consumed.approvalId}${consumed.resolvedBy ? `, 승인자: ${consumed.resolvedBy}` : ""})`,
        };
      }
    }
    return destructiveBlockDecision(ctx, gate);
  } catch (err) {
    return destructiveFailSafe(ctx, err);
  }
}

/**
 * lineage 모드: 유출 판정과 파괴 게이트의 합성 — 승인 소각 방지 peek 프로토콜.
 *
 * 문제: 유출 승인 소비는 computeLineageDecision "안"에서 일어난다. 순서를 단순히
 * "유출 → 파괴"로 하면, 유출 승인이 소비돼 통과한 직후 파괴가 차단하는 경우
 * 그 승인이 실행 없이 소각된다(single-use). 역순도 대칭으로 파괴 승인이 소각된다.
 *
 * 프로토콜 (동기 단일 스레드라 peek↔consume 사이 상태 변화 없음):
 *  1. 파괴가 차단 예정 + 소비 가능한 파괴 승인 없음(peek) → 유출 판정을 아예
 *     돌리지 않고 파괴 차단 반환 (유출 승인 보존).
 *  2. 파괴 승인 있음(peek) → 유출 판정 실행(유출 승인 소비 가능) → 유출 통과
 *     시에만 파괴 승인을 실제 소비 → 통과. 유출이 차단이면 파괴 승인 미소비
 *     보존 — 두 승인을 다 받아둔 상태면 재시도 1회로 통과한다.
 */
function evaluateLineageWithDestructiveGate(
  ctx: ToolCallContext,
  sinkClass: SinkClass
): PolicyDecision {
  const gate = destructiveGateState(ctx);
  if (!gate) {
    const exfil = computeLineageDecision(ctx, sinkClass);
    if (!exfil.allowed && exfil.matchedTags.length > 0) {
      emitTrifectaEvent(ctx, sinkClass, exfil.matchedTags);
    }
    return exfil;
  }
  try {
    const hasDestructiveApproval =
      getPolicyConfig().destructivePolicy === "hitl" &&
      peekApprovalMatches(ctx, gate.evidence, "destructive");
    if (!hasDestructiveApproval) {
      return destructiveBlockDecision(ctx, gate); // 유출 판정 생략 — 유출 승인 보존
    }
    const exfil = computeLineageDecision(ctx, sinkClass);
    if (!exfil.allowed) {
      if (exfil.matchedTags.length > 0) emitTrifectaEvent(ctx, sinkClass, exfil.matchedTags);
      return exfil; // 파괴 승인 미소비 보존
    }
    const consumed = consumeApprovalIfMatching(ctx, gate.evidence, "destructive");
    if (!consumed) {
      // peek=true였으므로 동기 실행에선 도달 불가 — 도달 자체가 이상 상태라 차단
      return destructiveBlockDecision(ctx, gate);
    }
    return {
      ...exfil,
      reason: [
        exfil.reason,
        `파괴 게이트: HITL 승인으로 1회 통과 (approvalId: ${consumed.approvalId}${consumed.resolvedBy ? `, 승인자: ${consumed.resolvedBy}` : ""})`,
      ]
        .filter(Boolean)
        .join(" / "),
    };
  } catch (err) {
    return destructiveFailSafe(ctx, err);
  }
}

/** 도구 호출 시도 시 트라이펙타·파괴 게이트를 판정한다. (Image 3 오른쪽 흐름) */
export function evaluateToolCall(ctx: ToolCallContext): PolicyDecision {
  const sinkClass = classifySink(ctx.toolName);
  const mode = getPolicyConfig().judgmentMode;

  // lineage 모드 — 유출(real)과 파괴 게이트를 peek 프로토콜로 합성.
  if (mode === "lineage") {
    return evaluateLineageWithDestructiveGate(ctx, sinkClass);
  }

  // session·shadow 모드 — 유출(toy) 판정 먼저. TrifectaEvent와 섀도 비교는
  // "유출 판정"에만 바인딩한다: 파괴 게이트가 합성된 최종값을 섀도에 넘기면
  // toy↔real 비교에 허위 불일치가 쌓이고(순수성), 파괴 차단의 matchedTags([U])가
  // TrifectaEvent를 오발행한다.
  const exfil = computeSessionDecision(ctx, sinkClass);
  if (!exfil.allowed && exfil.matchedTags.length > 0) {
    emitTrifectaEvent(ctx, sinkClass, exfil.matchedTags);
  }
  // runShadowEvaluation은 void + 전체 try/catch + 읽기 전용이라 decision에 관여 불가.
  runShadowEvaluation(ctx, sinkClass, exfil.allowed, sessionExposure.has(ctx.sessionId));
  if (!exfil.allowed) return exfil;
  return applyDestructiveGate(ctx) ?? exfil;
}

// ---------------------------------------------------------------------------
// 역방향 아웃바운드 콘텐츠 판정 — tools/call이 아닌 채널로 "서버로 돌아가는 콘텐츠"의 유출 검사.
//
// 배경(전수 조사 D-1): 프록시는 tools/call만 evaluateToolCall로 검사하고,
// sampling/createMessage 같은 역방향 요청은 fallbackRequestHandler에서 무검사 중계했다.
// sampling은 서버→클라 LLM 역요청이고 그 응답(LLM 출력)이 서버로 돌아가므로, 오염 세션에서
// 응답에 민감 데이터가 실리면 lethal-trifecta와 동형의 유출인데 판정이 전혀 안 돌았다
// (출력스캔까지 무력화 — U축 의존). 이 API가 "서버로 나가는 콘텐츠"를 tools/call 유출 판정과
// 같은 가드에 태워 미탐을 막는다.
//
// ★ 완전 additive — evaluateToolCall/computeLineageDecision 무변경. 판정을 tools/call
// 유출 경로(computeLineageDecision)와 **동일 강도**로 맞춘다: 나가는 콘텐츠를 아웃바운드
// 싱크 인자처럼 보고, 같은 프리미티브(collectLineageEvidence 값-계보 + 출력스캔 + 볼트원본)
// 로 valueSensitive를 계산하고, U축은 노출이력으로 본다.
//   valueSensitive = (콘텐츠 계보에 SENSITIVE) OR 출력스캔(containment/regex) OR 볼트원본재전송
//   sessionUntrusted = 노출이력(grow-only, 정화 불변 F1)
// 값-계보를 반드시 재사용하는 이유: LLM 요약은 민감 원본을 발췌·재포맷하므로 출력스캔
// containment(전체 문자열 일치)만으로는 놓친다. tools/call은 이를 VALUE_MATCH로 잡는데,
// 역방향(더 위험한 채널)이 그보다 느슨하면 방어 불가능한 비대칭이 된다. 계보 미스 시엔
// TEMPORAL_FALLBACK이 오염 frontier에 연결해 "오염 세션의 아웃바운드는 보수적 차단"까지
// tools/call과 동일하게 동작한다(과차단 대칭 — 깨끗한 세션은 노드가 없어 통과).
//
// 형식모델: TaintLineage.tla ReachSink(n) 가드 `~(SENSITIVE ∈ tags[n] ∧ exposure)`는
// 채널 불문 "민감값이 노출 세션에서 sink 도달 시 차단"이라 이 전이를 이미 커버한다.
// sampling은 sink 도달의 새 실현일 뿐 — 모델 무수정(recordExternalContent가 CreateNode의
// 새 실현이었던 것과 동형).
//
// 차단 의미론(default-deny, 원칙 4): 역방향은 자연스러운 "재시도" 지점이 없어 HITL
// 재개방을 제시하지 않는 하드 블록이다(computeLineageDecision의 weak-only offer 미사용).
// 프록시(②)는 allowed=false면 LLM 응답을 서버에 돌려주지 말고 MCP 에러로 대체해야 한다.
// 반환형은 PolicyDecision(toolName=channel) — shared/types 무변경, 프록시가
// broadcastDecision/recordAudit를 그대로 재사용한다.
// ---------------------------------------------------------------------------

/** evaluateOutboundContent가 검사하는 아웃바운드 채널. 유입(source)이 아니라 유출(sink) 축이다.
 *  resources/read·prompts/get은 ③ 결정: 비신뢰 대상으로 나가는 "요청 자체"가 유출구다
 *  (URI 쿼리에 데이터 싣기 등) — evaluateResourceRequest가 비신뢰일 때만 이 경로로 넘긴다. */
export type OutboundChannel = "sampling/createMessage" | "resources/read" | "prompts/get";

/**
 * 서버로 돌아가려는 아웃바운드 콘텐츠(sampling 응답 등)를 유출 관점에서 판정한다.
 *
 * @param content 서버로 나가는 콘텐츠 원형(sampling 응답의 content 등). 문자열이 아니어도
 *                되며(객체·배열) 내부 모든 문자열을 재귀 수집해 검사·계보 매칭한다.
 * @returns PolicyDecision. allowed=false면 프록시가 응답 대신 에러를 서버로 반환할 것.
 *
 * 정상 케이스(오염 없는 세션)는 통과한다 — 과차단은 tools/call과 대칭이다.
 */
export function evaluateOutboundContent(
  sessionId: string,
  channel: OutboundChannel,
  content: unknown
): PolicyDecision {
  // 나가는 콘텐츠를 아웃바운드 싱크의 "인자"처럼 취급한다 — 계보 값-매칭과 이벤트 방출기
  // (ToolCallContext를 받음)가 그대로 재사용된다. 채널명을 toolName으로(‘/’ 포함 → 실제
  // 도구명과 충돌 없음), content를 args로 접는다.
  const ctx: ToolCallContext = {
    sessionId,
    toolName: channel,
    args: { content } as Record<string, unknown>,
    argTags: [],
    timestamp: new Date().toISOString(),
  };
  try {
    // ① 값-계보: 콘텐츠 토큰이 어느 오염 노드에서 왔나 (computeLineageDecision과 동일).
    const evidence = collectLineageEvidence(ctx);
    // ② 출력스캔(TIER3): 세션이 읽은 민감 원본 포함(세탁·재조립) 또는 verbatim 비밀 키.
    const outputScanFinding = scanOutputForSensitive(
      getSensitivePayloads(sessionId),
      content,
      getPolicyConfig().secretDetection
    );
    // ③ 볼트 원본 재전송: 정화 후 원본을 그대로 되보내는 세탁 우회.
    const resendsSanitizedOriginal = containsVaultOriginal(content);

    const valueSensitive =
      evidence.unionTags.has(ToolRiskTag.SENSITIVE) ||
      resendsSanitizedOriginal ||
      outputScanFinding !== null;
    // U축 = 노출이력(grow-only, 정화 불변 — F1). tools/call U축과 동일.
    const sessionUntrusted = sessionExposure.has(sessionId);

    if (valueSensitive && sessionUntrusted) {
      const taintedNodes = evidence.nodes.filter((n) => n.tags.length > 0);
      const nodeDesc = taintedNodes
        .map((n) => `${n.nodeId}(${n.toolName}: ${n.tags.join("+")})`)
        .join(", ");
      const resendNote = resendsSanitizedOriginal
        ? " (정화 전 볼트 원본이 나가는 콘텐츠에 감지됨 — 원본 재전송)"
        : "";
      const outputScanNote = outputScanFinding
        ? outputScanFinding.kind === "containment"
          ? outputScanFinding.normalized
            ? " (출력-스캔: 세션이 읽은 민감 원본이 재포맷/인코딩돼 나가는 콘텐츠에 포함됨)"
            : " (출력-스캔: 세션이 읽은 민감 원본이 나가는 콘텐츠에 포함됨)"
          : " (출력-스캔: 나가는 콘텐츠에서 비밀 키 패턴 감지)"
        : "";
      const decision: PolicyDecision = {
        sessionId,
        toolName: channel,
        allowed: false,
        reason:
          `lethal trifecta 감지(역방향 아웃바운드 판정): 세션이 비신뢰 입력에 노출된 상태에서 ` +
          `민감 데이터가 '${channel}' 응답으로 외부 서버에 되돌아가려 해 차단 — ${nodeDesc || "근거: 콘텐츠 값-민감"}` +
          resendNote +
          outputScanNote,
        matchedTags: [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN],
        canOverride: false, // 역방향은 재시도 의미론이 없어 하드 블록 (default-deny)
        explanation: buildOutboundExfilExplanation(),
      };
      if (outputScanFinding) {
        decision.outputScan = emitOutputScanEvent(ctx, SinkClass.OUTBOUND_SINK, outputScanFinding);
      }
      // 채널 불문 트라이펙타 사실 기록 — 대시보드가 tools/call과 동일하게 본다.
      emitTrifectaEvent(ctx, SinkClass.OUTBOUND_SINK, decision.matchedTags);
      return decision;
    }

    return { sessionId, toolName: channel, allowed: true, matchedTags: [] };
  } catch (err) {
    // fail-safe: 역방향도 실전 결정자이므로 계산 실패는 차단이다 (조용한 통과 금지).
    console.error("[policy-engine] 역방향 아웃바운드 판정 계산 실패 — fail-safe 차단:", err);
    return {
      sessionId,
      toolName: channel,
      allowed: false,
      reason: "역방향 아웃바운드 판정 계산 실패 — fail-safe 차단 (오류 시 통과 금지)",
      matchedTags: [],
      canOverride: false,
      explanation: buildFailSafeExplanation(),
    };
  }
}

/**
 * ★ C-7 + ③: 리소스 요청(resources/read·prompts/get)을 "보내기 전" 판정한다.
 *
 * ③ 정책 결정(옵션 B — 비신뢰 대상만): 비신뢰 URI로 나가는 요청은 "읽기"라도 요청
 * 자체가 경계 밖 통신이다 — URI 쿼리에 데이터를 실으면 유출구가 된다(마크다운 이미지
 * URL 유출과 동형, tools/call·sampling을 막은 뒤 남는 마지막 열린 채널). 그래서
 * 요청 params 전체(URI 포함)를 evaluateOutboundContent와 같은 강도로 sink 판정한다.
 *
 * 신뢰 URI(trustedResourceUris 매칭)는 내부 자원 — 요청이 경계를 안 나가므로 sink
 * 검사 없이 통과한다(과차단 방지: 내부 경로 문자열이 우연히 민감값과 겹쳐도 무해).
 * 판정 기준이 유입 태깅(recordExternalContent)과 동일한 registry 규칙이라, "신뢰면
 * U 안 붙고 sink 검사도 없음 / 비신뢰면 U 붙고 sink 검사도 함"이 항상 일치한다.
 *
 * 프록시(②)는 요청을 중계하기 전에 이 함수를 부르고, allowed=false면 중계하지 않는다.
 * params를 안 넘기면 URI만 검사한다(최소 보장).
 */
export function evaluateResourceRequest(
  sessionId: string,
  channel: "resources/read" | "prompts/get",
  uri: string,
  params?: unknown
): PolicyDecision {
  if (isResourceUriTrusted(uri)) {
    return { sessionId, toolName: channel, allowed: true, matchedTags: [] };
  }
  return evaluateOutboundContent(sessionId, channel, params ?? { uri });
}

/**
 * 엔진 내부 관측 로그용 트라이펙타 이벤트 구조 (구 shared/types TrifectaEvent).
 * 계약에서 제거돼(발행 채널·소비자 없음) 로컬로만 유지한다 — 대시보드 표시는
 * PolicyDecision.matchedTags가 담당하고, 이 값은 stderr 로그로만 쓰인다.
 */
interface TrifectaEvent {
  id: string;
  sessionId: string;
  toolName: string;
  matchedTags: ToolRiskTag[];
  sinkClass: SinkClass;
  timestamp: string;
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
  // 관측 로그만 — 대시보드 표시는 PolicyDecision.matchedTags가 담당한다.
  console.log("[policy-engine] TrifectaEvent 발행:", event);
  return event;
}

/** TIER3 출력-스캔 탐지 이벤트 발행 (emitTrifectaEvent와 동일 관례 — 비밀 원본 미포함). */
function emitOutputScanEvent(
  ctx: ToolCallContext,
  sinkClass: SinkClass,
  finding: OutputScanFinding
): OutputScanEvent {
  const event: OutputScanEvent = {
    id: crypto.randomUUID(),
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    sinkClass,
    timestamp: new Date().toISOString(),
    kind: finding.kind,
    sourceTool: finding.sourceTool,
    matchLen: finding.matchLen,
    valueHash: finding.valueHash,
  };
  // TODO(B/C): dashboard·audit-log 쪽으로 발행. 현재는 PolicyDecision.outputScan으로
  // 프록시가 broadcastDecision 경로에 실어 대시보드로 전달한다.
  console.log("[policy-engine] OutputScanEvent 발행:", event);
  return event;
}
