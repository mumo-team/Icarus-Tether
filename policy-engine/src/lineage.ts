/**
 * 값 단위 taint 계보(lineage) 그래프 — 3단계: 정화(declassification) 연동까지.
 *
 * 기존 세션 boolean 방식(sessionStore)을 대체하지 않고 병행 기록한다.
 * 계보 기반 판정 전환은 다음 단계 — 이 모듈은 아직
 * 판정(evaluateToolCall)에 아무 영향을 주지 않는다.
 *
 * parent 연결 3층 (전부 결정론, 우선순위 — 상위 층이 맞으면 하위 층 미시도):
 *   1순위 MCP_REF          — 인자 속에 세션 그래프의 노드 id("tn_…")가 있으면 명시 참조
 *   2순위 VALUE_MATCH      — 이전 노드 결과의 토큰(해시)이 이번 인자 토큰과 일치
 *   3순위 TEMPORAL_FALLBACK — "살아있는 오염의 최전선(루트 보유자)"을 보수적으로
 *                             parent 후보로 (시간 근사, 항상 약한 연결)
 *
 * ★ 3순위는 단순 else가 아니라 "안전 바닥(fail-safe floor)"이다: VALUE_MATCH가
 *   깨끗한 노드에만 걸려(=오염 출처를 하나도 식별 못 함) 오염 루트가 안 덮이면,
 *   1·2순위가 성립했더라도 frontier를 덧붙여 fail-open을 막는다. MCP_REF(권위적
 *   명시 출처)와 "오염 노드를 실제로 잡은 VALUE_MATCH"는 신뢰하고 바닥을 건너뛴다.
 *
 * 전파·정화 불변식 (구조적으로 보장):
 *   1. 단방향 — 오염은 부모→자식으로만 흐른다. 역방향(자식→부모) 전파 코드는
 *      존재하지 않는다 (cascadeDown은 childIndex만 따라간다).
 *   2. 비대칭 — 전파는 "태그 추가"만. 정화(제거)는 declassifyNodeTag가 그 노드
 *      하나만 건드리며 자손 순회 코드가 없다 — 부모가 정화돼도 자식은 이미 원본
 *      값을 복사했을 수 있으므로 각자 정화를 통과해야만 풀린다.
 *   3. 소급 금지 — parents/parentLinks는 역사다. 정화는 "지금부터 안전"이지
 *      "과거 오염이 없던 일"이 아니므로 절대 수정하지 않는다.
 *   4. 판정 불간섭 — 계보 태그는 병행 기록. 차단은 여전히 sessionStore가 담당.
 *
 * 프라이버시: 결과 원본은 계보에 저장하지 않는다. 값 매칭용 토큰의
 * sha256 해시(+길이)만 남긴다 — 민감 원본은 sanitization 볼트가 관리하고,
 * 계보는 참조(해시)만 갖는다.
 */

import { createHash, randomUUID } from "node:crypto";
import type { ToolRiskTag } from "@icarus-tether/types";
import { getPolicyConfig } from "./config.js";

// ---------------------------------------------------------------------------
// 타입
// ---------------------------------------------------------------------------

export type LinkMethod = "MCP_REF" | "VALUE_MATCH" | "TEMPORAL_FALLBACK" | "NONE";

export interface ParentLink {
  nodeId: string;
  method: Exclude<LinkMethod, "NONE">;
  /** 신뢰도 낮은 연결 표시 — TEMPORAL_FALLBACK 전부, VALUE_MATCH는 근거가 빈약할 때. 튜닝용. */
  weak: boolean;
  /** VALUE_MATCH일 때 가장 강한 근거 토큰 (해시·길이만 — 원본 없음) */
  evidence?: { tokenHash: string; tokenLength: number };
}

export interface TaintNode {
  /** "tn_<uuid>" — 접두사 덕에 인자 속 MCP 참조(1순위)를 딥 스캔으로 식별 가능 */
  id: string;
  toolName: string;
  /** 유효 태그 = ownTags ∪ (모든 parent의 tags 합집합). 상속분이 여기에 쌓인다. */
  tags: Set<ToolRiskTag>;
  /** 이 노드 자체의 소스·내용 기반 태그 (상속분 제외 — 감사 시 출처 구분용) */
  ownTags: Set<ToolRiskTag>;
  /** parentLinks에서 파생된 id 목록 */
  parents: string[];
  /** 연결별 방법·신뢰도 기록 (디버깅·검수용) */
  parentLinks: ParentLink[];
  /** 이 노드 연결에 사용된 우선순위 층 */
  linkMethod: LinkMethod;
  sessionId: string;
  createdAt: string;
  /** 값 매칭(2순위)용 결과 토큰: sha256 해시 → 토큰 길이. 원본은 저장하지 않는다. */
  resultTokens: ReadonlyMap<string, number>;
}

// ---------------------------------------------------------------------------
// 값 매칭 튜닝 상수 — 우연한 겹침(동명이인류 오연결) 방지
// ---------------------------------------------------------------------------

/** 이 길이 미만의 값은 매칭 근거로 쓰지 않는다 ("true", "네", "name" 등은 길이에서 걸러짐) */
export const MATCH_TOKEN_MIN_LENGTH = 8;
/** 단일 토큰 매칭이 이 길이 이상이면 강한 연결, 미만이면 약한(weak) 연결 */
export const STRONG_TOKEN_MIN_LENGTH = 16;
/** 길이 8 이상이지만 도처에 흔해서 근거가 못 되는 토큰 (소문자 비교) */
const COMMON_MATCH_TOKENS = new Set([
  "password",
  "username",
  "response",
  "timestamp",
  "description",
  "undefined",
  "function",
  "javascript",
  "sessionid",
  "localhost",
]);

const NODE_ID_PATTERN =
  /^tn_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** 토큰 후보: 단어류 연속 구간 (이메일·코드·id 형태 포함) */
const TOKEN_RUN = /[\p{L}\p{N}@._+-]{8,}/gu;

// ---------------------------------------------------------------------------
// 세션별 그래프 저장소 (인메모리 — 삽입 순서가 시간 순서)
// ---------------------------------------------------------------------------

const lineageStore = new Map<string, Map<string, TaintNode>>();

/**
 * 묘비(tombstone) 저장소 — 가지치기된 "깨끗한" 노드의 잔상.
 *
 * 깨끗한 노드도 판정에 기여한다: 명시 참조(1순위)의 대상이 되거나 결과 토큰이
 * 값 매칭(2순위)의 근거가 되어, 폴백(오염 frontier)으로 떨어지는 것을 막아준다.
 * 노드를 통째로 지우면 "통과하던 호출이 차단으로" 바뀔 수 있으므로, 무거운 것
 * (parentLinks 근거·메타)만 버리고 판정 관련 골격은 남긴다:
 *  - resultTokens: 1·2순위 연결성 보존 (기존)
 *  - tags: ★사후 재오염분(교환성 수정) — prune 시점엔 항상 비어 있고(clean
 *    guard) 이후 cascadeDown 관통으로만 늘어난다(grow-only, 정화 불가 —
 *    fail-closed). 묘비가 깨끗한 동안엔 태그 무기여 = 기존 판정과 완전 동일.
 *  - parents: frontier 커버 판정용 역사 (소급 수정 금지)
 *
 * 교환성 근거(TaintPruningCommuteFixed 모델, TLC 위반 0): 이 세 필드가 남으면
 * "가지치기가 낀 세션"과 "가지치기가 전혀 없던 세션"의 판정이 어떤 연산
 * 인터리빙(사후 addNodeTags 포함)에서도 일치한다. tags를 빼면 5스텝 반례
 * (TaintPruningCommute 재현판 — git 이력)가 존재한다.
 */
interface Tombstone {
  resultTokens: ReadonlyMap<string, number>;
  tags: Set<ToolRiskTag>;
  parents: readonly string[];
}
type TombstoneMap = Map<string, Tombstone>;
const tombstoneStore = new Map<string, TombstoneMap>();

const EMPTY_TOMBSTONES: ReadonlyMap<string, Tombstone> = new Map();

function tombstonesOf(sessionId: string): ReadonlyMap<string, Tombstone> {
  return tombstoneStore.get(sessionId) ?? EMPTY_TOMBSTONES;
}

/** 묘비의 잔존 태그 조회 (shadow.ts evidence 수집·테스트 검증용 읽기 전용 접근) */
export function getTombstoneTags(
  sessionId: string,
  nodeId: string
): ReadonlySet<ToolRiskTag> | undefined {
  return tombstoneStore.get(sessionId)?.get(nodeId)?.tags;
}

/**
 * 자식 인덱스: sessionId → (parentId → 자식 id 집합).
 * live 전파(cascadeDown)가 따라가는 유일한 방향 — 부모를 거슬러 올라가는
 * 인덱스는 만들지 않아 역류(자식→부모) 전파가 구조적으로 불가능하다 (불변식 1).
 */
const childIndex = new Map<string, Map<string, Set<string>>>();

function getOrCreateGraph(sessionId: string): Map<string, TaintNode> {
  const existing = lineageStore.get(sessionId);
  if (existing) return existing;
  const fresh = new Map<string, TaintNode>();
  lineageStore.set(sessionId, fresh);
  return fresh;
}

function registerChild(sessionId: string, parentId: string, childId: string): void {
  const perSession = childIndex.get(sessionId) ?? new Map<string, Set<string>>();
  childIndex.set(sessionId, perSession);
  const children = perSession.get(parentId) ?? new Set<string>();
  perSession.set(parentId, children);
  children.add(childId);
}

export function getSessionLineage(sessionId: string): ReadonlyMap<string, TaintNode> {
  return lineageStore.get(sessionId) ?? new Map();
}

/**
 * 세션 계보에 지정 태그를 "지금도 살아있게" 지닌 노드가 하나라도 있는가.
 *
 * 비대칭 위협 모델(index.ts computeLineageDecision)의 U 축 판정에 쓴다: 비신뢰는
 * "제어흐름을 조작했는가"라 값-계보가 아니라 세션-존재로 본다. 정화가
 * declassifyNodeTag로 노드의 태그를 실제 제거하므로(비대칭 — 그 노드만), 정화된
 * 비신뢰는 여기서 자동으로 빠진다(정화 후 과차단 방지).
 *
 * 묘비의 잔존 태그(사후 재오염분)도 센다 — 오염을 실은 유일한 보유자가
 * 묘비뿐인 상태(cascade 관통 후 live 출처가 정화된 경우)에서 세션축이
 * 조용히 꺼지는 것을 막는다 (교환성 수정 ④).
 */
export function sessionHasLiveTag(sessionId: string, tag: ToolRiskTag): boolean {
  const graph = lineageStore.get(sessionId);
  if (graph) {
    for (const node of graph.values()) {
      if (node.tags.has(tag)) return true;
    }
  }
  for (const tomb of tombstoneStore.get(sessionId)?.values() ?? []) {
    if (tomb.tags.has(tag)) return true;
  }
  return false;
}

/**
 * 지정 태그를 "지금도 살아있게" 지닌 보유자 전체의 읽기 전용 스냅샷 —
 * sessionHasLiveTag와 정확히 같은 범위(live 노드 + 묘비 잔존 태그)를 목록으로 편다.
 * 즉 `collectLiveTagHolders(s, t).length > 0 ⇔ sessionHasLiveTag(s, t)`.
 *
 * 용도: 파괴 게이트(index.ts computeDestructiveDecision)의 HITL 승인 지문 입력.
 * "승인은 그 U-그림에만 유효"의 '그림'이 바로 이 스냅샷이다 — 승인~소비 사이에
 * 보유자가 추가(새 비신뢰 read)·제거(정화)되면 지문이 달라져 낡은 승인이 무효화된다
 * (TaintDestructiveHITL.tla ApprovalFreshness, 위반 0). 그래프는 절대 변형하지 않는다.
 * 묘비의 toolName은 "(pruned)" — shadow.ts collectLineageEvidence 관례와 동일.
 */
export function collectLiveTagHolders(
  sessionId: string,
  tag: ToolRiskTag
): Array<{ nodeId: string; toolName: string; tags: ToolRiskTag[] }> {
  const out: Array<{ nodeId: string; toolName: string; tags: ToolRiskTag[] }> = [];
  const graph = lineageStore.get(sessionId);
  if (graph) {
    for (const node of graph.values()) {
      if (node.tags.has(tag)) {
        out.push({ nodeId: node.id, toolName: node.toolName, tags: [...node.tags] });
      }
    }
  }
  for (const [nodeId, tomb] of tombstoneStore.get(sessionId) ?? []) {
    if (tomb.tags.has(tag)) {
      out.push({ nodeId, toolName: "(pruned)", tags: [...tomb.tags] });
    }
  }
  return out;
}

export function getTaintNode(sessionId: string, nodeId: string): TaintNode | undefined {
  return lineageStore.get(sessionId)?.get(nodeId);
}

// ---------------------------------------------------------------------------
// 문자열 수집·토큰화·해시
// ---------------------------------------------------------------------------

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
  } else if (typeof value === "object" && value !== null) {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 32);
}

function isUsableToken(token: string): boolean {
  return token.length >= MATCH_TOKEN_MIN_LENGTH && !COMMON_MATCH_TOKENS.has(token.toLowerCase());
}

/** 값에서 매칭 근거가 될 토큰들을 추출해 해시 → 길이 맵으로 (원본은 버려진다) */
function extractMatchTokens(value: unknown): Map<string, number> {
  const strings: string[] = [];
  collectStrings(value, strings);

  // ★ 성능: 해시 전에 토큰 "문자열"을 먼저 유일화한다(대용량 최적화). 반복 콘텐츠(로그·
  // 코드)는 같은 run이 수만 번 나오는데, 예전엔 매 등장마다 sha256을 돌렸다. 유일 문자열만
  // 해시하면 결과 Map은 비트 단위로 동일하다(중복 run은 원래도 같은 해시 key로 덮어써졌으므로
  // — 탐지·판정 완전 불변). big.txt류에서 수만 해시 → 유일 수개로.
  const uniqueTokens = new Map<string, number>();
  for (const s of strings) {
    const whole = s.trim();
    if (isUsableToken(whole)) uniqueTokens.set(whole, whole.length); // 값 통째 전달 케이스
    for (const run of whole.match(TOKEN_RUN) ?? []) {
      if (isUsableToken(run)) uniqueTokens.set(run, run.length);
    }
  }

  const tokens = new Map<string, number>();
  for (const [token, length] of uniqueTokens) tokens.set(hashToken(token), length);
  return tokens;
}

// ---------------------------------------------------------------------------
// 노드 생성 + 3층 parent 연결
// ---------------------------------------------------------------------------

export interface TaintNodeInput {
  /** 이번 도구 호출의 인자 — 1·2순위 연결의 근거. 없으면 3순위로 떨어진다. */
  args?: unknown;
  /** 도구 결과 — 이후 노드의 값 매칭(2순위)을 위해 토큰 해시만 추출·보관 */
  result?: unknown;
}

/**
 * 태그별 루트 보유자 판정: 노드가 어떤 태그 T에 대해 "T를 갖고 있으면서 부모 중
 * 누구도 T를 갖고 있지 않은" 상태면 true. 폴백 후보 = 살아있는 오염의 최전선.
 *
 * 교환성 수정 ⑤: live 노드와 재오염된 묘비 모두 후보이며, 부모 커버 판정도
 * 묘비 태그를 읽는다 — 묘비를 무시하면 "묘비만 오염을 든" 상태에서 frontier가
 * 비어 폴백 차단이 꺼진다 (모델의 유출 반례).
 */
interface TaintRootEntry {
  id: string;
  tags: ReadonlySet<ToolRiskTag>;
  parents: readonly string[];
}

function tagsOfAny(
  graph: Map<string, TaintNode>,
  tombstones: ReadonlyMap<string, Tombstone>,
  id: string
): ReadonlySet<ToolRiskTag> | undefined {
  return graph.get(id)?.tags ?? tombstones.get(id)?.tags;
}

function isLiveTaintRoot(
  graph: Map<string, TaintNode>,
  tombstones: ReadonlyMap<string, Tombstone>,
  entry: TaintRootEntry
): boolean {
  for (const tag of entry.tags) {
    const coveredByParent = entry.parents.some((pid) =>
      tagsOfAny(graph, tombstones, pid)?.has(tag)
    );
    if (!coveredByParent) return true;
  }
  return false;
}

export interface ResolvedParents {
  linkMethod: LinkMethod;
  parentLinks: ParentLink[];
}

/**
 * 3층 parent 연결의 순수(읽기 전용) 계산 — 그래프를 절대 변형하지 않는다.
 * createTaintNode(실제 노드 생성)와 previewParentLinks(섀도 판정용 미리보기)가
 * 같은 로직을 공유하므로, 섀도가 보는 부모와 실제로 연결될 부모가 항상 일치한다.
 */
function matchValueTokens(
  argTokens: Map<string, number>,
  resultTokens: ReadonlyMap<string, number>
): { matchCount: number; best?: { tokenHash: string; tokenLength: number } } {
  let matchCount = 0;
  let best: { tokenHash: string; tokenLength: number } | undefined;
  for (const [hash, length] of argTokens) {
    if (!resultTokens.has(hash)) continue;
    matchCount++;
    if (!best || length > best.tokenLength) best = { tokenHash: hash, tokenLength: length };
  }
  return { matchCount, best };
}

function resolveParents(
  graph: Map<string, TaintNode>,
  tombstones: ReadonlyMap<string, Tombstone>,
  input: TaintNodeInput
): ResolvedParents {
  let linkMethod: LinkMethod = "NONE";
  let parentLinks: ParentLink[] = [];

  // 1순위 MCP_REF: 인자 어딘가에 세션 그래프(또는 묘비)의 노드 id가 있으면 명시 참조.
  // 묘비 참조도 성립해야 "가지치기 전 통과 → 후에도 통과"가 유지된다 (깨끗한 부모와 동치).
  if (input.args !== undefined) {
    const argStrings: string[] = [];
    collectStrings(input.args, argStrings);
    const refIds = [
      ...new Set(
        argStrings.filter((s) => NODE_ID_PATTERN.test(s) && (graph.has(s) || tombstones.has(s)))
      ),
    ];
    if (refIds.length > 0) {
      linkMethod = "MCP_REF";
      parentLinks = refIds.map((nodeId) => ({ nodeId, method: "MCP_REF" as const, weak: false }));
    }
  }

  // 2순위 VALUE_MATCH: 인자 토큰 해시 ∩ (기존 노드 + 묘비)의 결과 토큰 해시
  if (linkMethod === "NONE" && input.args !== undefined) {
    const argTokens = extractMatchTokens(input.args);
    if (argTokens.size > 0) {
      for (const node of graph.values()) {
        const { matchCount, best } = matchValueTokens(argTokens, node.resultTokens);
        if (matchCount > 0 && best) {
          // 근거가 단일 토큰이고 길이도 짧으면 약한 연결로 표시 (튜닝 대상)
          const weak = matchCount < 2 && best.tokenLength < STRONG_TOKEN_MIN_LENGTH;
          parentLinks.push({ nodeId: node.id, method: "VALUE_MATCH", weak, evidence: best });
        }
      }
      for (const [nodeId, tomb] of tombstones) {
        const { matchCount, best } = matchValueTokens(argTokens, tomb.resultTokens);
        if (matchCount > 0 && best) {
          const weak = matchCount < 2 && best.tokenLength < STRONG_TOKEN_MIN_LENGTH;
          parentLinks.push({ nodeId, method: "VALUE_MATCH", weak, evidence: best });
        }
      }
      if (parentLinks.length > 0) linkMethod = "VALUE_MATCH";
    }
  }

  // 3순위 TEMPORAL_FALLBACK: "살아있는 오염의 최전선(frontier)" — 이제 단순한
  // else 분기가 아니라 "안전 바닥(safety floor)"이다 (fail-safe). 항상 약한 연결.
  //
  // 태그별 루트 보유자 규칙: N이 태그 T를 tags에 갖고 있고 N의 부모 중 누구도 T를
  // 갖고 있지 않으면, N이 T의 루트 보유자 = 후보다.
  //  - 정화 전: 소스 노드만 후보 (상속받은 자식은 부모가 T를 보유하므로 제외 — 눈덩이 방지)
  //  - 소스 A가 정화돼 T를 잃으면: A의 직계 자식이 자동으로 루트 보유자로 승계.
  //    손자는 부모(자식)가 아직 T를 보유하므로 여전히 제외 — 후보는 항상 최전선만.
  //
  // ★ 안전 바닥 발동조건 (fail-open 수정): VALUE_MATCH(2순위 휴리스틱)가 "깨끗한
  // 노드에만" 걸렸다면 이 전송값의 오염 출처를 하나도 식별하지 못한 것이다 —
  // "부모(및 그 조상)에 오염이 전혀 없음" = 살아있는 오염 루트 전부가 안 덮임.
  // 이때 frontier를 보수적으로 덧붙여 "확인 불가 = 의심 = 차단"으로 만든다.
  //  - VALUE_MATCH가 오염 노드를 하나라도 잡았으면 그 값의 실제 출처를 식별한
  //    것이므로 신뢰하고 바닥을 발동하지 않는다 (N4/N5 흐름 분리 정상 통과 유지).
  //  - MCP_REF(1순위)는 프록시가 확정한 명시 출처라 권위적 — 바닥에서 제외한다.
  //  - tombstone은 자기 잔존 tags로 판정한다(교환성 수정 ②) — 평소엔 비어 있어
  //    기존과 동일(깨끗 취급)하고, 사후 재오염된 묘비를 잡은 매칭은 출처 식별로
  //    인정해 바닥을 건너뛴다 ("묘비=무조건 깨끗"이던 이전 규칙은 이 경우
  //    출처를 식별했는데도 바닥이 오발동하는 과차단이었다 — 모델 반례).
  const resolvedTaint = parentLinks.some(
    (l) => (tagsOfAny(graph, tombstones, l.nodeId)?.size ?? 0) > 0
  );
  const valueMatchOnlyClean = linkMethod === "VALUE_MATCH" && !resolvedTaint;
  if (linkMethod === "NONE" || valueMatchOnlyClean) {
    // frontier 후보 = live 노드 + 재오염된 묘비 (교환성 수정 ⑤)
    const candidates: TaintRootEntry[] = [
      ...[...graph.values()].map((n) => ({ id: n.id, tags: n.tags, parents: n.parents })),
      ...[...tombstones].map(([id, t]) => ({ id, tags: t.tags, parents: t.parents })),
    ];
    const tainted = candidates.filter((c) => isLiveTaintRoot(graph, tombstones, c));
    if (tainted.length > 0) {
      // 깨끗 매칭 엣지는 보존(그래프 구조)하고 frontier만 덧붙인다 (dedup).
      const existing = new Set(parentLinks.map((l) => l.nodeId));
      for (const c of tainted) {
        if (!existing.has(c.id)) {
          parentLinks.push({ nodeId: c.id, method: "TEMPORAL_FALLBACK", weak: true });
        }
      }
      linkMethod = "TEMPORAL_FALLBACK";
    }
  }

  return { linkMethod, parentLinks };
}

/**
 * 섀도 판정용 미리보기 — "지금 이 인자로 노드를 만든다면 어느 부모에 연결될까"를
 * 그래프 변형 없이 계산한다. 노드 생성·childIndex 등록이 없으므로 아무리 호출해도
 * 계보에 유령 노드가 생기지 않는다.
 */
export function previewParentLinks(sessionId: string, args: unknown): ResolvedParents {
  const graph = lineageStore.get(sessionId) ?? new Map<string, TaintNode>();
  return resolveParents(graph, tombstonesOf(sessionId), { args });
}

export function createTaintNode(
  sessionId: string,
  toolName: string,
  tags: ToolRiskTag[],
  input: TaintNodeInput = {}
): TaintNode {
  const graph = getOrCreateGraph(sessionId);
  const tombstones = tombstonesOf(sessionId);
  const { linkMethod, parentLinks } = resolveParents(graph, tombstones, input);

  // 전파 (요구사항 1): 유효 태그 = 자기자신 태그 ∪ 모든 parent의 tags 합집합.
  // snapshot·live 모두 생성 시점에는 동일하게 복사한다 — live는 이후
  // addNodeTags에 의한 사후 추가분이 하향 전파되는 점만 다르다.
  // 묘비 부모의 잔존 태그(사후 재오염분)도 상속한다 (교환성 수정 ③) —
  // 평소엔 비어 있어 기존(무기여)과 동일하다.
  const effectiveTags = new Set(tags);
  for (const link of parentLinks) {
    const parentTags = tagsOfAny(graph, tombstones, link.nodeId);
    if (!parentTags) continue;
    for (const tag of parentTags) effectiveTags.add(tag);
  }

  const node: TaintNode = {
    id: `tn_${randomUUID()}`,
    toolName,
    tags: effectiveTags,
    ownTags: new Set(tags),
    parents: parentLinks.map((l) => l.nodeId),
    parentLinks,
    linkMethod,
    sessionId,
    createdAt: new Date().toISOString(),
    resultTokens: input.result !== undefined ? extractMatchTokens(input.result) : new Map(),
  };
  graph.set(node.id, node);
  for (const link of parentLinks) registerChild(sessionId, link.nodeId, node.id);
  return node;
}

// ---------------------------------------------------------------------------
// 사후 태그 추가 + live 전파
// ---------------------------------------------------------------------------

/**
 * 이미 생성된 노드에 오염 태그를 추가한다 — 지연 발견된 오염(사후 콘텐츠 스캔,
 * 프록시의 늦은 보고 등)의 진입점. sessionStore는 건드리지 않는다 (불변식 3).
 *
 * propagationMode에 따라:
 * - "snapshot": 이 노드에만 추가. 자식은 생성 시점 복사본을 유지.
 * - "live": 새로 추가된 태그만 자손에게 하향 전파(BFS). 이미 있던 태그의
 *   재추가는 no-op — 전파는 태그가 "늘어날" 때만 일어난다 (불변식 2).
 */
export function addNodeTags(sessionId: string, nodeId: string, tags: ToolRiskTag[]): void {
  const node = lineageStore.get(sessionId)?.get(nodeId);
  if (!node) {
    throw new Error(`[lineage] 세션 "${sessionId}"에 노드 "${nodeId}"가 없습니다`);
  }

  const added = tags.filter((t) => !node.tags.has(t));
  for (const tag of tags) {
    node.ownTags.add(tag); // 이 노드에서 직접 관측된 오염이므로 자체 태그
    node.tags.add(tag);
  }
  if (added.length === 0) return;

  if (getPolicyConfig().propagationMode === "live") {
    cascadeDown(sessionId, nodeId, added);
  }
}

/**
 * 하향 전파 — childIndex(부모→자식)만 따라가므로 역류가 불가능하다 (불변식 1).
 * "추가"만 하고 제거는 없다 (불변식 2). 부모는 항상 자식보다 먼저 생성되므로
 * 사이클이 있을 수 없지만, visited 집합으로 이중 안전장치를 둔다.
 */
/**
 * 계보 가지치기 — 명시 호출 전용 (판정·정화 경로에 자동 트리거 없음, 프록시가 주기 호출).
 *
 * 대상: "태그가 전부 없어졌고(정화 완료) live 자식이 없는" 노드만. 연쇄(fixpoint) —
 * 자식이 먼저 묘비가 돼 live 자식이 사라진 깨끗한 부모도 같은 패스에서 정리된다.
 *
 * 판정 불변 보장 (TaintPruning.tla PruneSafety, 352,346 상태 위반 0):
 *  1. 오염 노드(tags 비어있지 않음)는 절대 대상 아님 — frontier·전파·차단 기여 노드 불변.
 *     (ownTags ⊆ tags 이므로 tags가 비면 자체 태그도 없다)
 *  2. 깨끗한 노드의 판정 기여는 "연결"뿐(태그 기여 0) — 묘비가 1순위 참조와
 *     2순위 값 매칭 연결을 보존한다.
 *  3. 남은 노드의 parents 배열 불변(역사 보존) — frontier 판정 입력이 안 변한다.
 *
 * ★ 교환성 보장 (TaintPruningCommuteFixed 모델, 위반 0): childIndex 엣지를
 * 지우지 않는다 — 사후 addNodeTags의 cascadeDown이 묘비를 "관통"해(잔존 tags에
 * 적재 + 자손 계속) 가지치기가 없던 세션과 판정이 일치한다. 엣지를 지우던 이전
 * 구현은 관통이 끊겨 5스텝 유출 반례가 있었다 (TaintPruningCommute 재현판).
 * 같은 이유로 childless 판정은 "live 자식 없음"이다 — 묘비 자식은 prune을 막지
 * 않아 연쇄 정리가 유지된다.
 *
 * fail-safe: 실패하면 그냥 안 지운다. 개별 노드 단위로 위 논증이 성립하므로
 * 부분 완료 상태도 안전하다.
 *
 * 알려진 한계(문서화): 가지치기된 노드에 대한 "직접" addNodeTags는 예외로
 * 실패한다(fail-closed). cascade 경유 재오염은 위 관통으로 정상 반영된다.
 */
export function pruneSessionLineage(sessionId: string): { pruned: number } {
  try {
    if (getPolicyConfig().pruningPolicy !== "declassified") return { pruned: 0 };
    const graph = lineageStore.get(sessionId);
    if (!graph || graph.size === 0) return { pruned: 0 };

    const perSession = childIndex.get(sessionId);
    const tombstones = tombstoneStore.get(sessionId) ?? new Map<string, Tombstone>();
    tombstoneStore.set(sessionId, tombstones);

    let pruned = 0;
    let changed = true;
    while (changed) {
      changed = false;
      for (const node of [...graph.values()]) {
        const children = perSession?.get(node.id);
        const hasLiveChild =
          children !== undefined && [...children].some((cid) => graph.has(cid));
        if (node.tags.size > 0 || hasLiveChild) continue;

        graph.delete(node.id);
        // childIndex 엣지는 유지 — cascade 관통·연쇄 판정 모두 live 여부로 거른다
        tombstones.set(node.id, {
          resultTokens: node.resultTokens,
          tags: new Set(node.tags), // clean guard로 항상 {} — 이후 cascade 관통분만 쌓인다
          parents: [...node.parents],
        });
        pruned++;
        changed = true;
      }
    }
    return { pruned };
  } catch (err) {
    // fail-safe: 가지치기 실패 = 안 지움. 판정에는 어떤 영향도 없다.
    console.error("[lineage] 가지치기 실패 — 아무것도 추가로 지우지 않음 (fail-safe):", err);
    return { pruned: 0 };
  }
}

/**
 * 정화(declassification) 전용 태그 제거 — attemptSanitization(index.ts)만 사용할 것.
 * 의도적으로 index.ts에서 re-export하지 않는다: 엔진 공개 API에 범용 태그 제거
 * 함수가 존재하면 전파/정화 비대칭이 여기저기서 깨질 수 있기 때문.
 *
 * 정확히 "정화 검증을 통과한 그 노드 하나"만 건드린다:
 *  - 이 함수에는 자식/자손 순회 코드가 없다 — childIndex를 아예 참조하지 않으므로
 *    부모 정화가 자식 태그를 떼는 일은 구조적으로 불가능하다. 자식은 이미 부모의
 *    원본 값을 복사했을 수 있으므로 각자 정화를 통과해야만 풀린다 (비대칭).
 *  - parents/parentLinks는 건드리지 않는다 — 계보는 역사, 소급 수정 금지.
 *  - 이 노드가 태그를 잃어 폴백 후보에서 빠지면, 오염을 물려받은 직계 자식이
 *    루트 보유자 규칙(isLiveTaintRoot)에 의해 자동으로 후보 자격을 승계한다.
 */
export function declassifyNodeTag(sessionId: string, nodeId: string, tag: ToolRiskTag): void {
  const node = lineageStore.get(sessionId)?.get(nodeId);
  if (!node) return; // 계보는 부가 기록 — 노드가 없어도 정화 자체는 유효 (태그 유지 방향이 아님에 유의: 없는 노드는 제거할 것도 없다)
  node.ownTags.delete(tag);
  node.tags.delete(tag);
}

function cascadeDown(sessionId: string, fromId: string, tags: ToolRiskTag[]): void {
  const graph = lineageStore.get(sessionId);
  const perSession = childIndex.get(sessionId);
  if (!graph || !perSession) return;

  const tombstones = tombstoneStore.get(sessionId);
  const visited = new Set<string>([fromId]);
  const queue = [...(perSession.get(fromId) ?? [])];
  while (queue.length > 0) {
    const id = queue.shift();
    if (id === undefined || visited.has(id)) continue;
    visited.add(id);
    const child = graph.get(id);
    if (!child) {
      // ★ 묘비 관통 (교환성 수정 ②): 잔존 tags에 적재하고 자손 탐색을 계속한다.
      // 여기서 멈추면 묘비 너머의 live 자손이 사후 오염을 못 받아, 가지치기가
      // 없던 세션과 판정이 갈라진다 (TaintPruningCommute 5스텝 유출 반례).
      const tomb = tombstones?.get(id);
      if (tomb) {
        for (const tag of tags) tomb.tags.add(tag);
        queue.push(...(perSession.get(id) ?? []));
      }
      continue;
    }
    for (const tag of tags) child.tags.add(tag); // 상속분 — ownTags에는 넣지 않는다
    queue.push(...(perSession.get(id) ?? []));
  }
}
