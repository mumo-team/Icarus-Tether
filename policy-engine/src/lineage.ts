/**
 * 값 단위 taint 계보(lineage) 그래프 — 2단계: 태그 전파(propagation)까지.
 *
 * 기존 세션 boolean 방식(sessionStore)을 대체하지 않고 병행 기록한다.
 * 정화 연동과 계보 기반 판정 전환은 다음 단계 — 이 모듈은 아직
 * 판정(evaluateToolCall)에 아무 영향을 주지 않는다.
 *
 * parent 연결 3층 (전부 결정론, 우선순위 — 상위 층이 맞으면 하위 층 미시도):
 *   1순위 MCP_REF          — 인자 속에 세션 그래프의 노드 id("tn_…")가 있으면 명시 참조
 *   2순위 VALUE_MATCH      — 이전 노드 결과의 토큰(해시)이 이번 인자 토큰과 일치
 *   3순위 TEMPORAL_FALLBACK — 둘 다 없으면 자체 오염(ownTags)이 있는 노드 전부를
 *                             보수적으로 parent 후보로 (시간 근사, fail-safe, 항상 약한 연결)
 *
 * 전파 3대 불변식 (구조적으로 보장):
 *   1. 단방향 — 오염은 부모→자식으로만 흐른다. 역방향(자식→부모) 전파 코드는
 *      존재하지 않는다 (cascadeDown은 childIndex만 따라간다).
 *   2. 비대칭 — 전파는 "태그 추가"만. 태그를 제거하는 API 자체가 없다.
 *      부모가 정화돼도 자식은 이미 원본 값을 복사했을 수 있으므로 자식 태그 유지.
 *   3. 판정 불간섭 — 계보 태그는 병행 기록. 차단은 여전히 sessionStore가 담당.
 *
 * 프라이버시: 결과 원본은 계보에 저장하지 않는다. 값 매칭용 토큰의
 * sha256 해시(+길이)만 남긴다 — 민감 원본은 sanitization 볼트가 관리하고,
 * 계보는 참조(해시)만 갖는다.
 */

import { createHash, randomUUID } from "node:crypto";
import type { ToolRiskTag } from "@taintguard/types";
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

  const tokens = new Map<string, number>();
  for (const s of strings) {
    const whole = s.trim();
    if (isUsableToken(whole)) tokens.set(hashToken(whole), whole.length); // 값 통째 전달 케이스
    for (const run of whole.match(TOKEN_RUN) ?? []) {
      if (isUsableToken(run)) tokens.set(hashToken(run), run.length);
    }
  }
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

export function createTaintNode(
  sessionId: string,
  toolName: string,
  tags: ToolRiskTag[],
  input: TaintNodeInput = {}
): TaintNode {
  const graph = getOrCreateGraph(sessionId);

  let linkMethod: LinkMethod = "NONE";
  let parentLinks: ParentLink[] = [];

  // 1순위 MCP_REF: 인자 어딘가에 세션 그래프의 노드 id가 있으면 명시 참조로 본다
  if (input.args !== undefined) {
    const argStrings: string[] = [];
    collectStrings(input.args, argStrings);
    const refIds = [...new Set(argStrings.filter((s) => NODE_ID_PATTERN.test(s) && graph.has(s)))];
    if (refIds.length > 0) {
      linkMethod = "MCP_REF";
      parentLinks = refIds.map((nodeId) => ({ nodeId, method: "MCP_REF" as const, weak: false }));
    }
  }

  // 2순위 VALUE_MATCH: 인자 토큰 해시 ∩ 기존 노드의 결과 토큰 해시
  if (linkMethod === "NONE" && input.args !== undefined) {
    const argTokens = extractMatchTokens(input.args);
    if (argTokens.size > 0) {
      for (const node of graph.values()) {
        let matchCount = 0;
        let best: { tokenHash: string; tokenLength: number } | undefined;
        for (const [hash, length] of argTokens) {
          if (!node.resultTokens.has(hash)) continue;
          matchCount++;
          if (!best || length > best.tokenLength) best = { tokenHash: hash, tokenLength: length };
        }
        if (matchCount > 0 && best) {
          // 근거가 단일 토큰이고 길이도 짧으면 약한 연결로 표시 (튜닝 대상)
          const weak = matchCount < 2 && best.tokenLength < STRONG_TOKEN_MIN_LENGTH;
          parentLinks.push({ nodeId: node.id, method: "VALUE_MATCH", weak, evidence: best });
        }
      }
      if (parentLinks.length > 0) linkMethod = "VALUE_MATCH";
    }
  }

  // 3순위 TEMPORAL_FALLBACK: 자체 오염(ownTags) 노드 전부 — 보수적, 항상 약한 연결 (fail-safe)
  // 상속-만-오염인 노드는 제외한다: 그 태그의 출처인 자체-오염 조상이 이미 후보라
  // 태그 보수성은 유지되고, 후보 눈덩이만 커지는 것을 막는다.
  // (주의: 다음 단계에서 정화가 ownTags를 제거하게 되면 이 기준은 재검토 필요)
  if (linkMethod === "NONE") {
    const tainted = [...graph.values()].filter((n) => n.ownTags.size > 0);
    if (tainted.length > 0) {
      linkMethod = "TEMPORAL_FALLBACK";
      parentLinks = tainted.map((n) => ({
        nodeId: n.id,
        method: "TEMPORAL_FALLBACK" as const,
        weak: true,
      }));
    }
  }

  // 전파 (요구사항 1): 유효 태그 = 자기자신 태그 ∪ 모든 parent의 tags 합집합.
  // snapshot·live 모두 생성 시점에는 동일하게 복사한다 — live는 이후
  // addNodeTags에 의한 사후 추가분이 하향 전파되는 점만 다르다.
  const effectiveTags = new Set(tags);
  for (const link of parentLinks) {
    const parent = graph.get(link.nodeId);
    if (!parent) continue;
    for (const tag of parent.tags) effectiveTags.add(tag);
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
function cascadeDown(sessionId: string, fromId: string, tags: ToolRiskTag[]): void {
  const graph = lineageStore.get(sessionId);
  const perSession = childIndex.get(sessionId);
  if (!graph || !perSession) return;

  const visited = new Set<string>([fromId]);
  const queue = [...(perSession.get(fromId) ?? [])];
  while (queue.length > 0) {
    const id = queue.shift();
    if (id === undefined || visited.has(id)) continue;
    visited.add(id);
    const child = graph.get(id);
    if (!child) continue;
    for (const tag of tags) child.tags.add(tag); // 상속분 — ownTags에는 넣지 않는다
    queue.push(...(perSession.get(id) ?? []));
  }
}
