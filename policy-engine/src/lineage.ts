/**
 * 값 단위 taint 계보(lineage) 그래프 — 1단계: 자료구조 + 노드 생성/연결만.
 *
 * 기존 세션 boolean 방식(sessionStore)을 대체하지 않고 병행 기록한다.
 * 태그 전파(parent → child)와 정화 연동은 다음 단계 — 이 모듈은 아직
 * 판정(evaluateToolCall)에 아무 영향을 주지 않는다.
 *
 * parent 연결 3층 (전부 결정론, 우선순위 — 상위 층이 맞으면 하위 층 미시도):
 *   1순위 MCP_REF          — 인자 속에 세션 그래프의 노드 id("tn_…")가 있으면 명시 참조
 *   2순위 VALUE_MATCH      — 이전 노드 결과의 토큰(해시)이 이번 인자 토큰과 일치
 *   3순위 TEMPORAL_FALLBACK — 둘 다 없으면 아직 오염 태그가 남은 노드 전부를
 *                             보수적으로 parent 후보로 (시간 근사, fail-safe, 항상 약한 연결)
 *
 * 프라이버시: 결과 원본은 계보에 저장하지 않는다. 값 매칭용 토큰의
 * sha256 해시(+길이)만 남긴다 — 민감 원본은 sanitization 볼트가 관리하고,
 * 계보는 참조(해시)만 갖는다.
 */

import { createHash } from "node:crypto";
import type { ToolRiskTag } from "@taintguard/types";

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
  /** 이 노드 자체의 소스·내용 기반 태그 (전파는 다음 단계) */
  tags: Set<ToolRiskTag>;
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

function getOrCreateGraph(sessionId: string): Map<string, TaintNode> {
  const existing = lineageStore.get(sessionId);
  if (existing) return existing;
  const fresh = new Map<string, TaintNode>();
  lineageStore.set(sessionId, fresh);
  return fresh;
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

  // 3순위 TEMPORAL_FALLBACK: 아직 오염 태그가 남은 노드 전부 — 보수적, 항상 약한 연결 (fail-safe)
  if (linkMethod === "NONE") {
    const tainted = [...graph.values()].filter((n) => n.tags.size > 0);
    if (tainted.length > 0) {
      linkMethod = "TEMPORAL_FALLBACK";
      parentLinks = tainted.map((n) => ({
        nodeId: n.id,
        method: "TEMPORAL_FALLBACK" as const,
        weak: true,
      }));
    }
  }

  const node: TaintNode = {
    id: `tn_${crypto.randomUUID()}`,
    toolName,
    tags: new Set(tags),
    parents: parentLinks.map((l) => l.nodeId),
    parentLinks,
    linkMethod,
    sessionId,
    createdAt: new Date().toISOString(),
    resultTokens: input.result !== undefined ? extractMatchTokens(input.result) : new Map(),
  };
  graph.set(node.id, node);
  return node;
}
