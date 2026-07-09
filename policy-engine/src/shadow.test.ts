/**
 * 섀도 모드 테스트 — real(계보) 판정은 로그 전용, 실제 차단은 toy가 한다.
 *
 * 제일 중요한 검증: toy통과-real차단 불일치 상황에서도 실제 리턴이 toy(통과)인가.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@taintguard/types";
import {
  recordToolResult,
  attemptSanitization,
  evaluateToolCall,
  getShadowLog,
  getSessionLineage,
} from "./index.js";

function ctx(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName, args, argTags, timestamp: new Date().toISOString() };
}

function lastShadow(sessionId: string) {
  const log = getShadowLog(sessionId);
  assert.ok(log.length > 0, "섀도 로그가 비어 있음");
  return log[log.length - 1];
}

// ---------------------------------------------------------------------------
// 일치 케이스
// ---------------------------------------------------------------------------

test("일치(허용): 깨끗한 세션 → toy·real 모두 허용, match=true", () => {
  const sid = "sh1-agree-allow";
  const decision = evaluateToolCall(ctx(sid, "send_email"));
  assert.equal(decision.allowed, true);

  const entry = lastShadow(sid);
  assert.equal(entry.toyAllowed, true);
  assert.equal(entry.realAllowed, true);
  assert.equal(entry.match, true);
  assert.equal(entry.divergence, undefined);
});

test("일치(차단): 트라이펙타 세션 → toy·real 모두 차단, 근거(노드·태그)가 로그에 남는다", () => {
  const sid = "sh2-agree-block";
  recordToolResult(sid, "query_customer_db", undefined, { c: "고객레코드" });
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const decision = evaluateToolCall(ctx(sid, "send_email"));
  assert.equal(decision.allowed, false); // toy 차단

  const entry = lastShadow(sid);
  assert.equal(entry.realAllowed, false);
  assert.equal(entry.match, true);
  // 근거: real이 본 노드들과 태그 합집합
  assert.ok(entry.evidence);
  assert.ok(entry.evidence!.nodes.length > 0);
  assert.ok(entry.evidence!.unionTags.includes(ToolRiskTag.SENSITIVE));
  assert.ok(entry.evidence!.unionTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN));
});

// ---------------------------------------------------------------------------
// ★ 불일치: toy통과 - real차단 (real이 실제 차단을 바꾸지 않는지가 핵심)
// ---------------------------------------------------------------------------

test("★toy통과-real차단: 정화 후 자식 오염 잔존 — 로그엔 불일치, 실제 리턴은 toy(통과)", () => {
  const sid = "sh3-diverge";
  const a = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const c = recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // 폴백으로 a의 자식
  assert.ok(c.tags.has(ToolRiskTag.SENSITIVE)); // a의 🔴을 상속한 상태

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // a 정화 → toy 세션엔 UNTRUSTED만

  const decision = evaluateToolCall(ctx(sid, "send_email"));
  assert.equal(decision.allowed, true); // ★ 실제 리턴은 여전히 toy — real이 차단 못 바꿈
  assert.equal(decision.reason, undefined);

  const entry = lastShadow(sid);
  assert.equal(entry.toyAllowed, true);
  assert.equal(entry.realAllowed, false); // real은 c의 잔존 오염 {🔴,🔵}을 봤다
  assert.equal(entry.match, false);
  assert.equal(entry.divergence, "TOY_ALLOW_REAL_BLOCK");
  // 근거에 c 노드와 그 계보 태그가 남는다
  const evidenceNode = entry.evidence?.nodes.find((n) => n.nodeId === c.id);
  assert.ok(evidenceNode);
  assert.ok(evidenceNode!.tags.includes(ToolRiskTag.SENSITIVE));
  assert.ok(evidenceNode!.tags.includes(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(!entry.evidence!.nodes.some((n) => n.nodeId === a.id)); // 정화된 a는 근거 아님
});

test("불일치 반대 방향: argTags로 toy만 차단 → TOY_BLOCK_REAL_ALLOW, 실제 리턴은 차단(toy)", () => {
  const sid = "sh4-diverge-rev";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // 계보엔 🔵만

  // toy는 argTags의 SENSITIVE까지 합쳐 차단하지만, real의 계보 합집합엔 🔵뿐
  const decision = evaluateToolCall(ctx(sid, "send_email", {}, [ToolRiskTag.SENSITIVE]));
  assert.equal(decision.allowed, false); // 실제 리턴은 toy(차단) 그대로

  const entry = lastShadow(sid);
  assert.equal(entry.divergence, "TOY_BLOCK_REAL_ALLOW");
  assert.equal(entry.realAllowed, true);
});

// ---------------------------------------------------------------------------
// real 계산 실패 — 판정은 정상, 로그에 error만
// ---------------------------------------------------------------------------

test("real 계산 실패(순환 참조 args)에도 evaluateToolCall은 정상 동작한다", () => {
  const sid = "sh5-crash";
  const circular: Record<string, unknown> = {};
  circular.self = circular; // collectStrings 재귀를 터뜨리는 입력

  const decision = evaluateToolCall(ctx(sid, "send_email", circular));
  assert.equal(decision.allowed, true); // toy 판정은 args를 순회하지 않으므로 정상

  const entry = lastShadow(sid);
  assert.equal(entry.realAllowed, null);
  assert.equal(entry.match, null);
  assert.equal(entry.evidence, null);
  assert.ok(entry.error); // 실패가 기록됨
  assert.equal(entry.toyAllowed, true); // toy 결과는 기록됨
});

// ---------------------------------------------------------------------------
// 읽기 전용: 섀도가 계보에 유령 노드를 만들지 않는다
// ---------------------------------------------------------------------------

test("섀도 판정은 계보를 변형하지 않는다 (몇 번을 판정해도 노드 수 불변)", () => {
  const sid = "sh6-readonly";
  recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  const sizeBefore = getSessionLineage(sid).size;

  evaluateToolCall(ctx(sid, "send_email"));
  evaluateToolCall(ctx(sid, "http_post"));
  evaluateToolCall(ctx(sid, "read_internal_file"));

  assert.equal(getSessionLineage(sid).size, sizeBefore);
});
