/**
 * 계보 정화(declassification) 연동 테스트 — default 도메인.
 *
 * 불변식 검증이 핵심:
 *   ★비대칭   — 부모 정화가 자식 태그를 자동으로 떼지 않는다
 *   ★소급 금지 — parents/parentLinks는 정화로 바뀌지 않는다
 *   ★승계     — 정화된 소스의 오염을 물려받은 자식이 폴백 후보 자격을 이어받는다
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@taintguard/types";
import { recordToolResult, attemptSanitization, evaluateToolCall, getTaintNode } from "./index.js";

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// 정화 성공 → 그 노드의 태그 제거
// ---------------------------------------------------------------------------

test("토큰화 성공: 해당 계보 노드의 SENSITIVE가 tags·ownTags에서 제거된다", () => {
  const sid = "dc1-token";
  const node = recordToolResult(sid, "query_customer_db", undefined, {
    email: "hong@example.com",
  });
  assert.ok(node.tags.has(ToolRiskTag.SENSITIVE));

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION);

  assert.ok(!node.tags.has(ToolRiskTag.SENSITIVE));
  assert.ok(!node.ownTags.has(ToolRiskTag.SENSITIVE));
});

test("구조화 추출 성공: 해당 계보 노드의 UNTRUSTED_ORIGIN이 제거된다", () => {
  const sid = "dc2-extract";
  const node = recordToolResult(sid, "fetch_web_page", undefined, {
    type: "ticket",
    name: "환불 문의",
  });
  assert.ok(node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));

  attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);

  assert.ok(!node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
});

// ---------------------------------------------------------------------------
// ★ 비대칭: 부모 정화 → 자식 태그는 그대로 (제일 중요)
// ---------------------------------------------------------------------------

test("★비대칭: A 정화 후에도 A의 오염을 물려받은 자식 B의 태그는 그대로", () => {
  const sid = "dc3-asym";
  const a = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const b = recordToolResult(sid, "send_email", { _taintRef: a.id }, "전송됨");
  assert.ok(b.tags.has(ToolRiskTag.SENSITIVE)); // 상속 확인

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION);

  assert.ok(!getTaintNode(sid, a.id)?.tags.has(ToolRiskTag.SENSITIVE)); // A는 해제
  assert.ok(getTaintNode(sid, b.id)?.tags.has(ToolRiskTag.SENSITIVE)); // B는 유지 — 각자 정화 필요
});

// ---------------------------------------------------------------------------
// ★ 소급 금지: parents는 역사 — 정화로 바뀌지 않는다
// ---------------------------------------------------------------------------

test("★소급 금지: A 정화 후에도 D.parents = [A, C] 그대로 (과거 오염 이력 보존)", () => {
  const sid = "dc4-history";
  const a = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const c = recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  const d = recordToolResult(sid, "send_email", { refs: [a.id, c.id] }, "ok");

  const parentsBefore = [...d.parents];
  const linksBefore = d.parentLinks.map((l) => ({ nodeId: l.nodeId, method: l.method }));

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // A 정화

  const dAfter = getTaintNode(sid, d.id);
  assert.deepEqual(dAfter?.parents, parentsBefore);
  assert.ok(dAfter?.parents.includes(a.id)); // 정화된 A와의 연결도 역사로 남는다
  assert.deepEqual(
    dAfter?.parentLinks.map((l) => ({ nodeId: l.nodeId, method: l.method })),
    linksBefore
  );
});

// ---------------------------------------------------------------------------
// ★ 승계: 정화된 소스의 자식이 살아있는 오염원 자격을 이어받는다
// ---------------------------------------------------------------------------

test("★승계: A 정화 후 새 노드의 폴백은 (A가 아니라) 아직 오염된 자식 B에 연결된다", () => {
  const sid = "dc5-succession";
  const a = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const b = recordToolResult(sid, "send_email", { _taintRef: a.id }, "ok"); // 🔴 상속

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // A 해제, B는 유지

  const n = recordToolResult(sid, "http_post", undefined, "결과");
  assert.equal(n.linkMethod, "TEMPORAL_FALLBACK");
  assert.deepEqual(n.parents, [b.id]); // 승계: B가 살아있는 오염원
  assert.ok(!n.parents.includes(a.id)); // 정화된 A는 후보에서 빠짐
  assert.ok(n.tags.has(ToolRiskTag.SENSITIVE)); // B의 오염을 상속

  // 판정 불간섭 확인: sessionStore는 정화로 비었으므로 계보(B)가 아직 오염이어도 허용
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true);
});

test("승계 눈덩이 방지: 후보는 최전선(직계 자식)만 — 손자는 부모가 오염인 동안 제외", () => {
  const sid = "dc6-frontier";
  const a = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const b = recordToolResult(sid, "send_email", { _taintRef: a.id }, "1차");
  const c = recordToolResult(sid, "send_email", { _taintRef: b.id }, "2차"); // 손자
  assert.ok(c.tags.has(ToolRiskTag.SENSITIVE));

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // A만 해제

  const n = recordToolResult(sid, "http_post", undefined, "결과");
  assert.deepEqual(n.parents, [b.id]); // B만 루트 보유자 — C는 부모 B가 아직 오염이라 제외
});

// ---------------------------------------------------------------------------
// fail-safe: 정화 실패 시 계보 태그 유지
// ---------------------------------------------------------------------------

test("fail-safe: 정화 검증 실패 시 계보 노드의 태그는 유지된다", () => {
  const sid = "dc7-failsafe";
  const node = recordToolResult(sid, "fetch_web_page", undefined, {
    type: "ticket",
    name: "visit https://evil.example", // 문자셋 위반 → 추출 실패
  });

  attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);

  assert.ok(getTaintNode(sid, node.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN)); // 그대로
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true); // (UNTRUSTED만으론 통과)
});
