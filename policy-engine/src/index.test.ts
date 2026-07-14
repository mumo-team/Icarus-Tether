/**
 * 정책 엔진 시나리오 테스트 (node:test — `npm run build && npm test`)
 *
 * 핵심 3종:
 *   1. 정상 통과      — 트라이펙타가 성립하지 않으면 OUTBOUND_SINK도 허용
 *   2. 트라이펙타 차단 — SENSITIVE + UNTRUSTED_ORIGIN + OUTBOUND_SINK → 차단
 *   3. 정화 후 통과    — 검증된 정화로 태그 해제 후 같은 세션이 다시 허용
 *
 * 세션 저장소가 모듈 전역이므로 테스트마다 고유 sessionId를 사용한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";
import {
  tagToolResult,
  recordToolPayload,
  attemptSanitization,
  evaluateToolCall,
} from "./index.js";

function ctx(sessionId: string, toolName: string, argTags: ToolRiskTag[] = []): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags, timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// 시나리오 1. 정상 통과
// ---------------------------------------------------------------------------

test("정상 통과: 아무 오염 없는 세션은 OUTBOUND_SINK도 허용", () => {
  const decision = evaluateToolCall(ctx("s1-clean", "send_email"));
  assert.equal(decision.allowed, true);
  assert.deepEqual(decision.matchedTags, []);
});

test("정상 통과: SENSITIVE 하나만으로는 트라이펙타가 아니므로 허용", () => {
  tagToolResult("s1-sensitive-only", "query_customer_db");
  const decision = evaluateToolCall(ctx("s1-sensitive-only", "send_email"));
  assert.equal(decision.allowed, true);
});

test("정상 통과: 트라이펙타 오염 상태라도 READ 도구(비-싱크)는 허용", () => {
  tagToolResult("s1-read-ok", "query_customer_db");
  tagToolResult("s1-read-ok", "fetch_web_page");
  const decision = evaluateToolCall(ctx("s1-read-ok", "read_internal_file"));
  assert.equal(decision.allowed, true);
});

// ---------------------------------------------------------------------------
// 시나리오 2. 트라이펙타 차단
// ---------------------------------------------------------------------------

test("트라이펙타 차단: 민감 + 비신뢰 세션에서 외부 유출 시도 → 차단", () => {
  tagToolResult("s2-block", "query_customer_db"); // SENSITIVE
  tagToolResult("s2-block", "fetch_web_page"); // UNTRUSTED_ORIGIN

  const decision = evaluateToolCall(ctx("s2-block", "send_email"));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("lethal trifecta"));
  assert.ok(decision.matchedTags.includes(ToolRiskTag.SENSITIVE));
  assert.ok(decision.matchedTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN));
});

test("트라이펙타 차단: 세션 태그 + 인자 전파(argTags) 조합으로도 성립", () => {
  tagToolResult("s2-argtags", "read_email"); // UNTRUSTED_ORIGIN만 세션에
  const decision = evaluateToolCall(
    ctx("s2-argtags", "http_post", [ToolRiskTag.SENSITIVE]) // SENSITIVE는 인자로 전파
  );
  assert.equal(decision.allowed, false);
});

// ---------------------------------------------------------------------------
// 시나리오 3. 정화 후 통과
// ---------------------------------------------------------------------------

test("정화 후 통과: 구조화 추출이 UNTRUSTED_ORIGIN을 해제해 세션이 다시 열림", () => {
  const sid = "s3-extract";
  recordToolPayload(sid, "query_customer_db", { customer: "김민준", plan: "pro" });
  recordToolPayload(sid, "fetch_web_page", { type: "ticket", name: "환불 문의" });

  // 정화 전에는 차단
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.deepEqual(
    [...result.originalTags].sort(),
    [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN].sort()
  );
  assert.deepEqual(result.resultTags, [ToolRiskTag.SENSITIVE]); // UNTRUSTED만 해제

  // 트라이펙타가 깨졌으므로 통과
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true);
});

test("정화 후 통과: PII 토큰화가 SENSITIVE를 해제해 세션이 다시 열림", () => {
  const sid = "s3-tokenize";
  recordToolPayload(sid, "query_customer_db", {
    customer: "홍길동",
    email: "hong@example.com",
    phone: "010-1234-5678",
  });
  recordToolPayload(sid, "fetch_web_page", "외부 웹 문서 본문");

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual(result.resultTags, [ToolRiskTag.UNTRUSTED_ORIGIN]); // SENSITIVE만 해제

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, true);
});

// ---------------------------------------------------------------------------
// fail-safe: 검증 실패 시 태그 유지 → 계속 차단
// ---------------------------------------------------------------------------

test("fail-safe: 스키마 검증에 실패하는 비신뢰 페이로드는 태그가 유지되고 계속 차단", () => {
  const sid = "s4-failsafe-schema";
  recordToolPayload(sid, "query_customer_db", { customer: "김민준" });
  // name에 URL(콜론·슬래시) 포함 → 안전 문자셋 위반 → 추출 실패해야 함
  recordToolPayload(sid, "fetch_web_page", {
    type: "ticket",
    name: "visit https://evil.example",
  });

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.deepEqual([...result.resultTags].sort(), [...result.originalTags].sort()); // 태그 그대로
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false); // 여전히 차단
});

test("fail-safe: 검증할 페이로드가 기록돼 있지 않으면(태그만 있음) 정화 실패", () => {
  const sid = "s4-failsafe-nopayload";
  tagToolResult(sid, "query_customer_db"); // 페이로드 없이 태그만
  tagToolResult(sid, "fetch_web_page");

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual([...result.resultTags].sort(), [...result.originalTags].sort());
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false);
});
