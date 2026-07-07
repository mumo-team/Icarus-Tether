/**
 * dev 도메인(config/dev.json) 엔진 통합 테스트.
 *
 * node --test는 테스트 파일마다 별도 프로세스를 띄우므로, 여기서 설정한
 * TAINTGUARD_DOMAIN이 다른 테스트 파일(default 도메인)과 충돌하지 않는다.
 * env를 먼저 세팅한 뒤 동적 import로 엔진을 로드한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@taintguard/types";

process.env.TAINTGUARD_DOMAIN = "dev";
const { tagToolResult, recordToolPayload, attemptSanitization, evaluateToolCall } = await import(
  "./index.js"
);

function ctx(sessionId: string, toolName: string, argTags: ToolRiskTag[] = []): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags, timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// dev 도메인 3대 시나리오
// ---------------------------------------------------------------------------

test("dev/정상 통과: 깨끗한 세션은 outbound 싱크(http_post)도 허용", () => {
  assert.equal(evaluateToolCall(ctx("d1-clean", "http_post")).allowed, true);
});

test("dev/트라이펙타 차단: read_env_file + read_github_issue → push_to_remote 차단", () => {
  tagToolResult("d1-block", "read_env_file"); // SENSITIVE (출처 기반, 1순위)
  tagToolResult("d1-block", "read_github_issue"); // UNTRUSTED_ORIGIN
  const decision = evaluateToolCall(ctx("d1-block", "push_to_remote"));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("lethal trifecta"));
});

test("dev/정화 후 통과: dev 스키마({type, title≤80}) 구조화 추출로 세션이 다시 열림", () => {
  const sid = "d1-extract";
  recordToolPayload(sid, "read_env_file", { DB_PASSWORD: "hunter2" });
  recordToolPayload(sid, "read_github_issue", { type: "bug", title: "로그인 버튼이 안 눌림" });

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.deepEqual(result.resultTags, [ToolRiskTag.SENSITIVE]); // UNTRUSTED만 해제

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, true);
});

// ---------------------------------------------------------------------------
// 원칙 4: default-deny — 미분류 도구는 위험 취급
// ---------------------------------------------------------------------------

test("default-deny(싱크): 오염 세션에서 미분류 도구 호출 → OUTBOUND_SINK 취급으로 차단", () => {
  const sid = "d2-unknown-sink";
  tagToolResult(sid, "read_env_file");
  tagToolResult(sid, "read_github_issue");

  const decision = evaluateToolCall(ctx(sid, "my_shiny_new_tool"));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("미분류 도구"));
});

test("default-deny(싱크): 깨끗한 세션이면 미분류 도구도 통과 (트라이펙타 미성립)", () => {
  assert.equal(evaluateToolCall(ctx("d2-unknown-clean", "my_shiny_new_tool")).allowed, true);
});

test("default-deny(소스): 미분류 도구의 결과는 UNTRUSTED_ORIGIN으로 태깅된다", () => {
  const sid = "d2-unknown-source";
  tagToolResult(sid, "read_env_file"); // SENSITIVE
  tagToolResult(sid, "weird_unregistered_tool"); // 미분류 → UNTRUSTED_ORIGIN이어야 함

  // 미분류 도구 결과가 UNTRUSTED로 잡혔다면 트라이펙타가 성립해 차단된다
  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);
});

// ---------------------------------------------------------------------------
// 내용 기반 비밀 탐지 (2·3순위) — 출처가 민감 소스가 아니어도 잡는다
// ---------------------------------------------------------------------------

test("내용 기반(3순위 정규식): GitHub 이슈 본문에 유출된 AWS 키 → SENSITIVE 전파 → 차단", () => {
  const sid = "d3-leaked-key";
  // read_github_issue는 비신뢰 소스일 뿐 민감 소스가 아니다 — 내용이 SENSITIVE를 만든다
  recordToolPayload(sid, "read_github_issue", "빌드 로그: AKIAIOSFODNN7EXAMPLE 키가 노출됨");
  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);
});

test("내용 기반(2순위 엔트로피): 형식 모르는 무작위 토큰이 실려와도 SENSITIVE 전파 → 차단", () => {
  const sid = "d3-entropy";
  recordToolPayload(sid, "read_pr_comment", {
    comment: "여기 임시 키: kJ8xQ2mZ9vL4nR7tB1wY5cF3hD6pS0aG",
  });
  assert.equal(evaluateToolCall(ctx(sid, "push_to_remote")).allowed, false);
});

test("내용 기반: 비밀 없는 평범한 이슈 본문은 UNTRUSTED만 — 단독으로는 통과", () => {
  const sid = "d3-clean-issue";
  recordToolPayload(sid, "read_github_issue", "버그: 다크모드에서 버튼이 안 보여요");
  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, true);
});

// ---------------------------------------------------------------------------
// 토큰화 정화 — 엔트로피로 잡은 비밀도 토큰화로 해제 가능
// ---------------------------------------------------------------------------

test("dev/정화 후 통과: 엔트로피 비밀을 토큰화해 SENSITIVE 해제 → 세션이 다시 열림", () => {
  const sid = "d4-tokenize";
  recordToolPayload(sid, "read_secrets", { API_KEY: "kJ8xQ2mZ9vL4nR7tB1wY5cF3hD6pS0aG" });
  recordToolPayload(sid, "read_pr_comment", "리뷰 코멘트입니다");

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual(result.resultTags, [ToolRiskTag.UNTRUSTED_ORIGIN]); // SENSITIVE만 해제

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, true);
});

// ---------------------------------------------------------------------------
// 원칙 5: fail-safe — 검증 실패 시 태그 유지 → 계속 차단
// ---------------------------------------------------------------------------

test("fail-safe: dev 스키마를 통과 못 하는 페이로드(type 밖 enum·title 초과)는 계속 차단", () => {
  const sid = "d5-failsafe";
  recordToolPayload(sid, "read_env_file", { TOKEN: "secret" });
  recordToolPayload(sid, "read_github_issue", { type: "chore", title: "스키마 밖 타입" });

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.deepEqual([...result.resultTags].sort(), [...result.originalTags].sort());
  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);

  const sid2 = "d5-failsafe-long";
  recordToolPayload(sid2, "read_env_file", { TOKEN: "secret" });
  recordToolPayload(sid2, "read_github_issue", { type: "bug", title: "가".repeat(81) });
  attemptSanitization(sid2, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.equal(evaluateToolCall(ctx(sid2, "http_post")).allowed, false);
});
