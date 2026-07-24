/**
 * resources/read·prompts/get 외부 콘텐츠 오염 태깅 (파트1 미탐 폐쇄).
 *
 * 파트1 확정: 프록시가 tools/call만 엔진에 넘겨, resources/read로 들어온 비신뢰
 * 콘텐츠가 exposure(U축)를 안 켰다 → 같은 lethal-trifecta 유출이 채널만 바꾸면
 * 통과(출력스캔까지 무력화). recordExternalContent가 그 콘텐츠를 recordToolResult와
 * 동일 파이프라인에 흘려보내 exposure를 켠다. tools/call 판정은 무변경(additive).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";
import {
  recordExternalContent,
  recordToolPayload,
  evaluateToolCall,
  isSessionExposed,
} from "./index.js";

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

test("★ 미탐 폐쇄: resources/read 비신뢰 유입 → exposure 켜짐 → 민감 유출 차단", () => {
  const sid = "ext-resources";
  // 1) 외부 리소스(비신뢰) 유입 — 이제 엔진이 안다
  recordExternalContent(sid, "resources/read", "file:///company/readme.txt", {
    contents: [{ text: "외부 문서 본문 — 신뢰할 수 없는 콘텐츠" }],
  });
  assert.equal(isSessionExposed(sid), true, "외부 비신뢰 콘텐츠로 exposure가 켜져야 함");

  // 2) 민감 데이터 읽기
  recordToolPayload(sid, "query_customer_db", { customer: "홍길동", plan: "pro" });

  // 3) 민감 유출 시도 → 차단 (파트1에서는 통과했던 지점)
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false, "이제 트라이펙타 성립 → 차단");
});

test("prompts/get도 동일 경로로 exposure를 켠다", () => {
  const sid = "ext-prompts";
  recordExternalContent(sid, "prompts/get", "summarize-ticket", {
    messages: [{ content: { text: "사용자 제공 프롬프트 본문" } }],
  });
  assert.equal(isSessionExposed(sid), true);
  recordToolPayload(sid, "query_customer_db", { customer: "김민준" });
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false);
});

test("순서 무관(grow-only): 민감 먼저 읽고 리소스가 나중이어도 차단", () => {
  const sid = "ext-order";
  recordToolPayload(sid, "query_customer_db", { customer: "홍길동" });
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true, "U 유입 전에는 통과");
  recordExternalContent(sid, "resources/read", "file:///x", { contents: [{ text: "외부 본문" }] });
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false, "리소스 유입 후 차단");
});

test("trusted:true면 UNTRUSTED_ORIGIN을 안 붙인다 (명시적 신뢰 — exposure 미발동)", () => {
  const sid = "ext-trusted";
  const node = recordExternalContent(
    sid,
    "resources/read",
    "file:///internal/trusted-config.txt",
    { contents: [{ text: "내부 신뢰 설정 값" }] },
    { trusted: true }
  );
  assert.equal(isSessionExposed(sid), false, "trusted면 exposure 안 켜짐");
  assert.ok(!node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN), "U 미부여");
  // 이후 민감만 있는 세션 → 트라이펙타 미성립 → 통과 (U가 없으므로)
  recordToolPayload(sid, "query_customer_db", { customer: "홍길동" });
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true);
});

test("내용에 비밀 패턴이 있으면 SENSITIVE도 부여 (내용 기반 — computeResultTags와 동일 규칙)", () => {
  const sid = "ext-secret";
  const node = recordExternalContent(sid, "resources/read", "file:///leak", {
    contents: [{ text: "설정: key=AKIAIOSFODNN7EXAMPLE 입니다" }],
  });
  assert.ok(node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN), "외부 → 비신뢰");
  assert.ok(node.tags.has(ToolRiskTag.SENSITIVE), "비밀 패턴 → 민감");
});

test("trusted라도 내용에 비밀이 있으면 SENSITIVE는 붙는다(U만 생략)", () => {
  const sid = "ext-trusted-secret";
  const node = recordExternalContent(
    sid,
    "resources/read",
    "file:///internal/env",
    { contents: [{ text: "AKIAIOSFODNN7EXAMPLE" }] },
    { trusted: true }
  );
  assert.ok(!node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(node.tags.has(ToolRiskTag.SENSITIVE));
});

test("additive 확인: 외부 콘텐츠 API를 안 쓰면 tools/call 판정은 기존과 동일", () => {
  const sid = "ext-additive";
  // 순수 tools/call 흐름 — recordExternalContent 미사용
  recordToolPayload(sid, "query_customer_db", { customer: "홍길동" });
  recordToolPayload(sid, "fetch_web_page", "외부 본문");
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false, "기존 트라이펙타 차단 불변");
});
