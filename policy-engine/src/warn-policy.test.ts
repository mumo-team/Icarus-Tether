/**
 * unknownToolPolicy: "warn" 모드 테스트.
 *
 * default-deny(기본값 deny)는 dev-domain.test.ts에서 검증하고, 여기서는
 * 설정으로 완화("warn")했을 때 미분류 도구가 차단되지 않는지 확인한다.
 * (별도 프로세스이므로 임시 설정 파일 + TAINTGUARD_TOOL_REGISTRY로 로드)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, type ToolCallContext } from "@taintguard/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-warn-"));
const configFile = path.join(dir, "warn.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "warn-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    unknownToolPolicy: "warn",
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { tagToolResult, evaluateToolCall } = await import("./index.js");

function ctx(sessionId: string, toolName: string, argTags: ToolRiskTag[] = []): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags, timestamp: new Date().toISOString() };
}

test("warn 모드: 오염 세션이어도 미분류 도구는 차단하지 않는다 (READ 취급 + 경고만)", () => {
  const sid = "w1-tainted";
  tagToolResult(sid, "read_secrets");
  tagToolResult(sid, "fetch_web_page");

  assert.equal(evaluateToolCall(ctx(sid, "mystery_tool")).allowed, true);
});

test("warn 모드: 등록된 outbound 싱크는 여전히 차단된다 (완화는 미분류 도구에만 적용)", () => {
  const sid = "w2-tainted";
  tagToolResult(sid, "read_secrets");
  tagToolResult(sid, "fetch_web_page");

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);
});

test("warn 모드에서도 미분류 도구의 결과는 UNTRUSTED_ORIGIN으로 태깅된다 (소스 측 default-deny 유지)", () => {
  const sid = "w3-source";
  tagToolResult(sid, "read_secrets"); // SENSITIVE
  tagToolResult(sid, "mystery_feed_reader"); // 미분류 → UNTRUSTED_ORIGIN

  // 등록된 싱크로 나가려 하면 트라이펙타 성립 → 차단
  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false);
});
