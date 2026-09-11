/**
 * 안전 바닥 완화 스위치는 session 모드에 영향을 주지 않는다.
 *
 * session 판정(computeSessionDecision)에는 출력 스캔이 없으므로 "스캔이 아무것도 못 찾음"이라는
 * 조건 자체가 성립하지 않는다. 스위치를 켠 설정으로 session 모드를 돌려도 S+U 세션의 외부 싱크는
 * 기존대로 차단돼야 두 정책(session vs lineage)의 비교가 성립한다. 설정 캐시가 프로세스당
 * 하나라 별도 파일로 둔다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-relax-session-"));
const configFile = path.join(dir, "relax-session.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "relax-session-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "session",
    fallbackRelaxation: "scan-clean",
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, evaluateToolCall, getPolicyConfig } = await import("./index.js");

const ctx = (sessionId: string, args: Record<string, unknown>): ToolCallContext => ({
  sessionId,
  toolName: "http_post",
  args,
  argTags: [],
  timestamp: new Date().toISOString(),
});

test("설정 파싱: fallbackRelaxation=scan-clean이 로드된다", () => {
  assert.equal(getPolicyConfig().fallbackRelaxation, "scan-clean");
});

test("session 모드: 스위치가 켜져 있어도 S+U 세션의 무관 내용 전송은 기존대로 차단", () => {
  const sid = "relax-session-1";
  const origLog = console.log;
  console.log = () => {};
  try {
    recordToolResult(sid, "fetch_web_page", undefined, "외부 콘텐츠");
    recordToolResult(sid, "read_secrets", undefined, "h9x2mq");
    const d = evaluateToolCall(ctx(sid, { body: "총 레코드 42건, 평균 처리 1.3초" }));
    assert.equal(d.allowed, false);
    assert.doesNotMatch(d.reason ?? "", /안전 바닥 완화/);
  } finally {
    console.log = origLog;
  }
});
