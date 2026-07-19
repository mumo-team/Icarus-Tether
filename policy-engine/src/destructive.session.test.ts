/**
 * 파괴적 액션 게이트 — session(toy) 모드 패리티 + 섀도 순수성.
 *
 * 파괴 게이트는 judgmentMode와 독립이다: session 모드에서도 같은 시나리오가
 * 같은 결과(직접 삭제 통과 / 비신뢰 후 차단 / 정화 후 통과 / HITL 승인 통과)를
 * 내야 한다 (destructive.test.ts의 lineage판과 패리티). 추가로 섀도 비교 로그의
 * toyAllowed가 "유출-전용" 값임을 검증한다 — 파괴 합성값이 섞이면 toy↔real
 * 비교에 허위 불일치가 쌓인다 (섀도 순수성).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { SanitizationMethod, ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-destructive-session-"));
const configFile = path.join(dir, "destructive-session.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "destructive-session-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    sinks: {
      read_secrets: "READ",
      fetch_web_page: "READ",
      delete_records: "WRITE_INTERNAL",
      http_post: "OUTBOUND_SINK",
    },
    judgmentMode: "session",
    destructivePolicy: "hitl",
    destructiveTools: ["delete_records"],
    extractionSchema: {
      fields: {
        type: { kind: "enum", values: ["bug", "feature"] },
        title: { kind: "string", maxLength: 80, charset: "safe-text" },
      },
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const {
  attemptSanitization,
  evaluateToolCall,
  getShadowLog,
  recordToolResult,
  requestApproval,
  resolveApproval,
} = await import("./index.js");

function ctx(sessionId: string, toolName: string, args: Record<string, unknown> = {}): ToolCallContext {
  return { sessionId, toolName, args, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------

test("session 모드 패리티: 직접 삭제 2연속 통과 / 비신뢰 후 차단(hitl 제안)", () => {
  const sid = "ds1-parity";
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, true);
  recordToolResult(sid, "delete_records", {}, "ok");
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, true);

  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  const blocked = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(blocked.allowed, false);
  assert.deepEqual(blocked.matchedTags, [ToolRiskTag.UNTRUSTED_ORIGIN]);
  assert.equal(blocked.canOverride, true);
  assert.ok(blocked.approvalId);
});

test("섀도 순수성: 파괴 차단된 호출의 shadowLog.toyAllowed는 유출-전용 값", () => {
  const sid = "ds2-shadow";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const decision = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(decision.allowed, false, "최종 판정은 파괴 게이트 차단");

  const entries = getShadowLog(sid).filter((e) => e.toolName === "delete_records");
  assert.ok(entries.length > 0, "섀도 로그가 남아야 함 (session 모드)");
  const last = entries[entries.length - 1];
  // WRITE_INTERNAL이라 유출(toy) 판정은 통과 — 파괴 합성값(false)이 아니라
  // 유출-전용 값(true)이 기록돼야 toy↔real 비교가 오염되지 않는다.
  assert.equal(last.toyAllowed, true, "toyAllowed는 유출 판정 값이어야 함 (섀도 순수성)");
});

test("session 모드: 정화(구조화 추출) 후 삭제 통과", () => {
  const sid = "ds3-sanitize";
  recordToolResult(sid, "fetch_web_page", undefined, { type: "feature", title: "safe title" });
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.ok(!result.resultTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, true);
});

test("session 모드: HITL 승인 → 재시도 통과 (destructive HITL은 judgmentMode 독립)", () => {
  const sid = "ds4-hitl";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const blocked = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(blocked.allowed, false);
  requestApproval(sid, blocked.approvalId!);
  resolveApproval(blocked.approvalId!, true, "session-tester");

  const passed = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(passed.allowed, true);
  assert.ok(passed.reason?.includes("파괴 게이트: HITL 승인으로 1회 통과"));
});

test("유출(toy) 판정은 파괴 게이트와 무관하게 그대로: S+U 세션의 http_post 차단", () => {
  const sid = "ds5-exfil-intact";
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서");

  const decision = evaluateToolCall(ctx(sid, "http_post", { body: "전송" }));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("lethal trifecta"));
});
