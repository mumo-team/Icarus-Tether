/**
 * 파괴적 액션 게이트 — destructivePolicy:"block" (확정 차단, 승인 우회 없음).
 * 설정이 프로세스당 1회 캐시라 정책별로 파일을 나눈다 (explain.test.ts 관례).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-destructive-block-"));
const configFile = path.join(dir, "destructive-block.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "destructive-block-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    sinks: {
      read_secrets: "READ",
      fetch_web_page: "READ",
      delete_records: "WRITE_INTERNAL",
    },
    judgmentMode: "lineage",
    destructivePolicy: "block",
    destructiveTools: ["delete_records"],
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { evaluateToolCall, recordToolResult } = await import("./index.js");

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------

test("block 정책: 비신뢰 노출 후 삭제는 확정 차단 — 승인 우회 없음", () => {
  const sid = "db1-block";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const decision = evaluateToolCall(ctx(sid, "delete_records"));
  assert.equal(decision.allowed, false);
  assert.deepEqual(decision.matchedTags, [ToolRiskTag.UNTRUSTED_ORIGIN]);
  assert.equal(decision.canOverride, false);
  assert.equal(decision.approvalId, undefined);
  assert.ok(!decision.reason?.includes("[HITL"));

  // 설명 계층: 승인 액션은 불가 + "왜 못 여는지" 사람 말 (detail 없음 — 불가 관례)
  const approval = decision.explanation!.actions.find((a) => a.kind === "REQUEST_APPROVAL")!;
  assert.equal(approval.available, false);
  assert.equal(approval.detail, undefined);
  assert.ok(approval.description.includes("열 수 없"));
});

test("block 정책도 사용자 직접 지시 삭제(깨끗한 세션)는 통과", () => {
  const sid = "db2-clean";
  assert.equal(evaluateToolCall(ctx(sid, "delete_records")).allowed, true);
});
