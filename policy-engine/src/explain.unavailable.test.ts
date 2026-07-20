/**
 * 사용자용 설명 계층 — 정화 근거가 설정에 전혀 없을 때의 SANITIZE 가용성.
 *
 * available은 정화 게이트의 설정 기준 선행조건(canTokenize/canExtractStructured)을
 * 따른다: 근거가 없으면 눌러봐야 fail-safe로 실패하므로 "가능"이라 표시하면 안 된다.
 * 설정은 프로세스당 1회 캐시라(getPolicyConfig) 이 케이스는 자기 픽스처를 가진
 * 별도 파일이어야 한다 — explain.test.ts의 픽스처는 근거가 있는(가능) 쪽을 검증한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-explain-unavail-"));
const configFile = path.join(dir, "explain-unavailable.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "explain-unavailable-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    hitlPolicy: "weak-only",
    // 정화 근거 없음 — piiPatterns·secretDetection·extractionSchema 전부 생략.
    // canTokenize()=false, canExtractStructured()=false가 되는 유일한 목적의 픽스처.
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, evaluateToolCall } = await import("./index.js");

function ctx(sessionId: string): ToolCallContext {
  return {
    sessionId,
    toolName: "http_post",
    args: {},
    argTags: [],
    timestamp: new Date().toISOString(),
  };
}

/** 사람 말 필드에 노출되면 안 되는 기술 용어 (explain.test.ts와 동일 규칙) */
const BANNED = /SENSITIVE|UNTRUSTED|OUTBOUND|TOKENIZATION|STRUCTURED_EXTRACTION|trifecta|lethal|tn_/;

test("정화 근거 없는 설정: SANITIZE(TOKENIZATION) available:false + detail 없음 + 사유는 사람 말", () => {
  const sid = "eu1-unavailable";
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // 폴백 → weak 트라이펙타

  const decision = evaluateToolCall(ctx(sid));
  assert.equal(decision.allowed, false);
  assert.ok(decision.explanation);

  const sanitizes = decision.explanation!.actions.filter((a) => a.kind === "SANITIZE");
  // ★ F1 이후 유출 SANITIZE는 TOKENIZATION 하나뿐(STRUCTURED_EXTRACTION 제거). 정화
  //   근거가 없는 설정이므로 그 하나가 available:false + detail 없음 + 사유 사람말.
  assert.equal(sanitizes.length, 1);
  for (const action of sanitizes) {
    assert.equal(action.available, false);
    assert.equal(action.detail, undefined); // 불가 액션은 기계용 정보도 없음 (e4 관례)
    assert.ok(action.description.length > 0); // "왜 안 되는지" 사유가 있어야 함
    assert.doesNotMatch(action.description, BANNED, `기술 용어 누출: "${action.description}"`);
  }
});

test("정화 근거 없어도 다른 액션(REQUEST_APPROVAL·INSPECT_SOURCE)은 영향 없음", () => {
  const sid = "eu2-others-intact";
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서");

  const decision = evaluateToolCall(ctx(sid));
  assert.equal(decision.canOverride, true); // weak 차단 — HITL은 정화 설정과 무관
  const approval = decision.explanation!.actions.find((a) => a.kind === "REQUEST_APPROVAL")!;
  assert.equal(approval.available, true);
  assert.equal(approval.detail, decision.approvalId);
  const inspect = decision.explanation!.actions.find((a) => a.kind === "INSPECT_SOURCE")!;
  assert.equal(inspect.available, true);
});
