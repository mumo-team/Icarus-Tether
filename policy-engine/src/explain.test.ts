/**
 * 사용자용 설명 계층 테스트 — lineage + weak-only + toolLabels 설정.
 *
 * 핵심 검증: 사람 말 필드(summary/reason/risks/label/description)에 기술 용어가
 * 새지 않는다 — regex로 강제. detail은 기계용 필드라 예외.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext, type UserFacingExplanation } from "@taintguard/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-explain-"));
const configFile = path.join(dir, "explain.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "explain-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    hitlPolicy: "weak-only",
    toolLabels: {
      read_secrets: "비밀 파일 읽기",
      fetch_web_page: "웹 페이지 가져오기",
      http_post: "외부로 전송",
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, evaluateToolCall } = await import("./index.js");

function ctx(
  sessionId: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags, timestamp: new Date().toISOString() };
}

function setupWeakTrifecta(sid: string): void {
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // 폴백 → weak
}

/** 사람 말 필드에 노출되면 안 되는 기술 용어 (detail은 검사 제외 — 기계용) */
const BANNED = /SENSITIVE|UNTRUSTED|OUTBOUND|TOKENIZATION|STRUCTURED_EXTRACTION|trifecta|lethal|tn_/;

function humanTexts(ex: UserFacingExplanation): string[] {
  return [
    ex.summary,
    ex.reason,
    ...ex.risks,
    ...ex.actions.flatMap((a) => [a.label, a.description]),
  ];
}

// ---------------------------------------------------------------------------

test("차단 시 explanation이 채워지고, 사람 말 필드에 기술 용어가 새지 않는다", () => {
  const sid = "e1-human";
  setupWeakTrifecta(sid);

  const decision = evaluateToolCall(ctx(sid));
  assert.equal(decision.allowed, false);
  assert.ok(decision.explanation);

  for (const text of humanTexts(decision.explanation!)) {
    assert.doesNotMatch(text, BANNED, `기술 용어 누출: "${text}"`);
    assert.ok(text.length > 0);
  }
  assert.ok(decision.explanation!.summary.includes("막았어요"));
  assert.ok(decision.explanation!.risks.length > 0);
});

test("SANITIZE: 정화로 풀 수 있는 태그별 액션이 available:true + 기계용 detail에 method", () => {
  const sid = "e2-sanitize";
  setupWeakTrifecta(sid);

  const ex = evaluateToolCall(ctx(sid)).explanation!;
  const sanitizes = ex.actions.filter((a) => a.kind === "SANITIZE");
  assert.equal(sanitizes.length, 2); // SENSITIVE·UNTRUSTED 각각
  assert.ok(sanitizes.every((a) => a.available));
  const details = sanitizes.map((a) => a.detail).sort();
  assert.deepEqual(
    details,
    [SanitizationMethod.STRUCTURED_EXTRACTION, SanitizationMethod.TOKENIZATION].sort()
  );
});

test("REQUEST_APPROVAL: weak 차단이면 available:true + detail에 approvalId", () => {
  const sid = "e3-approval";
  setupWeakTrifecta(sid);

  const decision = evaluateToolCall(ctx(sid));
  assert.equal(decision.canOverride, true);
  const approval = decision.explanation!.actions.find((a) => a.kind === "REQUEST_APPROVAL")!;
  assert.equal(approval.available, true);
  assert.equal(approval.detail, decision.approvalId);
});

test("REQUEST_APPROVAL: strong(명시 참조) 차단이면 available:false + '왜 못 여는지' 설명", () => {
  const sid = "e4-strong";
  const a = recordToolResult(sid, "read_secrets", undefined, "키");
  const b = recordToolResult(sid, "fetch_web_page", { _taintRef: [a.id] }, "문서");

  const decision = evaluateToolCall(ctx(sid, { _taintRef: [b.id] }));
  assert.equal(decision.canOverride, false);
  const approval = decision.explanation!.actions.find((a2) => a2.kind === "REQUEST_APPROVAL")!;
  assert.equal(approval.available, false);
  assert.equal(approval.detail, undefined);
  assert.ok(approval.description.includes("열 수 없")); // 이유도 사람 말로
});

test("노드 id 대신 도구 라벨: reason·출처 설명에 tn_ 없음 + config 라벨 노출", () => {
  const sid = "e5-labels";
  setupWeakTrifecta(sid);

  const ex = evaluateToolCall(ctx(sid)).explanation!;
  assert.ok(ex.reason.includes("비밀 파일 읽기")); // read_secrets의 라벨
  assert.ok(ex.reason.includes("웹 페이지 가져오기")); // fetch_web_page의 라벨
  assert.doesNotMatch(ex.reason, /tn_/);

  const inspect = ex.actions.find((a) => a.kind === "INSPECT_SOURCE")!;
  assert.equal(inspect.available, true); // 항상 가능
  assert.ok(inspect.description.includes("비밀 파일 읽기"));
  assert.doesNotMatch(inspect.description, /tn_/);
});

test("개발자용 reason은 그대로 유지된다 (노드 id·기술 용어 포함 — 디버깅용)", () => {
  const sid = "e6-dev-reason";
  setupWeakTrifecta(sid);

  const decision = evaluateToolCall(ctx(sid));
  assert.ok(decision.reason?.includes("lethal trifecta")); // 개발자용은 불변
  assert.match(decision.reason ?? "", /tn_/); // 노드 id도 그대로
});

test("fail-safe 차단(계산 실패)에도 단순 explanation이 붙는다", () => {
  const circular: Record<string, unknown> = {};
  circular.self = circular;

  const decision = evaluateToolCall(ctx("e7-failsafe", circular));
  assert.equal(decision.allowed, false);
  assert.ok(decision.explanation);
  assert.ok(decision.explanation!.summary.includes("막았어요"));
  for (const text of humanTexts(decision.explanation!)) {
    assert.doesNotMatch(text, BANNED);
  }
});

test("통과 결정에는 explanation이 없다 (차단 설명 계층이므로)", () => {
  const decision = evaluateToolCall(ctx("e8-allowed"));
  assert.equal(decision.allowed, true);
  assert.equal(decision.explanation, undefined);
});
