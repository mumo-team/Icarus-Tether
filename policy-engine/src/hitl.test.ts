/**
 * HITL 오버라이드 테스트 — judgmentMode=lineage + hitlPolicy=weak-only.
 * (별도 프로세스이므로 임시 설정 파일 + TAINTGUARD_TOOL_REGISTRY로 로드)
 *
 * 제일 중요한 검증: 승인이 확정되기 전까지는(OFFERED/PENDING/REJECTED) 몇 번을
 * 재평가해도 차단 — "응답 없음 → 통과"가 절대 없다 (fail-safe).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, type ToolCallContext } from "@taintguard/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-hitl-"));
const configFile = path.join(dir, "hitl.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "hitl-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    hitlPolicy: "weak-only",
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const {
  recordToolResult,
  evaluateToolCall,
  requestApproval,
  resolveApproval,
  getOverrideAuditLog,
} = await import("./index.js");

function ctx(
  sessionId: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags, timestamp: new Date().toISOString() };
}

/** 폴백(weak)으로만 엮인 트라이펙타 세션 준비 */
function setupWeakTrifecta(sid: string): void {
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // 폴백 → weak 상속
}

// ---------------------------------------------------------------------------
// 승인 가능 여부 — 결정론 판정
// ---------------------------------------------------------------------------

test("weak(폴백) 연결 트라이펙타 → 차단 + canOverride:true + approvalId 발급", () => {
  const sid = "h1-weak";
  setupWeakTrifecta(sid);

  const decision = evaluateToolCall(ctx(sid));
  assert.equal(decision.allowed, false); // 차단은 차단 (HITL은 제안만)
  assert.equal(decision.canOverride, true);
  assert.match(decision.approvalId ?? "", /^ap_/);
  assert.ok(decision.reason?.includes("승인 요청 가능"));
});

test("명시 참조(MCP_REF, strong) 트라이펙타 → canOverride:false — 사람도 못 여는 확정 차단", () => {
  const sid = "h2-strong";
  const a = recordToolResult(sid, "read_secrets", undefined, "키");
  const b = recordToolResult(sid, "fetch_web_page", { _taintRef: [a.id] }, "문서"); // strong 연결

  const decision = evaluateToolCall(ctx(sid, { _taintRef: [b.id] })); // strong 참조로 유출 시도
  assert.equal(decision.allowed, false);
  assert.equal(decision.canOverride, false);
  assert.equal(decision.approvalId, undefined);
});

test("argTags가 오염을 실으면 → canOverride:false (프록시가 확정한 증거)", () => {
  const sid = "h3-argtags";
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // 계보엔 🔵(weak)만

  const decision = evaluateToolCall(ctx(sid, {}, [ToolRiskTag.SENSITIVE]));
  assert.equal(decision.allowed, false);
  assert.equal(decision.canOverride, false);
});

// ---------------------------------------------------------------------------
// 승인 수명주기
// ---------------------------------------------------------------------------

test("승인 플로우: 요청→승인→1회 통과→다시 차단(single-use), 재평가 중 approvalId 안정", () => {
  const sid = "h4-flow";
  setupWeakTrifecta(sid);

  const d1 = evaluateToolCall(ctx(sid));
  assert.equal(d1.allowed, false);
  const approvalId = d1.approvalId!;

  // 승인 대기 등록
  const req = requestApproval(sid, approvalId);
  assert.equal(req.status, "PENDING");

  // ★fail-safe: PENDING(미해결) 동안은 몇 번을 재평가해도 차단
  const d2 = evaluateToolCall(ctx(sid));
  assert.equal(d2.allowed, false);
  assert.equal(d2.approvalId, approvalId); // 재평가해도 같은 제안 재사용 (id 안정성)
  assert.equal(evaluateToolCall(ctx(sid)).allowed, false);

  // 사람이 명시적으로 승인
  const resolved = resolveApproval(approvalId, true, "reviewer-kim");
  assert.equal(resolved.status, "APPROVED");
  assert.equal(resolved.resolvedBy, "reviewer-kim");

  // 같은 호출 재평가 → 1회 통과
  const d3 = evaluateToolCall(ctx(sid));
  assert.equal(d3.allowed, true);
  assert.ok(d3.reason?.includes(approvalId));
  assert.ok(d3.reason?.includes("reviewer-kim"));

  // single-use: 소비됐으므로 다음 호출은 다시 차단 (+ 새 제안)
  const d4 = evaluateToolCall(ctx(sid));
  assert.equal(d4.allowed, false);
  assert.equal(d4.canOverride, true);
  assert.notEqual(d4.approvalId, approvalId); // 새 승인 필요
});

test("거부: resolveApproval(false) → 계속 차단", () => {
  const sid = "h5-reject";
  setupWeakTrifecta(sid);

  const d1 = evaluateToolCall(ctx(sid));
  requestApproval(sid, d1.approvalId!);
  resolveApproval(d1.approvalId!, false, "reviewer-lee");

  assert.equal(evaluateToolCall(ctx(sid)).allowed, false);
});

test("★fail-safe: 승인 없이는(요청만 하고 방치) 영원히 차단 — 응답 없음 → 통과 없음", () => {
  const sid = "h6-failsafe";
  setupWeakTrifecta(sid);

  const d1 = evaluateToolCall(ctx(sid));
  requestApproval(sid, d1.approvalId!);

  for (let i = 0; i < 5; i++) {
    assert.equal(evaluateToolCall(ctx(sid)).allowed, false);
  }
});

test("승인은 그 호출에만: 다른 args로 호출하면 지문 불일치 → 차단", () => {
  const sid = "h7-scope";
  setupWeakTrifecta(sid);

  const d1 = evaluateToolCall(ctx(sid, { body: "전송" }));
  requestApproval(sid, d1.approvalId!);
  resolveApproval(d1.approvalId!, true, "reviewer-kim");

  // 승인된 것과 다른 args → 승인 미적용, 차단 유지
  assert.equal(evaluateToolCall(ctx(sid, { body: "다른 내용" })).allowed, false);
  // 승인된 그 args는 통과
  assert.equal(evaluateToolCall(ctx(sid, { body: "전송" })).allowed, true);
});

test("fail-closed: 없는 approvalId·세션 불일치·미등록 해결은 전부 예외", () => {
  const sid = "h8-invalid";
  setupWeakTrifecta(sid);
  const d1 = evaluateToolCall(ctx(sid));

  assert.throws(() => requestApproval(sid, "ap_00000000-0000-0000-0000-000000000000"));
  assert.throws(() => requestApproval("다른-세션", d1.approvalId!));
  assert.throws(() => resolveApproval(d1.approvalId!, true)); // request 없이 resolve 불가
});

// ---------------------------------------------------------------------------
// 감사 로그
// ---------------------------------------------------------------------------

test("감사 로그: OFFERED→REQUESTED→APPROVED→OVERRIDE_USED가 승인자·시각과 함께 남는다", () => {
  const sid = "h9-audit";
  setupWeakTrifecta(sid);

  const d1 = evaluateToolCall(ctx(sid));
  requestApproval(sid, d1.approvalId!);
  resolveApproval(d1.approvalId!, true, "reviewer-kim");
  evaluateToolCall(ctx(sid)); // 승인 소비

  const log = getOverrideAuditLog(sid).filter((e) => e.approvalId === d1.approvalId);
  const actions = log.map((e) => e.action);
  assert.deepEqual(actions, ["OFFERED", "REQUESTED", "APPROVED", "OVERRIDE_USED"]);
  const used = log[log.length - 1];
  assert.equal(used.actor, "reviewer-kim"); // 누가
  assert.ok(used.timestamp); // 언제
  assert.equal(used.toolName, "http_post"); // 뭘
});
