/**
 * HITL TOCTOU 회귀 테스트 — 승인~소비 사이 계보 변화 시 낡은 승인 무효화.
 *
 * 배경: TaintHITL.tla 형식검증이 발견한 TOCTOU — 소비 시점에 계보를 재확인하지
 * 않으면, 승인 시점엔 weak였던 연결이 소비 시점에 strong으로 재분류돼도 낡은
 * 승인이 "확정 차단이어야 할 strong 트라이펙타"를 통과시킨다. 수정: 제안 시점
 * 계보 지문을 저장하고 소비 시점에 대조(불일치 → OVERRIDE_STALE, 영구 무효).
 *
 * (별도 프로세스이므로 임시 설정 파일 + TAINTGUARD_TOOL_REGISTRY로 로드 —
 * hitl.test.ts와 같은 부트스트랩 패턴)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-hitl-toctou-"));
const configFile = path.join(dir, "hitl-toctou.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "hitl-toctou-test",
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

function ctx(sessionId: string, args: Record<string, unknown>): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags: [], timestamp: new Date().toISOString() };
}

/** 폴백(weak)으로만 엮인 트라이펙타 세션 준비 (hitl.test.ts와 동일 패턴) */
function setupWeakTrifecta(sid: string): void {
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // 폴백 → weak 상속
}

/** 승인까지 완료된 weak 차단 상황을 만들고 approvalId를 돌려준다 */
function approveWeakBlock(sid: string, args: Record<string, unknown>): string {
  const d = evaluateToolCall(ctx(sid, args));
  assert.equal(d.allowed, false);
  assert.equal(d.canOverride, true); // 승인 시점엔 weak — 승인이 정당했다
  const approvalId = d.approvalId!;
  requestApproval(sid, approvalId);
  resolveApproval(approvalId, true, "reviewer-kim");
  return approvalId;
}

// ---------------------------------------------------------------------------
// ★T1 TOCTOU 회귀: 승인 후 weak→strong 승격 → 낡은 승인 소비 시도 → 거부
// (TaintHITL.tla 반례 Offer→Approve→Escalate→Consume의 코드판 — 이제 막혀야 함)
// ---------------------------------------------------------------------------

// 16자 이상 단일 토큰 — 결과에 등장하면 VALUE_MATCH가 strong으로 분류 (lineage.ts STRONG_TOKEN_MIN_LENGTH)
const LONG_TOKEN = "EXFILTRATION-PAYLOAD-TOKEN-1234567890";

test("★TOCTOU: 승인 후 strong 재분류(Escalate) → 낡은 승인 미소비 + 확정 차단 + OVERRIDE_STALE", () => {
  const sid = "t1-toctou";
  setupWeakTrifecta(sid);
  const attackArgs = { body: LONG_TOKEN };

  // Offer→Approve: 이 시점 evidence는 폴백(weak) — 승인 가능이 맞았다
  const approvalId = approveWeakBlock(sid, attackArgs);

  // ★Escalate: 승인~소비 사이 recordToolResult — 같은 토큰을 결과에 담은 오염
  // 노드가 생겨, 같은 args가 VALUE_MATCH strong으로 재분류된다
  recordToolResult(sid, "fetch_web_page", undefined, `본문: ${LONG_TOKEN}`);

  // Consume 시도: 계보 지문 불일치 → 낡은 승인 무효, strong 트라이펙타 확정 차단
  const d = evaluateToolCall(ctx(sid, attackArgs));
  assert.equal(d.allowed, false); // 낡은 승인이 통과시키지 못한다 (1단계 반례 시나리오 봉쇄)
  assert.equal(d.canOverride, false); // 이제 strong — 사람도 못 여는 확정 차단
  assert.equal(d.approvalId, undefined);

  const actions = getOverrideAuditLog(sid)
    .filter((e) => e.approvalId === approvalId)
    .map((e) => e.action);
  assert.deepEqual(actions, ["OFFERED", "REQUESTED", "APPROVED", "OVERRIDE_STALE"]);
});

test("★T2 영구 무효: 무효화된 승인은 이후 어떤 재평가에서도 소비되지 않는다", () => {
  const sid = "t2-permanent";
  setupWeakTrifecta(sid);
  const attackArgs = { body: LONG_TOKEN };
  const approvalId = approveWeakBlock(sid, attackArgs);
  recordToolResult(sid, "fetch_web_page", undefined, `본문: ${LONG_TOKEN}`);

  for (let i = 0; i < 3; i++) {
    assert.equal(evaluateToolCall(ctx(sid, attackArgs)).allowed, false);
  }
  const log = getOverrideAuditLog(sid).filter((e) => e.approvalId === approvalId);
  assert.ok(!log.some((e) => e.action === "OVERRIDE_USED")); // 통과에 쓰인 적 없음
  assert.equal(log.filter((e) => e.action === "OVERRIDE_STALE").length, 1); // 무효화는 1회 기록
});

// ---------------------------------------------------------------------------
// ★T3 지문 대조의 엄격함: 변경됐지만 "여전히 weak"인 경우도 낡은 승인은 무효 —
// 단, 새 제안이 발급되고 재승인하면 통과 (HITL이 무용지물이 되지 않음)
// ---------------------------------------------------------------------------

test("★T3 변경-but-still-weak: 낡은 승인 무효 + 새 제안 발급 → 재승인하면 통과", () => {
  const sid = "t3-stillweak";
  setupWeakTrifecta(sid);
  // 9자 토큰 — 매칭돼도 단일·짧아서 weak VALUE_MATCH (STRONG_TOKEN_MIN_LENGTH 미만)
  const args = { body: "shorttok9" };

  const approvalId1 = approveWeakBlock(sid, args);

  // 계보 변화: 같은 토큰을 결과에 담은 노드 → evidence가 폴백(a,b)에서
  // weak VALUE_MATCH(새 노드)로 바뀜 — 여전히 all-weak지만 "사람이 본 그림"과 다르다
  recordToolResult(sid, "fetch_web_page", undefined, "ref shorttok9 끝");

  // 낡은 승인은 무효(승인 이식 차단) — 하지만 여전히 weak이므로 새 제안 발급
  const d2 = evaluateToolCall(ctx(sid, args));
  assert.equal(d2.allowed, false);
  assert.equal(d2.canOverride, true);
  const approvalId2 = d2.approvalId!;
  assert.notEqual(approvalId2, approvalId1); // 새 계보 지문의 새 제안

  // 새 제안을 재승인하면 통과 — 정상 HITL 흐름은 살아 있다
  requestApproval(sid, approvalId2);
  resolveApproval(approvalId2, true, "reviewer-kim");
  const d3 = evaluateToolCall(ctx(sid, args));
  assert.equal(d3.allowed, true);
  assert.ok(d3.reason?.includes(approvalId2));

  const stale = getOverrideAuditLog(sid).filter((e) => e.approvalId === approvalId1);
  assert.equal(stale[stale.length - 1].action, "OVERRIDE_STALE");
  const used = getOverrideAuditLog(sid).filter((e) => e.approvalId === approvalId2);
  assert.equal(used[used.length - 1].action, "OVERRIDE_USED");
});

// ---------------------------------------------------------------------------
// 정상 케이스 불변: 계보가 안 변했으면 승인은 그대로 통과 (hitl.test.ts h4의
// 보장을 이 파일에서도 독립 확인 — 지문 대조가 정상 흐름을 깨지 않는다)
// ---------------------------------------------------------------------------

test("정상 weak 승인: 승인~소비 사이 계보 변화 없음 → 여전히 1회 통과", () => {
  const sid = "t4-normal";
  setupWeakTrifecta(sid);
  const args = { body: "전송" };

  const approvalId = approveWeakBlock(sid, args);
  const d = evaluateToolCall(ctx(sid, args));
  assert.equal(d.allowed, true); // 지문 일치 — 재검증이 정상 케이스를 막지 않는다
  assert.ok(d.reason?.includes(approvalId));
});
