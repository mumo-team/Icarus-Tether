/**
 * 파괴적 액션 게이트 — lineage + destructivePolicy:"hitl" + hitlPolicy:"weak-only".
 *
 * 핵심 검증(설계 요구사항): "삭제 자체"가 아니라 "비신뢰가 유발한 파괴"만 차단 —
 * 사용자 직접 지시 삭제(깨끗한 세션)는 통과, 비신뢰 노출 후 삭제는 차단+HITL.
 * 의미론의 선행 확정본은 formal/TaintDestructiveHITL.tla (TLC 위반 0) — 여기의
 * 시나리오들은 그 모델의 전이·불변식의 코드판이다.
 *
 * session 모드 패리티는 destructive.session.test.ts, block 정책은
 * destructive.block.test.ts, off 기본값·설정 검증은 destructive.config.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  SanitizationMethod,
  ToolRiskTag,
  type ToolCallContext,
  type UserFacingExplanation,
} from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-destructive-"));
const configFile = path.join(dir, "destructive.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "destructive-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    sinks: {
      read_secrets: "READ",
      fetch_web_page: "READ",
      // ★ 파괴 도구도 sinks 등급을 명시한다 (설정 가이드) — 안 하면 미선언 싱크
      //   default-deny(OUTBOUND 취급)로 유출 축에도 걸려 파괴 축 검증이 오염된다.
      delete_records: "WRITE_INTERNAL",
      wipe_and_send: "OUTBOUND_SINK", // 이중 게이트(유출+파괴) 검증용
      http_post: "OUTBOUND_SINK",
    },
    judgmentMode: "lineage",
    hitlPolicy: "weak-only",
    destructivePolicy: "hitl",
    destructiveTools: ["delete_records", "wipe_and_send"],
    toolLabels: {
      fetch_web_page: "웹 페이지 가져오기",
      delete_records: "기록 삭제",
    },
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
  getOverrideAuditLog,
  recordToolResult,
  requestApproval,
  resolveApproval,
} = await import("./index.js");

function ctx(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName, args, argTags, timestamp: new Date().toISOString() };
}

/** 대시보드 승인 흐름 축약: OFFERED → PENDING → APPROVED */
function approve(sessionId: string, approvalId: string): void {
  requestApproval(sessionId, approvalId);
  resolveApproval(approvalId, true, "destructive-tester");
}

/** 사람 말 필드 금지 기술 용어 (explain.test.ts와 동일 규칙 — detail은 기계용 예외) */
const BANNED = /SENSITIVE|UNTRUSTED|OUTBOUND|TOKENIZATION|STRUCTURED_EXTRACTION|trifecta|lethal|tn_/;

function humanTexts(ex: UserFacingExplanation): string[] {
  return [ex.summary, ex.reason, ...ex.risks, ...ex.actions.flatMap((a) => [a.label, a.description])];
}

// ---------------------------------------------------------------------------

test("사용자 직접 지시 삭제: 깨끗한 세션에서 2연속 통과 (자기-오염 회귀)", () => {
  const sid = "d1-direct";

  // 1차 삭제 — 통과
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", { table: "old_logs" })).allowed, true);

  // 프록시처럼 결과를 기록한다. destructiveTools 등록만으로 "분류된 도구"이므로
  // 결과에 UNTRUSTED_ORIGIN이 자동 부착되면 안 된다 — 부착되면 2차가 차단된다
  // (isClassifiedTool에 destructiveTools 미포함이던 설계 초안의 자기-오염 함정).
  const node = recordToolResult(sid, "delete_records", { table: "old_logs" }, "3 rows deleted");
  assert.equal(node.tags.size, 0, "파괴 도구 결과는 깨끗해야 함 (자기-오염 금지)");

  // 2차 삭제 — 여전히 통과 (비개발자 시나리오 직격 회귀)
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", { table: "old_logs" })).allowed, true);
});

test("비신뢰 노출 후 삭제: 차단 + 항상 승인 제안 (hitl)", () => {
  const sid = "d2-injected";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const decision = evaluateToolCall(ctx(sid, "delete_records", { table: "users" }));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("파괴적 액션 차단"));
  assert.deepEqual(decision.matchedTags, [ToolRiskTag.UNTRUSTED_ORIGIN]);
  assert.equal(decision.canOverride, true); // hitl: 항상 오버라이드 가능 (weak-only 규칙 미적용)
  assert.ok(decision.approvalId);
});

test("★F1 알려진 미탐(파트2 대상): 정화로 U 세탁 시 파괴가 통과 — 현재 동작 기록", () => {
  // ⚠ 이 통과는 "정답"이 아니라 헌팅 F1에서 확정된 미탐이다. 파괴 게이트의 U축은
  // 세션-존재(sessionHasLiveTag)라, STRUCTURED_EXTRACTION이 U 노드를 declassify하면
  // 세션 U축이 꺼져 정화와 무관한 삭제까지 통과한다. 파트1(explain SANITIZE 제거)은
  // "엔진이 이 경로를 해결책으로 권하지 않는 것"까지만 고치고 판정은 불변으로 뒀다.
  // 근본 수정(정화 불변 판정 or 노출 이력)은 유출축 C1과 함께 파트2에서 결정한다.
  // 이 테스트는 그 미탐의 회귀 앵커다 — 파트2 수정이 들어가면 여기가 깨져
  // "false로 업데이트하라"는 신호가 된다.
  const sid = "d3-sanitize";
  recordToolResult(sid, "fetch_web_page", undefined, { type: "bug", title: "safe title" });
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, false);

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.ok(!result.resultTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN), "정화로 U가 해제됨");
  assert.equal(
    evaluateToolCall(ctx(sid, "delete_records", {})).allowed,
    true,
    "현재 동작(미탐): 정화로 세션 U가 꺼져 파괴가 통과 — 파트2에서 차단으로 전환 예정"
  );

  // 실패 경로: 스키마 밖 페이로드 → 정화 실패(fail-safe) → 계속 차단 (이건 정상)
  const sid2 = "d3-sanitize-fail";
  recordToolResult(sid2, "fetch_web_page", undefined, "스키마에 안 맞는 자유 텍스트");
  const failed = attemptSanitization(sid2, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.ok(failed.resultTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN), "실패 시 태그 유지");
  assert.equal(evaluateToolCall(ctx(sid2, "delete_records", {})).allowed, false);
});

test("HITL: 승인 → 재시도 1회 통과 → 재재시도는 다시 차단 + 새 제안 (single-use)", () => {
  const sid = "d4-hitl";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const blocked = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(blocked.allowed, false);
  const id1 = blocked.approvalId!;
  approve(sid, id1);

  const passed = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(passed.allowed, true);
  assert.ok(passed.reason?.includes("파괴 게이트: HITL 승인으로 1회 통과"));
  assert.ok(passed.reason?.includes(id1));

  // 승인은 1회용 — 같은 호출을 다시 하면 차단 + "새" 제안이 발급된다
  const reblocked = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(reblocked.allowed, false);
  assert.ok(reblocked.approvalId);
  assert.notEqual(reblocked.approvalId, id1);
});

test("TOCTOU: 승인 후 새 비신뢰 유입 → 낡은 승인 영구 무효(OVERRIDE_STALE) + 재차단", () => {
  const sid = "d5-toctou";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서 1");

  const blocked = evaluateToolCall(ctx(sid, "delete_records", {}));
  const id1 = blocked.approvalId!;
  approve(sid, id1);

  // 승인~소비 사이에 U-그림이 변한다 — 새 비신뢰 read (모델의 ReadUntrusted 전이)
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서 2");

  const retried = evaluateToolCall(ctx(sid, "delete_records", {}));
  assert.equal(retried.allowed, false, "낡은 U-그림의 승인으로는 통과 불가");
  assert.ok(retried.approvalId);
  assert.notEqual(retried.approvalId, id1, "새 그림의 새 제안이 발급돼야 함");

  const stale = getOverrideAuditLog(sid).filter(
    (e) => e.approvalId === id1 && e.action === "OVERRIDE_STALE"
  );
  assert.equal(stale.length, 1, "낡은 승인은 OVERRIDE_STALE로 감사 기록");
});

test("이중 게이트(유출+파괴): 교차 SUPERSEDED·소각 없음, 두 승인 보유 시 재시도 1회 통과", () => {
  const sid = "d6-dual";
  recordToolResult(sid, "read_secrets", undefined, "키"); // S (짧은 값 — VALUE_MATCH 배제)
  recordToolResult(sid, "fetch_web_page", undefined, "문서"); // U → 폴백 = weak 트라이펙타

  // 1차: 파괴 게이트가 먼저 차단 (peek: 파괴 승인 없음 → 유출 판정 생략 = 유출 승인 보존 구조)
  const b1 = evaluateToolCall(ctx(sid, "wipe_and_send", {}));
  assert.equal(b1.allowed, false);
  assert.ok(b1.reason?.includes("파괴적 액션 차단"));
  const dId = b1.approvalId!;
  approve(sid, dId);

  // 2차: 파괴 승인 있음 → 유출 판정 실행 → 트라이펙타 차단 + 유출 제안 발급.
  //      파괴 승인은 소비되지 않고 보존돼야 한다 (승인 소각 방지 프로토콜).
  const b2 = evaluateToolCall(ctx(sid, "wipe_and_send", {}));
  assert.equal(b2.allowed, false);
  assert.ok(b2.reason?.includes("lethal trifecta"), "2차 차단은 유출 게이트여야 함");
  const eId = b2.approvalId!;
  assert.notEqual(eId, dId, "유출·파괴 제안은 서로 다른 offer (서로소 공간)");
  const dAudit = getOverrideAuditLog(sid).filter((e) => e.approvalId === dId);
  assert.ok(
    !dAudit.some((e) => e.action === "OVERRIDE_USED" || e.action === "OVERRIDE_STALE" || e.action === "SUPERSEDED"),
    "유출 게이트 활동이 파괴 승인을 소비·소각·봉인하면 안 됨 (GateIsolation)"
  );
  approve(sid, eId);

  // 3차: 유출 승인 소비 → 통과 → 파괴 승인 실소비 → 최종 통과 (재시도 1회)
  const passed = evaluateToolCall(ctx(sid, "wipe_and_send", {}));
  assert.equal(passed.allowed, true);
  assert.ok(passed.reason?.includes("HITL 오버라이드 승인으로 1회 통과"), "유출 소비 기록");
  assert.ok(passed.reason?.includes("파괴 게이트: HITL 승인으로 1회 통과"), "파괴 소비 기록");
  const used = getOverrideAuditLog(sid).filter((e) => e.action === "OVERRIDE_USED");
  assert.deepEqual(new Set(used.map((e) => e.approvalId)), new Set([dId, eId]));
  assert.ok(
    !getOverrideAuditLog(sid).some((e) => e.action === "OVERRIDE_STALE"),
    "전 과정에서 교차 소각 0건"
  );
});

test("파괴-단독 차단은 TrifectaEvent를 발행하지 않는다", () => {
  const sid = "d7-no-trifecta-event";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U만 (S 없음)

  const logs: string[] = [];
  const orig = console.log;
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  let decision;
  try {
    decision = evaluateToolCall(ctx(sid, "delete_records", {}));
  } finally {
    console.log = orig;
  }
  assert.equal(decision.allowed, false);
  assert.ok(
    !logs.some((l) => l.includes("TrifectaEvent")),
    "matchedTags=[U]인 파괴 차단이 트라이펙타 이벤트로 오발행되면 안 됨"
  );
});

test("파괴 차단 explanation: 사람 말 규칙 + 라벨 노출 + 액션 구성", () => {
  const sid = "d8-explain";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");

  const decision = evaluateToolCall(ctx(sid, "delete_records", {}));
  const ex = decision.explanation!;
  assert.ok(ex);
  assert.ok(ex.summary.includes("잠시 멈췄어요"));
  for (const text of humanTexts(ex)) {
    assert.doesNotMatch(text, BANNED, `기술 용어 누출: "${text}"`);
  }
  assert.ok(ex.reason.includes("웹 페이지 가져오기"), "출처는 노드 id가 아니라 도구 라벨로");
  assert.doesNotMatch(ex.reason, /tn_/);

  const approval = ex.actions.find((a) => a.kind === "REQUEST_APPROVAL")!;
  assert.equal(approval.available, true);
  assert.equal(approval.detail, decision.approvalId);

  // ★F1 파트1 회귀 앵커: 파괴 차단 설명은 SANITIZE(정화)를 해제 경로로 제시하지
  // 않는다. 정화는 "나가는 값 안전화"라 파괴엔 논리적으로 무의미하고, safe-text가
  // 자연어 삭제 명령을 통과시켜 U축을 세탁하므로(헌팅 F1/P6) 엔진이 이를 "해결책"
  // 으로 권하면 사람을 오도해 게이트를 뚫는다. 정당한 해제 경로는 HITL 승인뿐.
  assert.equal(
    ex.actions.find((a) => a.kind === "SANITIZE"),
    undefined,
    "파괴 차단 설명에 SANITIZE 액션이 있으면 안 됨 (F1: 정화는 파괴 해결책 아님)"
  );
  // 남는 액션은 REQUEST_APPROVAL + INSPECT_SOURCE 둘뿐
  assert.deepEqual(
    ex.actions.map((a) => a.kind).sort(),
    ["INSPECT_SOURCE", "REQUEST_APPROVAL"]
  );
});

test("argTags에 실려온 비신뢰: 세션 계보 없이도 파괴 게이트 발동", () => {
  const sid = "d9-argtags"; // 완전히 깨끗한 세션
  const decision = evaluateToolCall(
    ctx(sid, "delete_records", {}, [ToolRiskTag.UNTRUSTED_ORIGIN])
  );
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("인자 태그 근거"));
});
