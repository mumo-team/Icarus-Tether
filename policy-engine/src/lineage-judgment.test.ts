/**
 * judgmentMode: "lineage" — real(계보)이 실제 차단을 결정하는 모드 테스트.
 * (별도 프로세스이므로 임시 설정 파일 + TAINTGUARD_TOOL_REGISTRY로 로드)
 *
 * 핵심: 세션 전체가 아니라 "지금 나가려는 값의 계보"만 본다.
 *  - 정화된 노드는 태그가 없어 자동 제외
 *  - 나가는 값과 무관한 다른 갈래의 오염은 판정에 영향 없음
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-judgment-"));
const configFile = path.join(dir, "lineage-mode.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "lineage-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    // read_secrets는 read-only 소스 — 싱크 축 default-deny(fail-open #2 수정)로
    // OUTBOUND 강등되지 않도록 READ로 명시 (그래야 :127의 read_secrets 평가가 통과 유지)
    sinks: { read_secrets: "READ" },
    judgmentMode: "lineage",
    piiPatterns: [
      { type: "EMAIL", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" },
    ],
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, attemptSanitization, evaluateToolCall, pruneSessionLineage, getSessionLineage } =
  await import("./index.js");

function ctx(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName, args, argTags, timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// ★ 값 단위 판정 — real 전환의 목적
// ---------------------------------------------------------------------------

test("★값 단위: 정화된 A의 값은 통과, 오염 잔존 B의 값은 차단 — 같은 세션에서", () => {
  const sid = "j1-value-level";
  const a = recordToolResult(sid, "read_secrets", undefined, { contact: "a@b.co" }); // 🔴
  const b = recordToolResult(sid, "fetch_web_page", { _taintRef: a.id }, "외부 문서"); // 🔵+🔴상속

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // A 정화 (B는 각자 정화 필요)

  // 세션 boolean을 다시 오염시켜 둔다 — toy라면 아래 두 호출 모두 차단했을 상태
  recordToolResult(sid, "read_secrets", undefined, { other: "x@y.io" });

  // A의 값을 내보내는 호출: A의 계보는 깨끗 → 세션에 오염이 있어도 통과 ★
  const allowA = evaluateToolCall(ctx(sid, "http_post", { _taintRef: a.id, body: "전송" }));
  assert.equal(allowA.allowed, true);

  // B의 값을 내보내는 호출: B에 상속 오염({🔵,🔴})이 살아있음 → 차단 ★
  const blockB = evaluateToolCall(ctx(sid, "http_post", { _taintRef: b.id, body: "전송" }));
  assert.equal(blockB.allowed, false);
  assert.ok(blockB.reason?.includes("lethal trifecta"));
});

test("★d4 시나리오: 정화된 부모 + 상속 오염 자식이 폴백에 잡히면 real은 차단이 맞다", () => {
  // dev-domain d4에서 toy는 통과시키던 상황 — 자식의 상속 오염이 남아 있으므로
  // real(값 단위 + 비대칭 정화)에서는 차단이 올바른 판정이다.
  const sid = "j2-d4-scenario";
  const a = recordToolResult(sid, "read_secrets", undefined, { key: "k@v.co" }); // 🔴
  const b = recordToolResult(sid, "fetch_web_page", undefined, "코멘트"); // 폴백→a, {🔵,🔴}
  assert.ok(b.tags.has(ToolRiskTag.SENSITIVE));

  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // a만 정화

  // args 근거가 없어 폴백 → 승계 규칙에 의해 b(살아있는 오염원)에 연결 → 차단
  const decision = evaluateToolCall(ctx(sid, "http_post"));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes(b.id)); // 근거 노드가 reason에 명시된다
});

// ---------------------------------------------------------------------------
// 차단 reason — b안: 근거 노드·태그 + 해제 방법
// ---------------------------------------------------------------------------

test("차단 reason에 오염 노드 id·도구명·태그와 해제 방법 힌트가 담긴다", () => {
  const sid = "j3-reason";
  const a = recordToolResult(sid, "read_secrets", undefined, { contact: "a@b.co" });
  const b = recordToolResult(sid, "fetch_web_page", { _taintRef: a.id }, "문서");

  const decision = evaluateToolCall(ctx(sid, "http_post", { _taintRef: b.id }));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes(b.id)); // 어느 노드가
  assert.ok(decision.reason?.includes("fetch_web_page")); // 어디서 왔고
  assert.ok(decision.reason?.includes(ToolRiskTag.SENSITIVE)); // 왜 오염인지
  assert.ok(decision.reason?.includes(SanitizationMethod.TOKENIZATION)); // 뭘 하면 풀리는지
});

// ---------------------------------------------------------------------------
// fail-safe: real 계산 실패 = 차단 (조용한 통과 금지)
// ---------------------------------------------------------------------------

test("★fail-safe: real 계산 실패(순환 참조 args) 시 차단한다", () => {
  const sid = "j4-failsafe";
  const circular: Record<string, unknown> = {};
  circular.self = circular;

  const decision = evaluateToolCall(ctx(sid, "http_post", circular));
  assert.equal(decision.allowed, false); // 섀도(무개입)와 반대 — 실전 결정자는 실패 시 차단
  assert.ok(decision.reason?.includes("fail-safe"));
  assert.deepEqual(decision.matchedTags, []); // 탐지가 아닌 운영 오류 차단
});

// ---------------------------------------------------------------------------
// 경계 동작
// ---------------------------------------------------------------------------

test("lineage 모드에서도 비-싱크(READ) 도구는 계보와 무관하게 허용", () => {
  const sid = "j5-read";
  const a = recordToolResult(sid, "read_secrets", undefined, { contact: "a@b.co" });
  recordToolResult(sid, "fetch_web_page", { _taintRef: a.id }, "문서"); // 세션 트라이펙타 상태

  assert.equal(evaluateToolCall(ctx(sid, "read_secrets")).allowed, true);
});

test("argTags도 계보 합집합에 합쳐져 판정된다 (프록시가 전파한 인자 태그)", () => {
  const sid = "j6-argtags";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // 계보엔 🔵만

  // 인자에 SENSITIVE가 실려 오면 (계보 🔵 + 인자 🔴) → 트라이펙타 → 차단
  const decision = evaluateToolCall(ctx(sid, "http_post", {}, [ToolRiskTag.SENSITIVE]));
  assert.equal(decision.allowed, false);
  assert.ok(decision.reason?.includes("인자 태그"));
});

test("깨끗한 값: 세션이 깨끗하면 outbound도 허용 (기본 동작 보존)", () => {
  assert.equal(evaluateToolCall(ctx("j7-clean", "http_post")).allowed, true);
});

test("pruningPolicy off(기본): pruneSessionLineage는 no-op — 아무것도 지우지 않는다", () => {
  const sid = "j8-prune-off";
  recordToolResult(sid, "read_secrets", undefined, { contact: "a@b.co" });
  attemptSanitization(sid, SanitizationMethod.TOKENIZATION); // 정화돼 깨끗한 childless 노드

  const sizeBefore = getSessionLineage(sid).size;
  const { pruned } = pruneSessionLineage(sid);
  assert.equal(pruned, 0); // 이 설정 파일엔 pruningPolicy가 없음 → 기본 off
  assert.equal(getSessionLineage(sid).size, sizeBefore);
});
