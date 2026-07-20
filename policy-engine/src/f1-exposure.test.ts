/**
 * ★ F1 회귀 — 비신뢰 노출이력(untrustedExposure) 세탁 방지.
 *
 * 헌팅에서 발견한 F1: U축이 값-계보가 아니라 세션-존재로 판정되는데, 정화
 * (STRUCTURED_EXTRACTION)가 U 노드 태그를 떼면 세션 U축이 통째로 꺼져 정화와
 * 무관한 유출(C1)·삭제(P6)가 열렸다. 근본 수정: U축을 노출이력(grow-only, 정화
 * 불변)으로 판정. valueSensitive AND exposure를 유지하므로 과차단(RE35/RE36)은
 * 없다. 의미론 선행 확정본: formal/TaintLineage.tla(ExfilSafety·ExposureMonotone),
 * formal/TaintDestructiveHITL.tla(DestructiveSafety·ExposureMonotone) — TLC 위반 0.
 *
 * lineage 모드 자체 픽스처(설정 캐시가 프로세스당 1회라 별도 파일).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { SanitizationMethod, ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-f1-"));
const configFile = path.join(dir, "f1.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "f1-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    sinks: { read_secrets: "READ", fetch_web_page: "READ" },
    judgmentMode: "lineage",
    // 토큰화 성공 경로(RE35)용: AWS 키 정규식으로 실제 치환이 일어나게
    secretDetection: {
      bySource: true,
      byRegex: [{ type: "AWS_KEY", pattern: "\\bAKIA[0-9A-Z]{16}\\b" }],
    },
    extractionSchema: {
      fields: {
        type: { kind: "enum", values: ["bug", "ticket"] },
        title: { kind: "string", maxLength: 80, charset: "safe-text" },
      },
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { attemptSanitization, evaluateToolCall, isSessionExposed, recordToolResult } = await import(
  "./index.js"
);

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

function ctx(sessionId: string, args: Record<string, unknown> = {}): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------

test("★C1 차단: 비신뢰 정화 후 무관한 민감값 전송은 여전히 차단 (세탁 방지)", () => {
  const sid = "f1-c1";
  // 세션이 비신뢰(웹)에 노출 + 민감(시크릿) 읽음
  recordToolResult(sid, "fetch_web_page", undefined, { type: "ticket", title: "환불 문의" });
  const sec = recordToolResult(sid, "read_secrets", undefined, `KEY=${AWS_KEY}`);

  // 정화 전: 시크릿 값 전송 차단
  assert.equal(evaluateToolCall(ctx(sid, { body: `보고 ${AWS_KEY}`, _taintRef: [sec.id] })).allowed, false);

  // 공격자: 비신뢰 노드를 구조화 추출로 정화해 세션 U축을 세탁 시도
  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.ok(!result.resultTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN), "U 노드 태그는 해제됨");
  assert.ok(isSessionExposed(sid), "노출이력은 정화 불변으로 유지돼야 함");

  // ★ F1: 정화 후에도 같은 시크릿 전송은 차단 (exposure가 살아 U축 유지)
  assert.equal(
    evaluateToolCall(ctx(sid, { body: `보고 ${AWS_KEY}`, _taintRef: [sec.id] })).allowed,
    false,
    "정화가 무관한 민감 유출을 세탁하지 못함"
  );
});

test("RE35 유지(과차단 아님): 민감을 토큰화하면 전송 통과 (S축 정상 재개방)", () => {
  const sid = "f1-re35";
  // 민감만 (비신뢰 노출 없음)
  recordToolResult(sid, "read_secrets", undefined, `KEY=${AWS_KEY}`);
  assert.equal(isSessionExposed(sid), false, "비신뢰 노출 없음");

  // 토큰화로 S 해제 → 무해한 상태 전송 통과
  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.ok(!result.resultTags.includes(ToolRiskTag.SENSITIVE), "토큰화로 S 해제");
  assert.equal(
    evaluateToolCall(ctx(sid, { body: "설정 점검 완료 - 키는 볼트 토큰화됨" })).allowed,
    true,
    "노출 없는 세션의 S 정화 후 전송은 통과"
  );
});

test("RE36 유지(과차단 아님): 비신뢰 정화 후 민감 없는 값 전송은 통과", () => {
  const sid = "f1-re36";
  // 비신뢰만 (민감 없음) — 노출이력은 켜지지만 valueSensitive가 없어 통과
  recordToolResult(sid, "fetch_web_page", undefined, { type: "bug", title: "login broken" });
  assert.ok(isSessionExposed(sid), "비신뢰 노출됨");

  attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.equal(
    evaluateToolCall(ctx(sid, { body: "확인된 버그: 로그인" })).allowed,
    true,
    "노출이력이 있어도 민감(S)이 없으면 유출 아님 — 과차단 아님"
  );
});

test("노출이력 단조성: 정화·통과 어떤 순서로도 exposure는 꺼지지 않는다", () => {
  const sid = "f1-monotone";
  assert.equal(isSessionExposed(sid), false);
  recordToolResult(sid, "fetch_web_page", undefined, { type: "bug", title: "t" });
  assert.equal(isSessionExposed(sid), true);
  attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.equal(isSessionExposed(sid), true, "정화 후에도 유지 (ExposureMonotone)");
  evaluateToolCall(ctx(sid, { body: "x" }));
  assert.equal(isSessionExposed(sid), true, "판정 후에도 유지");
});
