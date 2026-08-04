/**
 * collectStrings 견고화 회귀 — 순환참조·깊은 중첩·공유참조 DAG.
 *
 * 수정 전(무가드 재귀): 순환참조 → 무한재귀, 깊은 중첩(배열 ~1만·객체 ~5만 depth
 * 실측) → RangeError. recordToolResult/recordExternalContent가 이 경로를 타서
 * 프록시 fail-safe가 "차단"으로 처리 — 정상 깊은 데이터 오탐 + 공격자 유발 DoS.
 *
 * 수정(명시 스택 + WeakSet 방문가드, value-walk.ts)의 핵심 계약:
 *  1. 순환·깊이 무제한에서 안 터진다.
 *  2. ★ 절단이 없다 — 아무리 깊어도 전부 수집. "깊이 상한 밑에 숨기면 통과"
 *     우회가 성립하지 않는다 (미탐 0).
 *  3. 공유참조 DAG의 지수 폭발(작은 페이로드로 2^n 순회 유발)을 방문가드가 막는다.
 *  4. JSON 표현 가능한 입력(순환·공유참조 없음)에선 결과가 기존 재귀와 순서까지 동일.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-valuewalk-"));
const configFile = path.join(dir, "cfg.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "value-walk-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    sinks: { read_secrets: "READ" },
    judgmentMode: "lineage",
    piiPatterns: [
      { type: "EMAIL", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" },
    ],
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { collectStrings, mapValueStrings } = await import("./value-walk.js");
const { detectSecrets } = await import("./secret-detection.js");
const {
  recordToolResult,
  recordExternalContent,
  evaluateToolCall,
  attemptSanitization,
} = await import("./index.js");

function ctx(
  sessionId: string,
  toolName: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName, args, argTags, timestamp: new Date().toISOString() };
}

function deepObj(depth: number, bottom: unknown): unknown {
  let v = bottom;
  for (let i = 0; i < depth; i++) v = { a: v };
  return v;
}

function deepArr(depth: number, bottom: unknown): unknown {
  let v = bottom;
  for (let i = 0; i < depth; i++) v = [v];
  return v;
}

// ---------------------------------------------------------------------------
// collectStrings 단위 — 기존 동작 유지(순서 포함) + 병리 입력 견고성
// ---------------------------------------------------------------------------

test("정상 데이터: 수집 결과·순서가 기존 재귀 구현과 동일하다", () => {
  const value = { a: "1", b: ["2", { c: "3" }], d: "4" };
  assert.deepEqual(collectStrings(value), ["1", "2", "3", "4"]);
});

test("같은 내용의 문자열 중복은 그대로 전부 수집된다 (원시값은 방문가드 대상 아님)", () => {
  assert.deepEqual(collectStrings({ a: "x", b: "x", c: ["x"] }), ["x", "x", "x"]);
});

test("순환참조 객체·배열에서 안 터지고, 문자열은 한 번씩 수집된다", () => {
  const circular: Record<string, unknown> = { name: "hello" };
  circular.self = circular;
  assert.deepEqual(collectStrings(circular), ["hello"]);

  const arr: unknown[] = ["first"];
  arr.push(arr);
  assert.deepEqual(collectStrings(arr), ["first"]);
});

test("★ 절단 없음: 10만 depth 바닥의 문자열도 수집된다 (객체·배열)", () => {
  assert.deepEqual(collectStrings(deepObj(100_000, "바닥값")), ["바닥값"]);
  assert.deepEqual(collectStrings(deepArr(100_000, "바닥값")), ["바닥값"]);
});

test("공유참조 DAG(30단 × 2분기 = 재귀라면 2^30 방문)가 선형으로 끝난다", () => {
  let node: unknown = "leaf";
  for (let i = 0; i < 30; i++) node = { a: node, b: node };
  // 최하단 "leaf"는 원시값이라 가드 대상이 아님 — 최심층 객체의 a·b 양쪽에서 수집(2회).
  // 그 위의 공유 객체들은 방문가드로 1회씩만 순회돼 지수 폭발이 없다.
  assert.deepEqual(collectStrings(node), ["leaf", "leaf"]);
});

// ---------------------------------------------------------------------------
// mapValueStrings 단위 (tokenizePII의 순회) — 구조 보존 + 병리 입력 견고성
// ---------------------------------------------------------------------------

test("mapValueStrings: 문자열만 치환되고 구조·원시값이 보존된다", () => {
  const { value, strings } = mapValueStrings(
    { a: "x", n: 1, b: [true, "y", null] },
    (s) => s.toUpperCase()
  );
  assert.deepEqual(value, { a: "X", n: 1, b: [true, "Y", null] });
  assert.deepEqual(strings, ["X", "Y"]);
});

test("mapValueStrings: 순환 입력 → 순환 모양이 보존된 출력, 무한루프 없음", () => {
  const circular: Record<string, unknown> = { name: "hello" };
  circular.self = circular;
  const { value } = mapValueStrings(circular, (s) => s.toUpperCase());
  const out = value as Record<string, unknown>;
  assert.equal(out.name, "HELLO");
  assert.equal(out.self, out); // 순환 유지
});

test("mapValueStrings: 10만 depth에서도 안 터진다", () => {
  const { strings } = mapValueStrings(deepObj(100_000, "바닥값"), (s) => s);
  assert.deepEqual(strings, ["바닥값"]);
});

// ---------------------------------------------------------------------------
// detectSecrets — 동형 재귀였던 별도 사본도 같은 가드를 탄다
// ---------------------------------------------------------------------------

test("detectSecrets: 순환·깊은 중첩에서 안 터지고 바닥의 비밀을 찾는다", () => {
  const det = {
    bySource: true,
    byEntropy: null,
    byRegex: [{ type: "AWS_KEY", pattern: "AKIA[0-9A-Z]{16}" }],
  };
  const circular: Record<string, unknown> = { key: "AKIAABCDEFGHIJKLMNOP" };
  circular.self = circular;
  assert.equal(detectSecrets(circular, det).length, 1);
  assert.equal(detectSecrets(deepObj(100_000, "AKIAABCDEFGHIJKLMNOP"), det).length, 1);
});

// ---------------------------------------------------------------------------
// 통합 — 기록·판정·정화 경로가 병리 입력에서 터지지 않고 의미도 안전하다
// ---------------------------------------------------------------------------

test("recordToolResult/recordExternalContent: 순환·10만 depth 입력에서 안 터진다", () => {
  const circular: Record<string, unknown> = { name: "hello" };
  circular.self = circular;
  assert.doesNotThrow(() => recordToolResult("vw-rec1", "fetch_web_page", undefined, circular));
  assert.doesNotThrow(() => recordToolResult("vw-rec2", "fetch_web_page", circular, "결과"));
  assert.doesNotThrow(() =>
    recordToolResult("vw-rec3", "fetch_web_page", undefined, deepObj(100_000, "바닥값"))
  );
  assert.doesNotThrow(() =>
    recordExternalContent("vw-rec4", "resources/read", "file:///x", circular)
  );
});

test("★ 오탐 해소: 깊기만 한 정상 인자(1만 depth)는 fail-safe 차단 대신 정상 통과한다", () => {
  const sid = "vw-deep-clean";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U 노출만
  const decision = evaluateToolCall(
    ctx(sid, "http_post", { body: deepObj(10_000, "무해한 값") } as Record<string, unknown>)
  );
  assert.equal(decision.allowed, true); // 민감 없음 — 수정 전엔 RangeError → fail-safe 차단(오탐)
});

test("★ 우회 없음: 5만 depth 바닥에 숨긴 민감 원본도 출력스캔이 잡아 차단한다", () => {
  const sid = "vw-deep-exfil";
  recordToolResult(sid, "read_secrets", undefined, { secret: "TOPSECRET-ORIGINAL-0123456789" });
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U 노출
  const decision = evaluateToolCall(
    ctx(sid, "http_post", {
      body: deepObj(50_000, "TOPSECRET-ORIGINAL-0123456789"),
    } as Record<string, unknown>)
  );
  assert.equal(decision.allowed, false); // 절단이 있었다면 바닥을 못 보고 통과했을 케이스
});

test("attemptSanitization: 순환 페이로드에서 안 터지고, 태그는 유지된다 (fail-safe)", () => {
  const sid = "vw-circ-sanitize";
  const circular: Record<string, unknown> = { contact: "a@b.co" };
  circular.self = circular;
  recordToolResult(sid, "read_secrets", undefined, circular); // SENSITIVE 페이로드 기록

  let result: ReturnType<typeof attemptSanitization> | undefined;
  assert.doesNotThrow(() => {
    result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  });
  // 순환 페이로드는 "실제 변경" 게이트(JSON 직렬화)를 검증할 수 없으므로
  // 태그 해제가 일어나면 안 된다 — 오류로 태그가 벗겨지는 경로 금지.
  assert.ok(result!.resultTags.includes(ToolRiskTag.SENSITIVE));
});
