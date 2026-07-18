/**
 * TIER3 출력-스캔 회귀 테스트 — 미탐 #1 벡터 A(세탁 민감 유출) 차단 + 과차단 0.
 *
 * ★ 핵심 과차단 가드: 고엔트로피 정상값(git SHA·UUID·JWT·integrity 해시)은 미발동.
 *   엔트로피를 의도적으로 안 쓰기 때문 — 벤치가 토큰 <20자로 숨기던 과차단을
 *   여기서 실측·고정한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { SecretDetectionConfig } from "./config.js";
import { scanOutputForSensitive, type SensitivePayload } from "./output-scan.js";

const DET: SecretDetectionConfig = {
  bySource: true,
  // ★ byEntropy를 일부러 켜 둔다 — 그래도 출력-스캔이 엔트로피를 안 써야 SHA/UUID가 통과.
  byEntropy: { minLength: 20, entropyThreshold: 3.8 },
  byRegex: [
    { type: "AWS_KEY", pattern: "\\bAKIA[0-9A-Z]{16}\\b" },
    { type: "GITHUB_TOKEN", pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b" },
  ],
};

const SECRET_PAYLOADS: SensitivePayload[] = [
  { toolName: "read_secrets", payload: { secret: "MYSECRETPASSWORDVALUE" } }, // 21자
];

// ── 포함검사 ──────────────────────────────────────────────────────────────
test("containment: 민감 원본이 출력에 통째로 포함되면 탐지", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { body: "leak MYSECRETPASSWORDVALUE now" }, DET);
  assert.equal(f?.kind, "containment");
  assert.equal(f?.sourceTool, "read_secrets");
});

test("containment: <8자 청크로 세탁해도 concat 재조립으로 탐지 (attack1)", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { parts: ["MYSECRE", "TPASSW", "ORDVAL", "UE"] }, DET);
  assert.equal(f?.kind, "containment");
});

test("containment: 무관한 정상 출력은 미발동", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { body: "build succeeded in 42s" }, DET);
  assert.equal(f, null);
});

test("min-length: 짧은 민감값(<12)은 우연일치 방지로 제외 → 과차단 없음", () => {
  const shortPayloads: SensitivePayload[] = [{ toolName: "query_customer_db", payload: { grade: "VIP" } }];
  const f = scanOutputForSensitive(shortPayloads, { body: "VIP lounge access granted" }, DET);
  assert.equal(f, null);
});

// ── 정규식(엔트로피 제외) ───────────────────────────────────────────────────
test("regex: verbatim AWS 키 탐지", () => {
  const f = scanOutputForSensitive([], { body: "key=AKIAIOSFODNN7EXAMPLE done" }, DET);
  assert.equal(f?.kind, "regex");
});

test("regex: verbatim GitHub 토큰 탐지", () => {
  const f = scanOutputForSensitive([], { token: "ghp_" + "A".repeat(36) }, DET);
  assert.equal(f?.kind, "regex");
});

// ── ★ 과차단 가드: 고엔트로피 정상값 미발동 (엔트로피 미사용 증명) ──────────────
test("★ git SHA(40hex) 정상값 — byEntropy가 켜져 있어도 미발동", () => {
  const f = scanOutputForSensitive([], { body: "deploy 9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" }, DET);
  assert.equal(f, null);
});

test("★ UUID v4 정상값 — 미발동", () => {
  const f = scanOutputForSensitive([], { traceId: "550e8400-e29b-41d4-a716-446655440000" }, DET);
  assert.equal(f, null);
});

test("★ JWT 정상값 — 미발동", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
  const f = scanOutputForSensitive([], { authorization: `Bearer ${jwt}` }, DET);
  assert.equal(f, null);
});

test("★ npm integrity(sha512-) 정상값 — 미발동", () => {
  const integ = "sha512-oPX8q3aB9cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6";
  const f = scanOutputForSensitive([], { integrity: integ }, DET);
  assert.equal(f, null);
});

// ── 통합: evaluateToolCall 판정 경로 (lineage 모드) ──────────────────────────
const dir = mkdtempSync(path.join(tmpdir(), "taintguard-tier3-"));
const configFile = path.join(dir, "tier3.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "tier3-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    secretDetection: { bySource: true, byEntropy: { minLength: 20, entropyThreshold: 3.8 }, byRegex: [] },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;
const { recordToolResult, evaluateToolCall } = await import("./index.js");

function ctx(sessionId: string, toolName: string, args: Record<string, unknown>) {
  return { sessionId, toolName, args, argTags: [], timestamp: new Date().toISOString() };
}

test("통합: attack1 청크 세탁 → 차단 + outputScan 이벤트 첨부", () => {
  const sid = "t3-attack1";
  recordToolResult(sid, "fetch_web_page", undefined, { body: "ref TRACKINGCODEAAAAAAAA" });
  recordToolResult(sid, "read_secrets", undefined, { secret: "MYSECRETPASSWORDVALUE" });
  const dec = evaluateToolCall(ctx(sid, "http_post", { parts: ["MYSECRE", "TPASSW", "ORDVAL", "UE"] }));
  assert.equal(dec.allowed, false);
  assert.equal(dec.outputScan?.kind, "containment");
  assert.equal(dec.outputScan?.sourceTool, "read_secrets");
});

test("통합: floor 억제(U 매칭) + SHA 실은 정상 전송 → 통과 (TIER3 과차단 0)", () => {
  const sid = "t3-normal";
  recordToolResult(sid, "fetch_web_page", undefined, { body: "see webdoc_A83jd9x" }); // U
  recordToolResult(sid, "read_secrets", undefined, { secret: "MYSECRETPASSWORDVALUE" }); // S 별도 갈래
  const dec = evaluateToolCall(
    ctx(sid, "http_post", { body: "문서 webdoc_A83jd9x 요약, 커밋 9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" })
  );
  assert.equal(dec.allowed, true);
  assert.equal(dec.outputScan, undefined);
});
