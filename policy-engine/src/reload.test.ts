/**
 * reloadPolicyConfig — 정책 핫리로드 (④).
 *
 * 계약:
 *  1. 재로드 후 다음 getPolicyConfig가 새 설정을 반환하고, 판정 동작도 바뀐다.
 *  2. ★ 검증-후-교체(fail-closed): 잘못된 설정 재로드는 throw하되 캐시는 그대로 —
 *     기존 정책 유지, 프로세스·세션 안 죽음. 로드 검증(trustedResourceUris 경계
 *     규칙 등)이 재로드 경로에도 똑같이 적용된다.
 *  3. 세션 상태(오염 그래프·노출이력)는 config와 별개 저장소 — 재로드로 안 날아간다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-reload-"));
const configFile = path.join(dir, "cfg.json");

function baseConfig(extra: Record<string, unknown>): Record<string, unknown> {
  return {
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    sinks: { read_secrets: "READ" },
    judgmentMode: "lineage",
    ...extra,
  };
}

writeFileSync(configFile, JSON.stringify(baseConfig({ domain: "reload-v1" })));
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const {
  getPolicyConfig,
  reloadPolicyConfig,
  isResourceUriTrusted,
  recordToolResult,
  evaluateToolCall,
  getSessionLineage,
  isSessionExposed,
} = await import("./index.js");

function ctx(sessionId: string, toolName: string, args: Record<string, unknown> = {}): ToolCallContext {
  return { sessionId, toolName, args, argTags: [], timestamp: new Date().toISOString() };
}

// 세션 상태를 미리 심는다 — 재로드를 넘나들며 보존을 검증할 공유 픽스처.
const SID = "reload-session";
const SECRET = "TOPSECRET-RELOAD-0123456789";
recordToolResult(SID, "read_secrets", undefined, { secret: SECRET });
recordToolResult(SID, "fetch_web_page", undefined, "외부 문서"); // U 노출

test("재로드 전 기준선: v1 도메인, file:// 비신뢰(목록 없음), 트라이펙타 차단", () => {
  assert.equal(getPolicyConfig().domain, "reload-v1");
  assert.equal(isResourceUriTrusted("file:///x"), false);
  assert.equal(evaluateToolCall(ctx(SID, "http_post", { body: SECRET })).allowed, false);
});

test("reloadPolicyConfig 후 다음 getPolicyConfig가 새 설정을 반환하고 판정 동작이 바뀐다", () => {
  writeFileSync(
    configFile,
    JSON.stringify(baseConfig({ domain: "reload-v2", trustedResourceUris: ["file:///"] }))
  );
  const next = reloadPolicyConfig();
  assert.equal(next.domain, "reload-v2");
  assert.equal(getPolicyConfig().domain, "reload-v2");
  assert.equal(getPolicyConfig(), next, "캐시가 재로드 결과로 교체돼야 함");
  // 동작 변화: v2가 file:///를 신뢰 목록에 넣었으므로 판정이 바뀐다
  assert.equal(isResourceUriTrusted("file:///x"), true);
});

test("세션 상태 보존: 재로드를 거쳐도 오염 그래프·노출이력·차단이 유지된다", () => {
  assert.ok(getSessionLineage(SID).size >= 2, "재로드 전에 만든 계보 노드가 남아 있어야 함");
  assert.equal(isSessionExposed(SID), true, "노출이력 유지");
  assert.equal(
    evaluateToolCall(ctx(SID, "http_post", { body: SECRET })).allowed,
    false,
    "재로드 후에도 기존 세션의 트라이펙타 차단 유지"
  );
});

test("★ fail-closed: 잘못된 설정 재로드는 throw하되 기존 config 유지 (검증이 재로드에도 적용)", () => {
  // C-7 경계 규칙 위반 — 로드 검증이 재로드 경로에도 도는지 그대로 확인된다
  writeFileSync(
    configFile,
    JSON.stringify(baseConfig({ domain: "reload-bad", trustedResourceUris: ["https://corp"] }))
  );
  assert.throws(() => reloadPolicyConfig(), /"\/"로 끝나야/);
  // 캐시는 안 건드렸다 — v2 정책 그대로
  assert.equal(getPolicyConfig().domain, "reload-v2");
  assert.equal(isResourceUriTrusted("file:///x"), true);

  // 형식 자체가 깨진 설정(필수 키 누락)도 동일
  writeFileSync(configFile, JSON.stringify({ domain: "reload-broken" }));
  assert.throws(() => reloadPolicyConfig());
  assert.equal(getPolicyConfig().domain, "reload-v2");

  // 파일이 JSON이 아니어도 동일
  writeFileSync(configFile, "not-json{{{");
  assert.throws(() => reloadPolicyConfig());
  assert.equal(getPolicyConfig().domain, "reload-v2");

  // 실패들 이후에도 판정·세션 정상 (프로세스가 무정책 상태가 되지 않음)
  assert.equal(evaluateToolCall(ctx(SID, "http_post", { body: SECRET })).allowed, false);
});

test("복구: 파일을 고쳐 다시 재로드하면 정상 적용된다", () => {
  writeFileSync(configFile, JSON.stringify(baseConfig({ domain: "reload-v3" })));
  assert.equal(reloadPolicyConfig().domain, "reload-v3");
  assert.equal(getPolicyConfig().domain, "reload-v3");
});

test("명시 경로 재로드: filePath 인자로 다른 파일을 지정할 수 있다", () => {
  const other = path.join(dir, "other.json");
  writeFileSync(other, JSON.stringify(baseConfig({ domain: "reload-other" })));
  assert.equal(reloadPolicyConfig(other).domain, "reload-other");
  assert.equal(getPolicyConfig().domain, "reload-other");
});
