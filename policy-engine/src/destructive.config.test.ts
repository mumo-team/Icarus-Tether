/**
 * 파괴적 액션 게이트 — off 기본값(기존 동작 불변) + 설정 검증 fail-closed.
 *
 * 활성 설정(캐시)은 destructivePolicy를 "생략"한 픽스처 — destructiveTools가
 * 있어도 정책이 off(기본)면 게이트가 완전히 비활성이어야 한다: 기존 사용자
 * 설정 파일(tool-registry.json 등)에 아무 키도 안 넣은 상태의 동작 보증.
 * 설정 검증은 loadPolicyConfig 직접 호출(캐시 무관)로 확인한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-destructive-config-"));

function writeConfig(name: string, extra: Record<string, unknown>): string {
  const file = path.join(dir, name);
  writeFileSync(
    file,
    JSON.stringify({
      domain: "destructive-config-test",
      sensitiveSourceTools: ["read_secrets"],
      untrustedSourceTools: ["fetch_web_page"],
      sinks: {
        read_secrets: "READ",
        fetch_web_page: "READ",
        delete_records: "WRITE_INTERNAL",
        http_post: "OUTBOUND_SINK",
      },
      judgmentMode: "lineage",
      ...extra,
    })
  );
  return file;
}

// 활성 설정: destructiveTools만 있고 destructivePolicy는 "생략" → 기본 off
process.env.TAINTGUARD_TOOL_REGISTRY = writeConfig("off-default.json", {
  destructiveTools: ["delete_records"],
});

const { evaluateToolCall, loadPolicyConfig, recordToolResult } = await import("./index.js");

function ctx(sessionId: string, toolName: string, args: Record<string, unknown> = {}): ToolCallContext {
  return { sessionId, toolName, args, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------

test("off 기본값: destructivePolicy 생략 시 게이트 완전 비활성 (기존 동작 불변)", () => {
  const sid = "dc1-off";
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U 세션

  // 게이트가 꺼져 있으므로 비신뢰 노출 후에도 파괴 도구는 통과 (기존 동작 그대로)
  assert.equal(evaluateToolCall(ctx(sid, "delete_records", {})).allowed, true);

  // 유출 판정은 기존 그대로 — S+U 세션의 OUTBOUND는 여전히 차단
  recordToolResult(sid, "read_secrets", undefined, "키");
  const exfil = evaluateToolCall(ctx(sid, "http_post", { body: "전송" }));
  assert.equal(exfil.allowed, false);
  assert.ok(exfil.reason?.includes("lethal trifecta"));
});

test("설정 파싱: 기본값·정상값", () => {
  const cfg = loadPolicyConfig(writeConfig("parse-defaults.json", {}));
  assert.equal(cfg.destructivePolicy, "off");
  assert.equal(cfg.destructiveTools.size, 0);

  const cfg2 = loadPolicyConfig(
    writeConfig("parse-values.json", { destructivePolicy: "hitl", destructiveTools: ["drop_table"] })
  );
  assert.equal(cfg2.destructivePolicy, "hitl");
  assert.ok(cfg2.destructiveTools.has("drop_table"));
});

test("설정 검증 fail-closed: 잘못된 destructivePolicy·destructiveTools는 로드 예외", () => {
  assert.throws(
    () => loadPolicyConfig(writeConfig("bad-policy.json", { destructivePolicy: "blcok" })),
    /destructivePolicy/
  );
  assert.throws(
    () => loadPolicyConfig(writeConfig("bad-tools.json", { destructiveTools: "delete_records" })),
    /destructiveTools/
  );
});
