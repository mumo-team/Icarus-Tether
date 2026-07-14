/**
 * propagationMode: "live" 전파 테스트.
 * (별도 프로세스이므로 임시 설정 파일 + TAINTGUARD_TOOL_REGISTRY로 로드 —
 *  warn-policy.test.ts와 같은 패턴)
 *
 * live에서도 3대 불변식은 동일하게 성립해야 한다: 전파는 부모→자식, 추가분만.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ToolRiskTag } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-live-"));
const configFile = path.join(dir, "live.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "live-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    propagationMode: "live",
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, addNodeTags, getTaintNode } = await import("./index.js");

test("live: 부모에 태그가 추가되면 자식·손자까지 하향 전파된다 (다층)", () => {
  const sid = "lv1-cascade";
  const parent = recordToolResult(sid, "read_secrets", undefined, "키 목록"); // SENSITIVE
  const child = recordToolResult(sid, "http_post", { _taintRef: parent.id }, "r1");
  const grandchild = recordToolResult(sid, "http_post", { _taintRef: child.id }, "r2");
  assert.ok(!child.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(!grandchild.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));

  addNodeTags(sid, parent.id, [ToolRiskTag.UNTRUSTED_ORIGIN]); // 지연 발견된 오염

  assert.ok(getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(getTaintNode(sid, grandchild.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  // 전파분은 상속이지 자체 태그가 아니다
  assert.equal(getTaintNode(sid, child.id)?.ownTags.size, 0);
  assert.equal(getTaintNode(sid, grandchild.id)?.ownTags.size, 0);
});

test("★live 단방향: 자식에 추가된 태그는 live여도 부모로 역류하지 않는다", () => {
  const sid = "lv2-oneway";
  const parent = recordToolResult(sid, "read_secrets", undefined, "키"); // SENSITIVE
  const child = recordToolResult(sid, "http_post", { _taintRef: parent.id }, "r");

  addNodeTags(sid, child.id, [ToolRiskTag.UNTRUSTED_ORIGIN]);

  assert.ok(getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(!getTaintNode(sid, parent.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
});

test("★live 비대칭: 부모 태그 제거(정화)는 자손에 전파되지 않는다", () => {
  const sid = "lv3-asym";
  const parent = recordToolResult(sid, "read_secrets", undefined, "키");
  const child = recordToolResult(sid, "http_post", { _taintRef: parent.id }, "r1");
  const grandchild = recordToolResult(sid, "http_post", { _taintRef: child.id }, "r2");
  assert.ok(grandchild.tags.has(ToolRiskTag.SENSITIVE));

  // 정화 시뮬레이션 — live 모드라도 "줄어드는" 변경은 절대 내려가지 않는다
  parent.tags.delete(ToolRiskTag.SENSITIVE);
  parent.ownTags.delete(ToolRiskTag.SENSITIVE);

  assert.ok(getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.SENSITIVE));
  assert.ok(getTaintNode(sid, grandchild.id)?.tags.has(ToolRiskTag.SENSITIVE));
});

test("live: 이미 있는 태그의 재추가는 no-op (늘어날 때만 전파)", () => {
  const sid = "lv4-noop";
  const parent = recordToolResult(sid, "read_secrets", undefined, "키"); // SENSITIVE
  const child = recordToolResult(sid, "http_post", { _taintRef: parent.id }, "r");

  addNodeTags(sid, parent.id, [ToolRiskTag.SENSITIVE]); // 이미 보유 → 추가분 없음

  const c = getTaintNode(sid, child.id);
  assert.deepEqual([...(c?.tags ?? [])], [ToolRiskTag.SENSITIVE]); // 변화 없음
  assert.equal(c?.ownTags.size, 0);
});
