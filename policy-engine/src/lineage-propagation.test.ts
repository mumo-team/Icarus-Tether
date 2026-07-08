/**
 * 계보 태그 전파 테스트 — default 도메인 (propagationMode: "snapshot").
 *
 * 3대 불변식 검증이 핵심:
 *   1. 단방향 (자식→부모 역류 금지)
 *   2. 비대칭 (정화는 전파 안 됨 — 태그 추가만 전파)
 *   3. 판정 불간섭 (계보 태그는 sessionStore 판정에 영향 없음)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, type ToolCallContext } from "@taintguard/types";
import { recordToolResult, addNodeTags, evaluateToolCall, getTaintNode } from "./index.js";

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// 기본 상속
// ---------------------------------------------------------------------------

test("전파: 부모 SENSITIVE → 자식이 물려받는다 (ownTags에는 없음 — 상속 구분)", () => {
  const sid = "p1-inherit";
  const parent = recordToolResult(sid, "query_customer_db", undefined, { c: "고객정보레코드01" });
  const child = recordToolResult(sid, "send_email", { _taintRef: parent.id }, "전송됨");

  assert.ok(child.tags.has(ToolRiskTag.SENSITIVE)); // 상속됨
  assert.equal(child.ownTags.size, 0); // 자체 태그는 아님 (send_email은 분류된 싱크)
  assert.ok(parent.ownTags.has(ToolRiskTag.SENSITIVE)); // 부모는 자체 태그
});

test("전파 합집합: 부모 A{SENSITIVE} + 부모 C{UNTRUSTED} → 자식은 둘 다", () => {
  const sid = "p2-union";
  const a = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  // C는 같은 세션의 두 번째 오염 노드라 폴백으로 A에 연결되는 게 정상 (보수적 설계)
  const c = recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  const child = recordToolResult(sid, "send_email", { refs: [a.id, c.id] }, "ok");

  assert.equal(child.linkMethod, "MCP_REF");
  // 자식 tags = 자기자신(∅) ∪ A.tags ∪ C.tags — 두 부모의 자체 태그가 모두 들어와야 한다
  assert.ok(child.tags.has(ToolRiskTag.SENSITIVE)); // A의 자체 태그
  assert.ok(child.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN)); // C의 자체 태그
  const expected = new Set([...child.ownTags, ...a.tags, ...c.tags]);
  assert.deepEqual([...child.tags].sort(), [...expected].sort());
});

// ---------------------------------------------------------------------------
// ★ 불변식 1: 단방향 — 자식 오염이 부모로 역류하면 안 된다
// ---------------------------------------------------------------------------

test("★단방향: 자식에 태그를 추가해도 부모는 절대 바뀌지 않는다", () => {
  const sid = "p3-oneway";
  const parent = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  const child = recordToolResult(sid, "send_email", { _taintRef: parent.id }, "ok");

  addNodeTags(sid, child.id, [ToolRiskTag.UNTRUSTED_ORIGIN]);

  assert.ok(getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(!getTaintNode(sid, parent.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN)); // 역류 없음
  assert.deepEqual([...parent.tags], [ToolRiskTag.SENSITIVE]);
});

// ---------------------------------------------------------------------------
// ★ 불변식 2: 비대칭 — 부모 정화가 자식 태그를 지우면 안 된다
// ---------------------------------------------------------------------------

test("★비대칭: 부모 태그를 제거(정화 시뮬레이션)해도 자식은 유지한다", () => {
  const sid = "p4-asym";
  const parent = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  const child = recordToolResult(sid, "send_email", { _taintRef: parent.id }, "ok");
  assert.ok(child.tags.has(ToolRiskTag.SENSITIVE));

  // 다음 단계의 정화가 할 일을 직접 시뮬레이션 — 자식은 이미 원본을 복사했을 수
  // 있으므로 부모 정화가 자식 안전을 보장하지 못한다
  parent.tags.delete(ToolRiskTag.SENSITIVE);
  parent.ownTags.delete(ToolRiskTag.SENSITIVE);

  assert.ok(getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.SENSITIVE)); // 유지
});

// ---------------------------------------------------------------------------
// snapshot 모드: 생성 시점 1회 복사, 사후 추가는 전파 안 됨
// ---------------------------------------------------------------------------

test("snapshot: 생성 후 부모에 태그가 추가돼도 자식은 재계산하지 않는다", () => {
  const sid = "p5-snapshot";
  const parent = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  const child = recordToolResult(sid, "send_email", { _taintRef: parent.id }, "ok");

  addNodeTags(sid, parent.id, [ToolRiskTag.UNTRUSTED_ORIGIN]);

  assert.ok(getTaintNode(sid, parent.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.ok(!getTaintNode(sid, child.id)?.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN)); // 스냅샷 유지
});

// ---------------------------------------------------------------------------
// 3순위 폴백 후보: 자체-오염 노드만 (상속-만-오염 노드 제외)
// ---------------------------------------------------------------------------

test("폴백 후보: 상속으로만 오염된 노드는 제외, 자체-오염 노드만 parent 후보", () => {
  const sid = "p6-fallback";
  const source = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  const inheritedOnly = recordToolResult(sid, "send_email", undefined, "ok"); // 폴백→source, 상속만
  assert.ok(inheritedOnly.tags.has(ToolRiskTag.SENSITIVE));
  assert.equal(inheritedOnly.ownTags.size, 0);

  const next = recordToolResult(sid, "http_post", undefined, "ok");
  assert.equal(next.linkMethod, "TEMPORAL_FALLBACK");
  assert.deepEqual(next.parents, [source.id]); // inheritedOnly는 후보 아님
});

// ---------------------------------------------------------------------------
// ★ 불변식 3: 계보 태그는 판정에 영향 없음 (병행 기록)
// ---------------------------------------------------------------------------

test("★판정 불간섭: addNodeTags로 계보만 오염시켜도 sessionStore 판정은 그대로", () => {
  const sid = "p7-parallel";
  const node = recordToolResult(sid, "query_customer_db", undefined, { c: "레코드" });
  addNodeTags(sid, node.id, [ToolRiskTag.UNTRUSTED_ORIGIN]); // 계보에만 추가

  // sessionStore에는 SENSITIVE만 있으므로 트라이펙타 미성립 → 여전히 허용
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true);
});

test("addNodeTags: 없는 노드는 예외 (fail-closed)", () => {
  assert.throws(() => addNodeTags("p8-nosuch", "tn_00000000-0000-0000-0000-000000000000", []));
});
