/**
 * 계보(lineage) 그래프 1단계 테스트 — 노드 생성 + 3층 parent 연결.
 * (default 도메인 분류 사용: query_customer_db=민감, fetch_web_page=비신뢰, send_email=싱크)
 *
 * 전파·정화 연동은 다음 단계이므로 여기서는 "연결과 기록"만 검증한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";
import {
  recordToolResult,
  tagToolResult,
  evaluateToolCall,
  getSessionLineage,
  getTaintNode,
} from "./index.js";

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// 노드 생성 + 자체 태그
// ---------------------------------------------------------------------------

test("노드 생성: 민감 소스 결과는 SENSITIVE 태그를 가진 노드가 된다", () => {
  const node = recordToolResult("l1-sensitive", "query_customer_db", undefined, {
    customer: "김민준",
  });
  assert.match(node.id, /^tn_/);
  assert.ok(node.tags.has(ToolRiskTag.SENSITIVE));
  assert.deepEqual(node.parents, []);
  assert.equal(node.linkMethod, "NONE"); // 깨끗한 세션의 첫 노드
  assert.equal(getTaintNode("l1-sensitive", node.id), node);
});

test("노드 생성: 미분류 도구 결과는 UNTRUSTED_ORIGIN (default-deny가 계보에도 반영)", () => {
  const node = recordToolResult("l1-unknown", "some_unregistered_tool", undefined, "결과");
  assert.ok(node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
});

// ---------------------------------------------------------------------------
// 1순위: MCP 참조
// ---------------------------------------------------------------------------

test("1순위 MCP_REF: 인자 속 노드 id를 명시 참조로 연결 (강한 연결)", () => {
  const sid = "l2-ref";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, { email: "a@b.co" });
  const n2 = recordToolResult(sid, "send_email", { _taintRef: n1.id, to: "팀" }, "전송됨");

  assert.equal(n2.linkMethod, "MCP_REF");
  assert.deepEqual(n2.parents, [n1.id]);
  assert.equal(n2.parentLinks[0].weak, false);
});

test("우선순위: MCP 참조가 있으면 값 매칭·시간 근사는 시도하지 않는다", () => {
  const sid = "l2-priority";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, {
    code: "CUST-2024-001122",
  });
  const n2 = recordToolResult(sid, "fetch_web_page", undefined, "웹 문서"); // 오염(비신뢰) 노드
  // 인자에 n1 참조 + n2 결과 매칭 토큰이 둘 다 있어도 1순위만 사용
  const n3 = recordToolResult(
    sid,
    "send_email",
    { ref: n2.id, body: "고객 CUST-2024-001122 안내" },
    "ok"
  );
  assert.equal(n3.linkMethod, "MCP_REF");
  assert.deepEqual(n3.parents, [n2.id]);
  assert.ok(!n3.parents.includes(n1.id));
});

// ---------------------------------------------------------------------------
// 2순위: 값 매칭 (해시 기반, 흔한 값 제외, 약한 연결 표시)
// ---------------------------------------------------------------------------

test("2순위 VALUE_MATCH: 이전 결과의 긴 토큰(≥16자)이 인자에 나타나면 강한 연결", () => {
  const sid = "l3-strong";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, {
    code: "CUST-2024-001122",
  });
  const n2 = recordToolResult(sid, "send_email", { note: "주문 CUST-2024-001122 참조" }, "ok");

  assert.equal(n2.linkMethod, "VALUE_MATCH");
  assert.deepEqual(n2.parents, [n1.id]);
  assert.equal(n2.parentLinks[0].weak, false); // 16자 토큰 → 강한 연결
  assert.equal(n2.parentLinks[0].evidence?.tokenLength, 16);
});

test("2순위 VALUE_MATCH: 단일 짧은 토큰(8~15자) 매칭은 약한 연결로 표시", () => {
  const sid = "l3-weak";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, { code: "ORD-99310" });
  const n2 = recordToolResult(sid, "send_email", { note: "주문 ORD-99310 발송" }, "ok");

  assert.equal(n2.linkMethod, "VALUE_MATCH");
  assert.deepEqual(n2.parents, [n1.id]);
  assert.equal(n2.parentLinks[0].weak, true); // 9자 단일 토큰 → 튜닝 대상
});

test("값 매칭 제외: 8자 미만·흔한 토큰은 근거가 못 되고, 3순위로 보수적으로 떨어진다", () => {
  const sid = "l3-excluded";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, {
    a: "ab12", // 8자 미만
    b: "password", // 흔한 토큰
  });
  const n2 = recordToolResult(sid, "send_email", { note: "ab12 password" }, "ok");

  // 우연한 겹침으로 VALUE_MATCH가 되면 안 됨 — 대신 fail-safe하게 시간 근사로
  assert.equal(n2.linkMethod, "TEMPORAL_FALLBACK");
  assert.deepEqual(n2.parents, [n1.id]); // n1은 오염(SENSITIVE) 노드라 후보에 포함
  assert.equal(n2.parentLinks[0].weak, true);
});

test("프라이버시: 계보에는 결과 원본이 없고 토큰 해시(+길이)만 남는다", () => {
  const sid = "l3-privacy";
  const secretValue = "CUST-2024-001122";
  const n1 = recordToolResult(sid, "query_customer_db", undefined, { code: secretValue });

  assert.equal("result" in n1, false); // 원본 필드 자체가 없음
  for (const [hash, length] of n1.resultTokens) {
    assert.notEqual(hash, secretValue);
    assert.match(hash, /^[0-9a-f]{32}$/); // sha256 앞 32자
    assert.equal(typeof length, "number");
  }
});

// ---------------------------------------------------------------------------
// 3순위: 시간 근사 (fail-safe)
// ---------------------------------------------------------------------------

test("3순위 TEMPORAL_FALLBACK: 근거가 없으면 오염 노드 전부를 약한 parent로 (깨끗한 노드 제외)", () => {
  const sid = "l4-fallback";
  const tainted = recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  const clean = recordToolResult(sid, "send_email", undefined, "전송 완료"); // 태그 없음
  const n3 = recordToolResult(sid, "http_post", { url: "hooks" }, "ok");

  assert.equal(n3.linkMethod, "TEMPORAL_FALLBACK");
  assert.ok(n3.parents.includes(tainted.id));
  assert.ok(!n3.parents.includes(clean.id)); // 깨끗한 노드는 후보 아님
  assert.ok(n3.parentLinks.every((l) => l.weak && l.method === "TEMPORAL_FALLBACK"));
});

test("tagToolResult(페이로드 없는 기존 경로)도 계보 노드를 병행 생성한다", () => {
  const sid = "l4-tag-only";
  tagToolResult(sid, "query_customer_db");
  tagToolResult(sid, "fetch_web_page");

  const graph = getSessionLineage(sid);
  assert.equal(graph.size, 2);
  const nodes = [...graph.values()];
  // 두 번째 노드는 args가 없으므로 3순위로 첫 오염 노드에 연결된다
  assert.equal(nodes[1].linkMethod, "TEMPORAL_FALLBACK");
  assert.deepEqual(nodes[1].parents, [nodes[0].id]);
});

// ---------------------------------------------------------------------------
// 병행 확인: 계보는 아직 판정에 영향을 주지 않는다
// ---------------------------------------------------------------------------

test("병행: recordToolResult를 써도 기존 sessionStore 기반 판정은 동일하게 동작", () => {
  const sid = "l5-parallel";
  recordToolResult(sid, "query_customer_db", undefined, { customer: "김민준" });
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, true); // SENSITIVE 하나뿐

  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  assert.equal(evaluateToolCall(ctx(sid, "send_email")).allowed, false); // 트라이펙타
});
