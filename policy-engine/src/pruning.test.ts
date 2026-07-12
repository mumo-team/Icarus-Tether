/**
 * 계보 가지치기 테스트 — lineage + pruningPolicy=declassified.
 *
 * 제일 중요한 검증(★): 가지치기 전후로 판정 결과가 완전히 동일하다 —
 * fast-check로 랜덤 시나리오 × 프로브 호출 집합에 대해 실측 검증.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@taintguard/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-pruning-"));
const configFile = path.join(dir, "pruning.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "pruning-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    pruningPolicy: "declassified",
    piiPatterns: [{ type: "EMAIL", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" }],
    extractionSchema: {
      fields: {
        type: { kind: "enum", values: ["note"] },
        name: { kind: "string", maxLength: 20, charset: "safe-text" },
      },
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const {
  recordToolResult,
  attemptSanitization,
  evaluateToolCall,
  pruneSessionLineage,
  getTaintNode,
  getSessionLineage,
} = await import("./index.js");

function ctx(
  sessionId: string,
  args: Record<string, unknown> = {},
  argTags: ToolRiskTag[] = []
): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags, timestamp: new Date().toISOString() };
}

function quiet<T>(fn: () => T): T {
  const origLog = console.log;
  const origError = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    return fn();
  } finally {
    console.log = origLog;
    console.error = origError;
  }
}

let seq = 0;
const nextSid = (): string => `prune-${++seq}`;

// ---------------------------------------------------------------------------
// ★ 판정 보존 — 랜덤 시나리오 실측 (fast-check)
// ---------------------------------------------------------------------------

type Op =
  | { kind: "record"; tool: string; refs: number[]; payload: "clean" | "schemaValid" }
  | { kind: "sanitize"; method: SanitizationMethod };

const opArb: fc.Arbitrary<Op> = fc.oneof(
  {
    arbitrary: fc.record({
      kind: fc.constant("record" as const),
      tool: fc.constantFrom("read_secrets", "fetch_web_page", "http_post"),
      refs: fc.array(fc.nat({ max: 20 }), { maxLength: 2 }),
      payload: fc.constantFrom("clean" as const, "schemaValid" as const),
    }),
    weight: 3,
  },
  {
    arbitrary: fc.record({
      kind: fc.constant("sanitize" as const),
      method: fc.constantFrom(SanitizationMethod.TOKENIZATION, SanitizationMethod.STRUCTURED_EXTRACTION),
    }),
    weight: 2,
  }
);

test("★판정 보존: 가지치기 전 통과/차단이 가지치기 후에도 완전히 동일하다", () => {
  fc.assert(
    fc.property(fc.array(opArb, { minLength: 4, maxLength: 15 }), (ops) => {
      const sid = nextSid();
      const nodeIds: string[] = [];

      for (const op of ops) {
        if (op.kind === "record") {
          const refIds = [...new Set(op.refs.map((i) => nodeIds[i % Math.max(nodeIds.length, 1)]))]
            .filter((id): id is string => id !== undefined);
          const node = quiet(() =>
            recordToolResult(
              sid,
              op.tool,
              refIds.length > 0 ? { _taintRef: refIds } : undefined,
              op.payload === "clean" ? "p" : { type: "note", name: "ok" }
            )
          );
          nodeIds.push(node.id);
        } else {
          quiet(() => attemptSanitization(sid, op.method));
        }
      }

      // 프로브 집합: 무참조(폴백) + 생성된 모든 노드 각각에 대한 명시 참조
      const probes: Array<Record<string, unknown>> = [{}, ...nodeIds.map((id) => ({ _taintRef: [id] }))];
      const before = probes.map((args) => quiet(() => evaluateToolCall(ctx(sid, args))).allowed);

      quiet(() => pruneSessionLineage(sid));

      const after = probes.map((args) => quiet(() => evaluateToolCall(ctx(sid, args))).allowed);
      assert.deepEqual(after, before, "가지치기가 판정 결과를 바꿈");
    }),
    { numRuns: Number(process.env.FC_NUM_RUNS ?? 1000) }
  );
});

// ---------------------------------------------------------------------------
// 결정론 단위 케이스
// ---------------------------------------------------------------------------

test("정화돼 깨끗해진 childless 노드는 가지치기된다", () => {
  const sid = nextSid();
  const a = recordToolResult(sid, "read_secrets", undefined, { email: "a@b.co" });
  quiet(() => attemptSanitization(sid, SanitizationMethod.TOKENIZATION)); // a 정화

  const { pruned } = pruneSessionLineage(sid);
  assert.ok(pruned >= 1);
  assert.equal(getTaintNode(sid, a.id), undefined); // 그래프에서 제거됨
});

test("자식이 있는 정화 노드는 가지치기되지 않는다 (dangling 방지)", () => {
  const sid = nextSid();
  const a = recordToolResult(sid, "read_secrets", undefined, { email: "a@b.co" });
  const b = recordToolResult(sid, "fetch_web_page", { _taintRef: [a.id] }, "문서"); // 오염 자식
  quiet(() => attemptSanitization(sid, SanitizationMethod.TOKENIZATION)); // a만 정화

  pruneSessionLineage(sid);
  assert.ok(getTaintNode(sid, a.id)); // 자식 b가 남아있어 유지
  assert.ok(getTaintNode(sid, b.id)?.tags.has(ToolRiskTag.SENSITIVE)); // b는 오염 유지(비대칭)
});

test("오염된 노드는 절대 가지치기되지 않는다", () => {
  const sid = nextSid();
  const a = recordToolResult(sid, "read_secrets", undefined, "키");
  const b = recordToolResult(sid, "fetch_web_page", undefined, "문서");

  pruneSessionLineage(sid);
  assert.ok(getTaintNode(sid, a.id));
  assert.ok(getTaintNode(sid, b.id));
  assert.equal(getSessionLineage(sid).size, 2);
});

test("연쇄(fixpoint): 깨끗한 체인은 자식부터 부모까지 한 번에 정리된다", () => {
  const sid = nextSid();
  const a = recordToolResult(sid, "http_post", undefined, "r1"); // 깨끗
  const b = recordToolResult(sid, "http_post", { _taintRef: [a.id] }, "r2"); // 깨끗, a의 자식

  const { pruned } = pruneSessionLineage(sid);
  assert.equal(pruned, 2); // b 제거 → a가 childless로 승격 → a도 제거
  assert.equal(getSessionLineage(sid).size, 0);
});

test("★묘비의 판정 보존(구체 케이스): 가지치기된 노드를 명시 참조하면 여전히 통과", () => {
  const sid = nextSid();
  // 깨끗한 노드 P를 먼저 (오염 frontier가 생기기 전 → 아무에게도 연결 안 됨)
  const p = recordToolResult(sid, "http_post", undefined, "r0");
  // 그 뒤 트라이펙타 오염 세션 구성
  recordToolResult(sid, "read_secrets", undefined, "키");
  recordToolResult(sid, "fetch_web_page", undefined, "문서");

  // 가지치기 전: P 참조는 통과(깨끗한 계보), 무참조는 차단(오염 frontier 폴백)
  assert.equal(quiet(() => evaluateToolCall(ctx(sid, { _taintRef: [p.id] }))).allowed, true);
  assert.equal(quiet(() => evaluateToolCall(ctx(sid))).allowed, false);

  const { pruned } = pruneSessionLineage(sid);
  assert.equal(pruned, 1); // P만 정리됨
  assert.equal(getTaintNode(sid, p.id), undefined);

  // 가지치기 후에도 동일: P 참조는 묘비 덕에 여전히 통과, 무참조는 여전히 차단
  assert.equal(quiet(() => evaluateToolCall(ctx(sid, { _taintRef: [p.id] }))).allowed, true);
  assert.equal(quiet(() => evaluateToolCall(ctx(sid))).allowed, false);
});

test("가지치기 후에도 frontier(승계) 규칙이 정상 동작한다", () => {
  const sid = nextSid();
  const p = recordToolResult(sid, "http_post", undefined, "r0"); // 깨끗 → 가지치기 대상
  const f1 = recordToolResult(sid, "read_secrets", undefined, "키");
  const f2 = recordToolResult(sid, "fetch_web_page", undefined, "문서");
  pruneSessionLineage(sid); // p 제거

  const n = quiet(() => recordToolResult(sid, "http_post", undefined, "새 결과"));
  assert.equal(n.linkMethod, "TEMPORAL_FALLBACK");
  assert.deepEqual([...n.parents].sort(), [f1.id, f2.id].sort()); // frontier 그대로
  assert.ok(!n.parents.includes(p.id)); // 깨끗했던 p는 원래도 후보가 아님
});
