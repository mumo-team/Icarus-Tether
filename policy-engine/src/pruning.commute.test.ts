/**
 * 가지치기 교환성(commutation) 테스트 — TLA+ 발견→수정의 회귀 검증.
 *
 * TaintPruningCommute.tla(재현판, git 이력)가 찾은 5스텝 반례: prune "이후"의
 * addNodeTags(지연 오염, live cascade)가 묘비에서 절단돼, 가지치기가 낀 세션과
 * 없던 세션의 판정이 갈라졌다 (유출·과차단 양방향). 수정(재오염 가능 묘비 —
 * cascade 관통 + 판정 5곳 묘비 태그 반영)은 TaintPruningCommuteFixed 모델로
 * 위반 0을 선증명한 뒤 이식했다. 기존 pruning.test.ts의 fast-check는 prune을
 * 항상 시퀀스 마지막에 두므로 이 계열을 관측하지 못한다 — 여기서는 prune을
 * 시퀀스 "중간"에 끼우고 가지치기 없는 쌍둥이 세션과 전 프로브 판정을 비교한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-commute-"));
const configFile = path.join(dir, "commute.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "commute-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    pruningPolicy: "declassified",
    propagationMode: "live", // cascade가 있어야 교환성 계열이 발현된다
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
  addNodeTags,
  getTaintNode,
  getTombstoneTags,
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
const nextSid = (): string => `commute-${++seq}`;

// ---------------------------------------------------------------------------
// T1 ★유출 방향 회귀 — TLC CommuteNoLeak 5스텝 반례의 코드판
// ---------------------------------------------------------------------------

test("★T1 유출 회귀: prune 후 조상 재오염이 묘비에 반영돼 묘비 참조가 차단된다", () => {
  const run = (sid: string, doPrune: boolean) => {
    const n1 = quiet(() => recordToolResult(sid, "http_post", undefined, "r1")); // 깨끗 루트
    const n2 = quiet(() => recordToolResult(sid, "http_post", { _taintRef: [n1.id] }, "r2")); // 깨끗 자식
    quiet(() => recordToolResult(sid, "fetch_web_page", { _taintRef: [n1.id] }, "doc")); // U — n1 생존 + 세션 U축

    if (doPrune) {
      const { pruned } = quiet(() => pruneSessionLineage(sid));
      assert.equal(pruned, 1); // n2만 — n1은 live 자식(U 노드) 보유
      assert.equal(getTaintNode(sid, n2.id), undefined);
    }

    quiet(() => addNodeTags(sid, n1.id, [ToolRiskTag.SENSITIVE])); // 지연 오염 발견
    return { n2Id: n2.id, allowed: quiet(() => evaluateToolCall(ctx(sid, { _taintRef: [n2.id] }))).allowed };
  };

  const withPrune = run(nextSid(), true);
  const twin = run(nextSid(), false);

  assert.equal(withPrune.allowed, false, "묘비 참조 유출 — 수정 전엔 통과였다");
  assert.equal(withPrune.allowed, twin.allowed, "가지치기 유무로 판정이 갈라짐");
});

// ---------------------------------------------------------------------------
// T2 cascade 관통 — 묘비 "너머"의 live 자손까지 사후 오염이 흐른다
// ---------------------------------------------------------------------------

test("T2 관통: 묘비를 경유한 사슬(조상→묘비→자손)로 사후 오염이 전파된다", () => {
  const sid = nextSid();
  const n1 = quiet(() => recordToolResult(sid, "http_post", undefined, "r1"));
  const p = quiet(() => recordToolResult(sid, "http_post", { _taintRef: [n1.id] }, "r2"));
  quiet(() => recordToolResult(sid, "fetch_web_page", { _taintRef: [n1.id] }, "doc")); // n1 생존 + 세션 U

  quiet(() => pruneSessionLineage(sid)); // p만 묘비
  const m = quiet(() => recordToolResult(sid, "http_post", { _taintRef: [p.id] }, "r3")); // 묘비 참조 자식

  quiet(() => addNodeTags(sid, n1.id, [ToolRiskTag.SENSITIVE]));

  assert.ok(getTombstoneTags(sid, p.id)?.has(ToolRiskTag.SENSITIVE), "묘비가 관통분을 적재");
  assert.ok(getTaintNode(sid, m.id)?.tags.has(ToolRiskTag.SENSITIVE), "묘비 너머 자손까지 전파");
  assert.equal(quiet(() => evaluateToolCall(ctx(sid, { _taintRef: [m.id] }))).allowed, false);
});

// ---------------------------------------------------------------------------
// T3 과차단 해소 — 재오염 묘비를 잡은 VALUE_MATCH는 출처 식별 = 안전 바닥 미발동
// ---------------------------------------------------------------------------

test("T3 과차단 해소: 재오염 묘비를 값 매칭으로 잡으면 바닥이 오발동하지 않는다", () => {
  const run = (sid: string, doPrune: boolean) => {
    const n1 = quiet(() => recordToolResult(sid, "http_post", undefined, "r1"));
    quiet(() => recordToolResult(sid, "http_post", { _taintRef: [n1.id] }, "shared-value-12345678")); // 깨끗 자식(긴 토큰)
    quiet(() => recordToolResult(sid, "fetch_web_page", { _taintRef: [n1.id] }, "doc")); // U
    quiet(() => recordToolResult(sid, "read_secrets", undefined, "키")); // S — 바닥 발동 시 차단 유발원

    if (doPrune) assert.equal(quiet(() => pruneSessionLineage(sid)).pruned, 1);
    quiet(() => addNodeTags(sid, n1.id, [ToolRiskTag.UNTRUSTED_ORIGIN])); // 묘비에 U 관통

    // 값 매칭 프로브: U만 실은(민감 아님) 값 — 출처가 식별되므로 통과해야 한다.
    // 수정 전 "묘비=무조건 깨끗" 규칙은 여기서 바닥을 발동시켜 frontier(S)로 차단했다.
    return quiet(() => evaluateToolCall(ctx(sid, { body: "shared-value-12345678" }))).allowed;
  };

  const withPrune = run(nextSid(), true);
  const twin = run(nextSid(), false);
  assert.equal(withPrune, twin, "가지치기 유무로 판정이 갈라짐 (과차단 방향)");
  assert.equal(withPrune, true, "출처 식별된 비민감 값이 바닥 오발동으로 차단됨");
});

// ---------------------------------------------------------------------------
// T4 ★쌍둥이 세션 fast-check — prune을 시퀀스 "중간"에 끼워도 판정 완전 동일
// ---------------------------------------------------------------------------

type Op =
  | { kind: "record"; tool: string; refs: number[]; payload: "clean" | "schemaValid" }
  | { kind: "sanitize"; method: SanitizationMethod }
  | { kind: "taint"; idx: number; tag: ToolRiskTag };

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
  },
  {
    arbitrary: fc.record({
      kind: fc.constant("taint" as const),
      idx: fc.nat({ max: 20 }),
      tag: fc.constantFrom(ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN),
    }),
    weight: 2,
  }
);

test("★T4 판정 보존(강화판): prune이 시퀀스 중간에 끼어도 쌍둥이 세션과 전 프로브 판정 동일", () => {
  fc.assert(
    fc.property(
      fc.array(opArb, { minLength: 4, maxLength: 12 }),
      fc.nat({ max: 11 }),
      (ops, pruneAt) => {
        const sidA = nextSid(); // 가지치기 O (pruneAt 위치)
        const sidB = nextSid(); // 가지치기 X — 이상세계 오라클
        const idsA: string[] = [];
        const idsB: string[] = [];

        const apply = (op: Op): void => {
          if (op.kind === "record") {
            const pick = (ids: string[]): string[] =>
              [...new Set(op.refs.map((i) => ids[i % Math.max(ids.length, 1)]))]
                .filter((id): id is string => id !== undefined);
            const refsA = pick(idsA);
            const refsB = pick(idsB);
            idsA.push(quiet(() =>
              recordToolResult(sidA, op.tool, refsA.length > 0 ? { _taintRef: refsA } : undefined,
                op.payload === "clean" ? "p" : { type: "note", name: "ok" })).id);
            idsB.push(quiet(() =>
              recordToolResult(sidB, op.tool, refsB.length > 0 ? { _taintRef: refsB } : undefined,
                op.payload === "clean" ? "p" : { type: "note", name: "ok" })).id);
          } else if (op.kind === "sanitize") {
            quiet(() => attemptSanitization(sidA, op.method));
            quiet(() => attemptSanitization(sidB, op.method));
          } else {
            if (idsA.length === 0) return;
            const i = op.idx % idsA.length;
            // 모델의 AddTag guard(n ∈ Live)와 동일: 대상이 A에서 묘비면 양쪽 모두 skip
            // (묘비 직접 재오염은 fail-closed throw로 문서화된 별도 경로)
            if (getTaintNode(sidA, idsA[i]!) === undefined) return;
            quiet(() => addNodeTags(sidA, idsA[i]!, [op.tag]));
            quiet(() => addNodeTags(sidB, idsB[i]!, [op.tag]));
          }
        };

        ops.forEach((op, k) => {
          apply(op);
          if (k === Math.min(pruneAt, ops.length - 1)) quiet(() => pruneSessionLineage(sidA));
        });

        // 프로브: 무참조 폴백 + 모든 노드(살았든 묘비든) 명시 참조 — 대응 인덱스 비교
        const decideAll = (sid: string, ids: string[]): boolean[] =>
          [{}, ...ids.map((id) => ({ _taintRef: [id] }))]
            .map((args) => quiet(() => evaluateToolCall(ctx(sid, args))).allowed);

        assert.deepEqual(decideAll(sidA, idsA), decideAll(sidB, idsB),
          "가지치기(중간 삽입) 유무로 판정이 갈라짐");
      }
    ),
    { numRuns: Number(process.env.FC_NUM_RUNS ?? 500) }
  );
});
