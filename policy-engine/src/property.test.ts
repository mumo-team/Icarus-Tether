/**
 * Property-based testing (fast-check) — TLA+ SinkSafety를 "실제 구현"으로 검증.
 *
 * formal/TaintLineage.tla가 설계의 안전 속성을 전수 탐색으로 증명했다면,
 * 이 파일은 같은 속성을 실제 코드(judgmentMode=lineage)에 대해 수천 개의
 * 랜덤 도구 호출 시퀀스로 검증한다. 둘은 짝: TLA+ = 설계, fast-check = 구현.
 *
 * 오라클 설계 — 순환성 회피:
 *   엔진 함수(previewParentLinks 등)를 오라클로 쓰면 엔진을 엔진으로 검증하는
 *   순환이 된다. 대신 아래 RefModel이 TLA+ 모델을 독립적으로 재구현한
 *   레퍼런스이며, 엔진의 실제 결과를 이 모델의 예측과 양방향 대조한다
 *   (유출도, 과차단도 반례가 된다).
 *
 * 생성기 단순화 — VALUE_MATCH(2순위) 배제:
 *   모든 페이로드 문자열을 8자 미만으로 제한해 값 매칭 토큰이 생기지 않게 한다.
 *   따라서 연결은 명시 참조(MCP_REF) 또는 폴백(frontier)만 남아 레퍼런스 모델이
 *   결정론적으로 미러링할 수 있다. (2순위 자체는 lineage.test.ts가 검증)
 *
 * 공허하지 않음 보장 (TLA+ sanity check 교훈):
 *   생성기가 위험한 케이스(트라이펙타 생성, 차단, 정화 성공/실패)를 실제로
 *   만들었는지 전 실행에 걸쳐 집계하고, 마지막 테스트가 카운터 전부 > 0을
 *   assert한다 — 안전한 시퀀스만 생성되면 테스트 자체가 실패한다.
 *
 * 반례 발생 시: fc.assert가 자동으로 shrinking해 최소 재현 시퀀스와 seed를
 * 에러 메시지에 출력한다. 재현: 에러의 seed/path를 fc.assert 옵션에 넣고 재실행.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";

// --- lineage 모드 테스트 설정 (warn/live 테스트와 같은 패턴) ---
const dir = mkdtempSync(path.join(tmpdir(), "taintguard-property-"));
const configFile = path.join(dir, "property-lineage.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "property-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    // secretDetection은 의도적으로 생략 — 태깅을 생성기가 완전 통제 (내용 기반 태깅 배제)
    piiPatterns: [{ type: "EMAIL", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" }],
    extractionSchema: {
      fields: {
        type: { kind: "enum", values: ["note", "bug"] },
        name: { kind: "string", maxLength: 20, charset: "safe-text" },
      },
    },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;

const { recordToolResult, attemptSanitization, evaluateToolCall, getSessionLineage } =
  await import("./index.js");

const S = ToolRiskTag.SENSITIVE;
const U = ToolRiskTag.UNTRUSTED_ORIGIN;

const NUM_RUNS = (n: number): number =>
  process.env.FC_NUM_RUNS ? Number(process.env.FC_NUM_RUNS) : n;

// ===========================================================================
// RefModel — TLA+ TaintLineage 모델의 코드판 레퍼런스 (오라클)
//
// 신뢰성의 핵심이므로 각 메서드에 TLA+ 액션 대응을 명시한다. TLA+가
// 비결정(∃)으로 뭉갠 지점 중 실제 코드가 결정론으로 고른 것(frontier 폴백)은
// "TLA+ 허용 범위(ps ⊆ created)의 한 경우를 코드와 같은 규칙으로 고른 것"이다.
// ===========================================================================

type PayloadKind = "clean" | "schemaValid" | "junk";

interface ModelNode {
  id: string;
  tags: Set<ToolRiskTag>; // TLA+ tags[n]
  parents: string[]; // TLA+ parents[n] — 생성 후 불변
}

interface ModelRecord {
  nodeId: string;
  tags: Set<ToolRiskTag>;
  payloadKind: PayloadKind;
}

const SENSITIVE_TOOLS = new Set(["read_secrets"]);
const UNTRUSTED_TOOLS = new Set(["fetch_web_page"]);
const CLASSIFIED_TOOLS = new Set(["read_secrets", "fetch_web_page", "http_post"]);

class RefModel {
  nodes: ModelNode[] = []; // 삽입 순서 = 생성 순서 (TLA+ created의 시간 순서)
  byId = new Map<string, ModelNode>();
  records: ModelRecord[] = []; // index.ts payloadStore 미러
  sessionTags = new Set<ToolRiskTag>(); // index.ts sessionStore 미러 (정화 조건에만 사용)

  /** classifySourceTags 미러: 소스 분류 + default-deny(미분류 → UNTRUSTED) */
  ownTagsFor(tool: string): Set<ToolRiskTag> {
    const tags = new Set<ToolRiskTag>();
    if (SENSITIVE_TOOLS.has(tool)) tags.add(S);
    if (UNTRUSTED_TOOLS.has(tool)) tags.add(U);
    if (!CLASSIFIED_TOOLS.has(tool)) tags.add(U); // default-deny
    return tags;
  }

  /**
   * 3순위 폴백의 frontier(루트 보유자) 규칙 미러 — lineage.ts isLiveTaintRoot.
   * TLA+에서는 CreateNode의 ps가 "created의 임의 부분집합"(비결정)이고, 코드는
   * 그중 이 규칙으로 결정한다. 모델은 코드의 결정을 따르되, 이 선택이 TLA+
   * 허용 범위 안임이 TLC 전수 탐색으로 이미 보장돼 있다.
   */
  frontier(): string[] {
    return this.nodes
      .filter((n) =>
        [...n.tags].some((t) => !n.parents.some((pid) => this.byId.get(pid)!.tags.has(t)))
      )
      .map((n) => n.id);
  }

  /** 생성기 refs(인덱스)를 실존 노드 id로 해석 — mod 기법 (shrinking 친화) */
  resolveRefs(indices: number[]): string[] {
    if (this.nodes.length === 0) return [];
    return [...new Set(indices.map((i) => this.nodes[i % this.nodes.length].id))];
  }

  /**
   * TLA+ CreateNode(n, own, ps) 대응:
   *   tags' = own ∪ UNION {tags[p] : p ∈ ps}   ← 아래 합집합 식과 동일 (전파)
   *   ps ⊆ created                              ← refs/frontier 모두 기존 노드만
   * ps 결정: refs 있으면 그것(코드의 MCP_REF), 없으면 frontier(코드의 3순위).
   */
  createNode(id: string, tool: string, refIds: string[], payloadKind: PayloadKind): ModelNode {
    const own = this.ownTagsFor(tool);
    const parents = refIds.length > 0 ? refIds : this.frontier();
    const tags = new Set(own);
    for (const pid of parents) for (const t of this.byId.get(pid)!.tags) tags.add(t);

    const node: ModelNode = { id, tags, parents };
    this.nodes.push(node);
    this.byId.set(id, node);
    for (const t of own) this.sessionTags.add(t);
    if (own.size > 0) this.records.push({ nodeId: id, tags: new Set(own), payloadKind });
    return node;
  }

  /**
   * TLA+ Declassify(n, t) 대응 — 대상 노드"들"의 targetTag만 제거하고,
   * 이 메서드에 자식을 갱신하는 코드가 없다 (비대칭 — declassifyNodeTag와 동일 구조).
   * 성공 조건은 index.ts attemptSanitization 미러:
   *   session에 targetTag 존재 ∧ targetTag 레코드 존재 ∧ 전원 검증 통과.
   * 검증 결과 미러: TOKENIZATION은 이 설정의 페이로드(전부 PII 없음)에서 항상
   * 성공, STRUCTURED_EXTRACTION은 schemaValid 페이로드만 성공.
   */
  sanitize(method: SanitizationMethod): { success: boolean; targets: string[] } {
    const targetTag = method === SanitizationMethod.TOKENIZATION ? S : U;
    const targets = this.records.filter((r) => r.tags.has(targetTag));
    if (!this.sessionTags.has(targetTag) || targets.length === 0) {
      return { success: false, targets: [] };
    }
    const allOk = targets.every((r) =>
      method === SanitizationMethod.TOKENIZATION ? true : r.payloadKind === "schemaValid"
    );
    if (!allOk) return { success: false, targets: [] }; // fail-safe: 하나라도 실패 → 전부 유지

    this.sessionTags.delete(targetTag);
    for (const r of targets) {
      r.tags.delete(targetTag);
      this.byId.get(r.nodeId)!.tags.delete(targetTag); // 그 노드만 — 자식 항 없음
    }
    return { success: true, targets: targets.map((r) => r.nodeId) };
  }

  /**
   * index.ts computeLineageDecision 미러 — ★비대칭 위협 모델:
   *   차단 ⇔ (값-계보에 민감 S) AND (세션에 살아있는 비신뢰 U).
   *   - 민감(S): 이 값이 실제로 민감 데이터를 담는가 → 값-계보(부모 태그 ∪ argTags).
   *   - 비신뢰(U): 세션이 비신뢰에 노출됐는가 → 세션 전체 노드 중 U 보유 존재
   *     (제어흐름 조작 위협이라 값에 본문이 없어도 성립). 값-축 U(argTags/부모)도 충분.
   * TLA+ per-value 트라이펙타보다 엄격한 보수적 확장이므로 SinkSafety를 위반하지 않는다.
   */
  predictAllowed(refIds: string[], argTags: ToolRiskTag[]): boolean {
    const parents = refIds.length > 0 ? refIds : this.frontier();
    const valueTags = new Set<ToolRiskTag>(argTags);
    for (const pid of parents) for (const t of this.byId.get(pid)!.tags) valueTags.add(t);
    const valueSensitive = valueTags.has(S);
    const sessionUntrusted = valueTags.has(U) || this.nodes.some((n) => n.tags.has(U));
    return !(valueSensitive && sessionUntrusted);
  }
}

// ===========================================================================
// 생성기 (op ADT) — 위험 케이스가 자주 나오게 소스 도구에 가중치
// ===========================================================================

type Op =
  | { kind: "record"; tool: string; refs: number[]; payloadKind: PayloadKind }
  | { kind: "sanitize"; method: SanitizationMethod }
  | { kind: "evaluate"; refs: number[]; argTags: ToolRiskTag[] };

const recordArb = fc.record({
  kind: fc.constant("record" as const),
  // 민감·비신뢰 소스에 가중 — 트라이펙타가 실제로 만들어지게
  tool: fc.constantFrom(
    "read_secrets",
    "read_secrets",
    "fetch_web_page",
    "fetch_web_page",
    "http_post",
    "mystery_tool" // 미분류 → default-deny로 UNTRUSTED
  ),
  refs: fc.array(fc.nat({ max: 30 }), { maxLength: 2 }),
  payloadKind: fc.constantFrom<PayloadKind>("clean", "schemaValid", "junk"),
});

const sanitizeArb = fc.record({
  kind: fc.constant("sanitize" as const),
  method: fc.constantFrom(SanitizationMethod.TOKENIZATION, SanitizationMethod.STRUCTURED_EXTRACTION),
});

const evaluateArb = fc.record({
  kind: fc.constant("evaluate" as const),
  refs: fc.array(fc.nat({ max: 30 }), { maxLength: 2 }),
  argTags: fc.subarray([S, U]),
});

const opArb: fc.Arbitrary<Op> = fc.oneof(
  { arbitrary: recordArb, weight: 4 },
  { arbitrary: evaluateArb, weight: 3 },
  { arbitrary: sanitizeArb, weight: 2 }
);

const seqArb = fc.array(opArb, { minLength: 5, maxLength: 25 });

function makePayload(kind: PayloadKind): unknown {
  // 전부 8자 미만 문자열 → 값 매칭 토큰이 생기지 않는다 (VALUE_MATCH 배제)
  switch (kind) {
    case "clean":
      return "p"; // 추출 실패(객체 아님) / 토큰화 성공
    case "schemaValid":
      return { type: "note", name: "ok" }; // 둘 다 성공
    case "junk":
      return { type: "zzz", name: "ok" }; // 추출 실패(enum 밖) / 토큰화 성공
  }
}

// ===========================================================================
// 인터프리터 — 시퀀스를 엔진에 실행하며 매 스텝 모델 예측과 대조
// ===========================================================================

let sessionSeq = 0;
const nextSid = (): string => `prop-${++sessionSeq}`;

// 공허하지 않음 카운터 — 마지막 테스트가 전부 > 0 을 assert
const stats = {
  trifectaNodesCreated: 0,
  sinkBlocked: 0,
  sinkAllowed: 0,
  sanitizeOk: 0,
  sanitizeFail: 0,
  failSafeBlocked: 0,
};

/** 수천 회 실행 시 TrifectaEvent/fail-safe 로그 폭주 방지 (카운터가 대신함) */
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

function ctx(sessionId: string, args: Record<string, unknown>, argTags: ToolRiskTag[]): ToolCallContext {
  return { sessionId, toolName: "http_post", args, argTags, timestamp: new Date().toISOString() };
}

function snapshotTags(sid: string): Map<string, string> {
  const snap = new Map<string, string>();
  for (const [id, node] of getSessionLineage(sid)) snap.set(id, [...node.tags].sort().join("+"));
  return snap;
}

function tagsEqual(actual: ReadonlySet<ToolRiskTag>, expected: ReadonlySet<ToolRiskTag>): boolean {
  return actual.size === expected.size && [...expected].every((t) => actual.has(t));
}

/** 시퀀스 실행 + 전 속성(SinkSafety·전파 합집합·단방향·비대칭) 스텝별 검증 */
function runScenario(ops: Op[]): void {
  const sid = nextSid();
  const model = new RefModel();

  for (const op of ops) {
    const before = snapshotTags(sid);

    if (op.kind === "record") {
      const refIds = model.resolveRefs(op.refs);
      const args = refIds.length > 0 ? { _taintRef: refIds } : undefined;
      const node = quiet(() =>
        recordToolResult(sid, op.tool, args, makePayload(op.payloadKind))
      );
      const predicted = model.createNode(node.id, op.tool, refIds, op.payloadKind);

      // 전파: tags = own ∪ ⋃(parents.tags) — TLA+ CreateNode와 동일 식
      assert.ok(tagsEqual(node.tags, predicted.tags), `전파 불일치: ${[...node.tags]} vs ${[...predicted.tags]}`);
      assert.deepEqual([...node.parents].sort(), [...predicted.parents].sort(), "parent 연결 불일치");
      if (predicted.tags.has(S) && predicted.tags.has(U)) stats.trifectaNodesCreated++;

      // ★단방향: 노드 생성이 기존 노드의 태그를 절대 바꾸지 않는다
      for (const [id, tagStr] of before) {
        assert.equal(snapshotTags(sid).get(id), tagStr, `단방향 위반: 기존 노드 ${id} 변경됨`);
      }
    } else if (op.kind === "sanitize") {
      const expected = model.sanitize(op.method);
      const targetTag = op.method === SanitizationMethod.TOKENIZATION ? S : U;
      const result = quiet(() => attemptSanitization(sid, op.method));
      const engineSuccess =
        result.originalTags.includes(targetTag) && !result.resultTags.includes(targetTag);
      assert.equal(engineSuccess, expected.success, "정화 성공 여부 불일치");
      expected.success ? stats.sanitizeOk++ : stats.sanitizeFail++;

      // ★비대칭: 변한 노드는 "정화 검증을 통과한 그 노드들"뿐이고, 정확히 targetTag만 잃는다
      const changedAllowed = new Set(expected.success ? expected.targets : []);
      for (const [id, tagStr] of before) {
        const now = snapshotTags(sid).get(id);
        if (changedAllowed.has(id)) {
          const expectedTags = tagStr.split("+").filter((t) => t !== "" && t !== targetTag);
          assert.equal(now, expectedTags.sort().join("+"), `정화 대상 ${id}의 태그 변화가 targetTag 제거와 다름`);
        } else {
          assert.equal(now, tagStr, `비대칭 위반: 정화 대상이 아닌 노드 ${id} 변경됨`);
        }
      }
    } else {
      const refIds = model.resolveRefs(op.refs);
      const args = refIds.length > 0 ? { _taintRef: refIds } : {};
      const decision = quiet(() => evaluateToolCall(ctx(sid, args, op.argTags)));

      // ★SinkSafety (양방향): 트라이펙타 계보 ⇔ 차단. 유출(트라이펙타인데 통과)도
      // 과차단(깨끗한데 차단)도 여기서 반례가 된다.
      const expectedAllowed = model.predictAllowed(refIds, op.argTags);
      assert.equal(
        decision.allowed,
        expectedAllowed,
        expectedAllowed ? "과차단: 깨끗한 계보가 차단됨" : "★유출: 트라이펙타 계보가 sink 통과"
      );
      decision.allowed ? stats.sinkAllowed++ : stats.sinkBlocked++;

      // 판정은 읽기 전용 — 어떤 노드의 태그도 바꾸지 않는다
      for (const [id, tagStr] of before) {
        assert.equal(snapshotTags(sid).get(id), tagStr, "판정이 계보를 변형함");
      }
    }
  }
}

// ===========================================================================
// 속성들
// ===========================================================================

test("P1 ★SinkSafety: 랜덤 시퀀스에서 트라이펙타 계보 ⇔ 차단 (전파·단방향·비대칭 동시 검증)", () => {
  fc.assert(
    fc.property(seqArb, (ops) => {
      runScenario(ops);
    }),
    { numRuns: NUM_RUNS(5000) }
  );
});

test("P2 ★전파 단방향(집중): 자식을 어떻게 만들어도 부모 노드들의 태그는 불변", () => {
  fc.assert(
    fc.property(
      fc.array(fc.constantFrom("read_secrets", "fetch_web_page", "http_post"), {
        minLength: 1,
        maxLength: 4,
      }),
      fc.constantFrom("read_secrets", "fetch_web_page", "mystery_tool"),
      (parentTools, childTool) => {
        const sid = nextSid();
        const parentIds = parentTools.map(
          (tool) => quiet(() => recordToolResult(sid, tool, undefined, "p")).id
        );
        const before = snapshotTags(sid);

        quiet(() => recordToolResult(sid, childTool, { _taintRef: parentIds }, "p"));

        for (const [id, tagStr] of before) {
          assert.equal(snapshotTags(sid).get(id), tagStr);
        }
      }
    ),
    { numRuns: NUM_RUNS(3000) }
  );
});

test("P3 ★정화 비대칭(집중): 부모 정화가 자식 태그를 자동으로 떼지 않는다", () => {
  fc.assert(
    fc.property(
      fc.constantFrom(
        { tool: "read_secrets", method: SanitizationMethod.TOKENIZATION },
        { tool: "fetch_web_page", method: SanitizationMethod.STRUCTURED_EXTRACTION }
      ),
      fc.constantFrom<PayloadKind>("clean", "schemaValid", "junk"),
      ({ tool, method }, payloadKind) => {
        const sid = nextSid();
        const parent = quiet(() => recordToolResult(sid, tool, undefined, makePayload(payloadKind)));
        const child = quiet(() => recordToolResult(sid, "http_post", { _taintRef: [parent.id] }, "p"));
        const childTagsBefore = [...child.tags].sort().join("+");

        quiet(() => attemptSanitization(sid, method));

        // 정화 성공·실패와 무관하게 자식은 절대 안 바뀐다 — 각자 정화를 통과해야 풀린다
        assert.equal([...child.tags].sort().join("+"), childTagsBefore);
      }
    ),
    { numRuns: NUM_RUNS(3000) }
  );
});

test("P4 ★fail-safe: real 계산이 실패해도 절대 통과(allowed:true)가 나오지 않는다", () => {
  fc.assert(
    fc.property(seqArb, (ops) => {
      const sid = nextSid();
      const model = new RefModel();
      // 랜덤 상태를 만든 뒤 (검증 없이 실행만)
      for (const op of ops) {
        if (op.kind === "record") {
          const refIds = model.resolveRefs(op.refs);
          const node = quiet(() =>
            recordToolResult(
              sid,
              op.tool,
              refIds.length > 0 ? { _taintRef: refIds } : undefined,
              makePayload(op.payloadKind)
            )
          );
          model.createNode(node.id, op.tool, refIds, op.payloadKind);
        } else if (op.kind === "sanitize") {
          quiet(() => attemptSanitization(sid, op.method));
        }
      }
      // 순환 참조 args → 계보 순회가 예외를 던진다 → fail-safe는 차단이어야 한다
      const circular: Record<string, unknown> = {};
      circular.self = circular;
      const decision = quiet(() => evaluateToolCall(ctx(sid, circular, [])));
      assert.equal(decision.allowed, false, "★fail-safe 위반: 계산 실패가 조용히 통과됨");
      assert.ok(decision.reason?.includes("fail-safe"));
      stats.failSafeBlocked++;
    }),
    { numRuns: NUM_RUNS(2000) }
  );
});

// ===========================================================================
// 공허하지 않음 검증 — 생성기가 위험 케이스를 실제로 만들었는가 (선언 순서상 마지막 실행)
// ===========================================================================

test("생성기 비공허성: 위험 케이스(트라이펙타·차단·정화 성공/실패)가 실제로 생성됐다", () => {
  console.log("[property-stats]", JSON.stringify(stats));
  assert.ok(stats.trifectaNodesCreated > 0, "트라이펙타 노드가 한 번도 안 만들어짐 — 생성기 공허");
  assert.ok(stats.sinkBlocked > 0, "차단이 한 번도 없음 — 생성기 공허");
  assert.ok(stats.sinkAllowed > 0, "통과가 한 번도 없음 — 생성기가 위험만 생성");
  assert.ok(stats.sanitizeOk > 0, "정화 성공 경로가 한 번도 안 나옴");
  assert.ok(stats.sanitizeFail > 0, "정화 실패(fail-safe) 경로가 한 번도 안 나옴");
  assert.ok(stats.failSafeBlocked > 0, "fail-safe 차단이 한 번도 안 나옴");
});
