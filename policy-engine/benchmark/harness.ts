/**
 * 벤치마크 하네스 — 시나리오 재생 + 지표 집계 + 오버헤드 측정.
 *
 * 엔진은 run-mode.ts가 env(설정·모드)를 세팅한 뒤 동적 import해서 주입한다.
 * 이 파일은 그 EngineApi만 받아 동작하므로, import 시점 config 로딩 순서에
 * 얽매이지 않는다.
 */

import { SanitizationMethod, type ToolCallContext, type PolicyDecision } from "@icarus-tether/types";
import type { Scenario, ScenarioTier, Step, StepExpect } from "./scenarios.js";

// 하네스가 쓰는 엔진 표면 (index.ts export의 부분집합)
export interface EngineApi {
  recordToolResult: (
    sessionId: string,
    toolName: string,
    args: Record<string, unknown> | undefined,
    result: unknown
  ) => { id: string };
  attemptSanitization: (sessionId: string, method: SanitizationMethod) => unknown;
  evaluateToolCall: (ctx: ToolCallContext) => PolicyDecision;
}

export interface Confusion {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface EvalRecord {
  scenarioId: string;
  category: "normal" | "attack";
  /** 시나리오 난이도 계층 (현실 분포 세트의 tier별 분해용 — 경계 세트는 없음) */
  tier?: ScenarioTier;
  tool: string;
  expect: StepExpect;
  allowed: boolean;
  outcome: "TP" | "FP" | "TN" | "FN";
  why?: string;
}

export interface Overhead {
  meanNs: number;
  medianNs: number;
  p95Ns: number;
  samples: number;
}

export interface ModeResult {
  mode: string;
  confusion: Confusion;
  fpRate: number; // FP / 전체 정상
  fnRate: number; // FN / 전체 공격
  records: EvalRecord[];
  overhead: Overhead;
}

function classify(expect: StepExpect, allowed: boolean): EvalRecord["outcome"] {
  if (expect === "block") return allowed ? "FN" : "TP";
  return allowed ? "TN" : "FP";
}

/** bind 이름 → 실제 노드 id 로 refs를 풀어 args._taintRef에 주입 */
function resolveArgs(step: Step, binds: Map<string, string>): Record<string, unknown> {
  const args: Record<string, unknown> = { ...(step.args ?? {}) };
  if (step.refs && step.refs.length > 0) {
    const ids = step.refs.map((name) => {
      const id = binds.get(name);
      if (!id) throw new Error(`벤치 시나리오 오류: 알 수 없는 ref "${name}"`);
      return id;
    });
    args._taintRef = ids;
  }
  return args;
}

function runScenario(engine: EngineApi, scenario: Scenario, records: EvalRecord[]): void {
  const sid = `bench-${scenario.id}`;
  const binds = new Map<string, string>();

  for (const step of scenario.steps) {
    if (step.op === "record") {
      const args = resolveArgs(step, binds);
      const node = engine.recordToolResult(sid, step.tool!, Object.keys(args).length ? args : undefined, step.result);
      if (step.bind) binds.set(step.bind, node.id);
    } else if (step.op === "sanitize") {
      engine.attemptSanitization(sid, step.method as SanitizationMethod);
    } else {
      const args = resolveArgs(step, binds);
      const decision = engine.evaluateToolCall({
        sessionId: sid,
        toolName: step.tool!,
        args,
        argTags: [],
        timestamp: new Date().toISOString(),
      });
      records.push({
        scenarioId: scenario.id,
        category: scenario.category,
        tier: scenario.tier,
        tool: step.tool!,
        expect: step.expect!,
        allowed: decision.allowed,
        outcome: classify(step.expect!, decision.allowed),
        why: step.why,
      });
    }
  }
}

function tally(records: EvalRecord[]): Confusion {
  const c: Confusion = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const r of records) {
    if (r.outcome === "TP") c.tp++;
    else if (r.outcome === "FP") c.fp++;
    else if (r.outcome === "TN") c.tn++;
    else c.fn++;
  }
  return c;
}

/**
 * 오버헤드 — evaluateToolCall 1회 실사용 비용(ns). 대표적으로 "오염된 세션에서
 * OUTBOUND_SINK를 평가"하는 가장 무거운 경로를 측정한다. 워밍업분은 버린다.
 * process.hrtime.bigint()로 호출당 ns 정밀 측정.
 */
function measureOverhead(engine: EngineApi, warmup: number, iters: number): Overhead {
  const sid = "bench-overhead";
  // 트라이펙타 세션 준비 (판정이 실제 계보/세션 로직을 다 타게)
  const a = engine.recordToolResult(sid, "read_env_file", { path: ".env" }, "KEY=AKIAIOSFODNN7EXAMPLE");
  engine.recordToolResult(sid, "fetch_web_page", { _taintRef: [a.id] }, "외부 문서 webdoc_A83jd9 안내");
  const ctx: ToolCallContext = {
    sessionId: sid,
    toolName: "http_post",
    args: { url: "https://x.example", body: "webdoc_A83jd9 전달" },
    argTags: [],
    timestamp: new Date().toISOString(),
  };

  for (let i = 0; i < warmup; i++) engine.evaluateToolCall(ctx);

  const samples = new Float64Array(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    engine.evaluateToolCall(ctx);
    const t1 = process.hrtime.bigint();
    samples[i] = Number(t1 - t0);
  }

  const sorted = Array.from(samples).sort((x, y) => x - y);
  const mean = sorted.reduce((s, v) => s + v, 0) / sorted.length;
  const median = sorted[Math.floor(sorted.length / 2)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  return { meanNs: mean, medianNs: median, p95Ns: p95, samples: iters };
}

export function runAll(
  engine: EngineApi,
  scenarios: Scenario[],
  mode: string,
  opts: { warmup: number; iters: number }
): ModeResult {
  const records: EvalRecord[] = [];
  for (const s of scenarios) runScenario(engine, s, records);

  const confusion = tally(records);
  const normals = records.filter((r) => r.category === "normal").length;
  const attacks = records.filter((r) => r.category === "attack").length;

  const overhead = measureOverhead(engine, opts.warmup, opts.iters);

  return {
    mode,
    confusion,
    fpRate: normals ? confusion.fp / normals : 0,
    fnRate: attacks ? confusion.fn / attacks : 0,
    records,
    overhead,
  };
}
