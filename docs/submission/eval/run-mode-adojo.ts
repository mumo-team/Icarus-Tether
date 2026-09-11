/**
 * AgentDojo 판정 지점 세트를 한 모드(session|lineage)로 실제 엔진에 채점.
 *
 * B(policy-engine) 파일은 수정하지 않는다 — 엔진의 공개 API(recordToolResult/
 * evaluateToolCall)만 import해서 쓴다. run-mode.ts와 동일하게, config를 임시
 * 파일로 쓰고 TAINTGUARD_TOOL_REGISTRY로 가리킨 뒤 엔진을 동적 import한다
 * (config 캐시가 프로세스당 1회라 모드별 별도 프로세스 필요).
 *
 * 실행: BENCH_MODE=session|lineage tsx run-mode-adojo.ts  → 결과 JSON 1줄을 stdout에.
 */
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE = path.resolve(__dirname, "../../../policy-engine/src/index.ts");

const mode = process.env.BENCH_MODE ?? "session";
if (mode !== "session" && mode !== "lineage") {
  console.error(`알 수 없는 BENCH_MODE: ${mode}`);
  process.exit(2);
}

const data = JSON.parse(readFileSync(path.join(__dirname, "scenarios-agentdojo.json"), "utf8"));
const config = data.config;
config.judgmentMode = mode;

const tmpDir = mkdtempSync(path.join(tmpdir(), "adojo-config-"));
const tmpConfig = path.join(tmpDir, "config.json");
writeFileSync(tmpConfig, JSON.stringify(config));
process.env.TAINTGUARD_TOOL_REGISTRY = tmpConfig;

// 엔진이 판정마다 console.log를 찍으므로 결과 JSON 오염 방지 (run-mode.ts와 동일)
const realStdoutWrite = process.stdout.write.bind(process.stdout);
console.log = () => {};

const engine: any = await import(ENGINE);

type Outcome = "TP" | "FP" | "TN" | "FN";
function classify(expect: string, allowed: boolean): Outcome {
  if (expect === "block") return allowed ? "FN" : "TP";
  return allowed ? "TN" : "FP";
}

const records: any[] = [];
let sid = 0;
for (const sc of data.scenarios) {
  const sessionId = `adojo-${mode}-${sid++}`;
  let last: any = null;
  for (const step of sc.steps) {
    if (step.op === "record") {
      const args = step.args && Object.keys(step.args).length ? step.args : undefined;
      engine.recordToolResult(sessionId, step.tool, args, step.result);
    } else {
      const decision = engine.evaluateToolCall({
        sessionId,
        toolName: step.tool,
        args: step.args ?? {},
        argTags: [],
        timestamp: new Date().toISOString(),
      });
      last = { expect: step.expect, allowed: decision.allowed };
    }
  }
  if (last) {
    records.push({
      id: sc.id, suite: sc.suite, category: sc.category, tier: sc.tier,
      expect: last.expect, allowed: last.allowed, outcome: classify(last.expect, last.allowed),
    });
  }
}

const c = { tp: 0, fp: 0, tn: 0, fn: 0 };
for (const r of records) {
  if (r.outcome === "TP") c.tp++;
  else if (r.outcome === "FP") c.fp++;
  else if (r.outcome === "TN") c.tn++;
  else c.fn++;
}
const normal = c.tn + c.fp;
const attack = c.tp + c.fn;
const result = {
  mode,
  confusion: c,
  fpRate: normal ? c.fp / normal : 0,
  fnRate: attack ? c.fn / attack : 0,
  normal,
  attack,
  records,
};
realStdoutWrite(JSON.stringify(result) + "\n");
console.error(`[${mode}] normal=${normal} attack=${attack} FP=${c.fp}(${(result.fpRate * 100).toFixed(1)}%) FN=${c.fn}(${(result.fnRate * 100).toFixed(1)}%)`);
