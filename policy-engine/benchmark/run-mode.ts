/**
 * 한 판정 모드로 벤치마크를 실행하는 엔트리 (하위 프로세스).
 *
 * BENCH_MODE(session|lineage)를 받아, dev-bench config에 그 모드를 주입한 임시
 * 설정 파일을 만들고 TAINTGUARD_TOOL_REGISTRY로 가리킨 뒤 엔진을 동적 import한다.
 * (getPolicyConfig 캐시가 프로세스당 1회라, 모드별로 별도 프로세스가 필요하다.)
 *
 * 엔진은 판정 시 console.log(stdout)로 로그를 찍으므로, 결과 JSON이 섞이지 않게
 * console.log를 stderr로 우회한다. 결과 JSON은 stdout에 딱 한 줄만 쓴다.
 */

import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const mode = process.env.BENCH_MODE ?? "session";
if (mode !== "session" && mode !== "lineage") {
  console.error(`[bench] 알 수 없는 BENCH_MODE: ${mode}`);
  process.exit(2);
}

// dev-bench 설정에 판정 모드를 주입한 임시 config 작성
const baseConfig = JSON.parse(readFileSync(path.join(__dirname, "config.dev-bench.json"), "utf8"));
baseConfig.judgmentMode = mode;
const tmpDir = mkdtempSync(path.join(tmpdir(), "bench-config-"));
const tmpConfig = path.join(tmpDir, "config.json");
writeFileSync(tmpConfig, JSON.stringify(baseConfig));
process.env.TAINTGUARD_TOOL_REGISTRY = tmpConfig;

// 엔진은 판정마다 TrifectaEvent·[SHADOW]를 console.log로 찍는다. 벤치는 수만 회
// 평가하므로 이를 그대로 두면 (a) 결과 JSON(stdout)이 오염되고 (b) 오케스트레이터의
// 파이프 버퍼가 넘친다. 결과 JSON은 realStdoutWrite로만 쓰고, console.log는 무음 처리.
// (실제 오류는 console.error로 그대로 노출된다.)
const realStdoutWrite = process.stdout.write.bind(process.stdout);
console.log = () => {};

// 시나리오 세트 선택: boundary(기존 경계 케이스 세트, 기본) | realistic(현실 분포 세트)
const benchSet = process.env.BENCH_SET ?? "boundary";
if (benchSet !== "boundary" && benchSet !== "realistic") {
  console.error(`[bench] 알 수 없는 BENCH_SET: ${benchSet} (boundary | realistic)`);
  process.exit(2);
}

// env 세팅 후 엔진·하네스·시나리오 로드 (config는 첫 evaluate에서 로드됨)
const engine = await import("../src/index.js");
const { runAll } = await import("./harness.js");
const scenarios =
  benchSet === "realistic"
    ? (await import("./scenarios-realistic.js")).REALISTIC_SCENARIOS
    : (await import("./scenarios.js")).SCENARIOS;

const warmup = Number(process.env.BENCH_WARMUP ?? 1000);
const iters = Number(process.env.BENCH_ITERS ?? 10000);

const result = runAll(engine, scenarios, mode, { warmup, iters });

// 결과 JSON은 진짜 stdout으로 딱 한 줄
realStdoutWrite(JSON.stringify(result) + "\n");
