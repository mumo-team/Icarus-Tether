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
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const mode = process.env.BENCH_MODE ?? "session";
if (mode !== "session" && mode !== "lineage") {
  console.error(`[bench] 알 수 없는 BENCH_MODE: ${mode}`);
  process.exit(2);
}

// 벤치 설정 선택 — BENCH_CONFIG(절대/상대 경로)가 있으면 그 설정으로, 없으면 기존 기본값.
// 확장 세트의 "도구 분류를 바꿔 다시 재는" 실행(B)이 기존 설정 파일을 건드리지 않고
// 별도 파일로 돌 수 있게 하는 유일한 스위치다.
const configPath = process.env.BENCH_CONFIG
  ? path.resolve(process.env.BENCH_CONFIG)
  : path.join(__dirname, "config.dev-bench.json");

// 설정에 판정 모드를 주입한 임시 config 작성 (원본 파일은 무수정)
const baseConfig = JSON.parse(readFileSync(configPath, "utf8"));
baseConfig.judgmentMode = mode;
// 바닥 완화 스위치 주입 — 확장 세트의 개선 전/후 비교용. 미지정이면 설정 파일 값(기본 "off").
// lineage 전용 규칙이라 session 모드 결과에는 영향이 없어야 한다(두 정책 비교 성립 조건).
if (process.env.BENCH_FALLBACK_RELAXATION) {
  baseConfig.fallbackRelaxation = process.env.BENCH_FALLBACK_RELAXATION;
}
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
//                    | ext(동결된 확장 세트 scenarios-ext.ts — 기존 세트와 별도 실행)
//                    | limits(동결된 한계 탐색 세트 scenarios-limits.ts — 565f11c)
const benchSet = process.env.BENCH_SET ?? "boundary";
if (benchSet !== "boundary" && benchSet !== "realistic" && benchSet !== "ext" && benchSet !== "limits") {
  console.error(`[bench] 알 수 없는 BENCH_SET: ${benchSet} (boundary | realistic | ext | limits)`);
  process.exit(2);
}

// 엔진 소스 위치 — BENCH_ENGINE_DIR이 있으면 그 디렉터리의 index.ts를 엔진으로 쓴다.
// "개선 전" 커밋을 git worktree로 받아 두고 그 src/를 가리키면, 시나리오·설정·하네스는
// 현재 것을 쓰면서 엔진만 옛 코드로 바꿔 같은 세트를 재는 비교가 성립한다.
// 미지정이면 기존과 같이 ../src (현재 엔진).
const engineDir = process.env.BENCH_ENGINE_DIR
  ? path.resolve(process.env.BENCH_ENGINE_DIR)
  : path.join(__dirname, "..", "src");
const engineEntry = pathToFileURL(path.join(engineDir, "index.ts")).href;
if (process.env.BENCH_ENGINE_DIR) console.error(`[bench] engine: ${engineDir}`);

// env 세팅 후 엔진·하네스·시나리오 로드 (config는 첫 evaluate에서 로드됨)
const engine = await import(engineEntry);
const { runAll } = await import("./harness.js");
const scenarios =
  benchSet === "realistic"
    ? (await import("./scenarios-realistic.js")).REALISTIC_SCENARIOS
    : benchSet === "ext"
      ? (await import("./scenarios-ext.js")).EXT_SCENARIOS
      : benchSet === "limits"
        ? (await import("./scenarios-limits.js")).EXT_LIMIT_SCENARIOS
        : (await import("./scenarios.js")).SCENARIOS;

const warmup = Number(process.env.BENCH_WARMUP ?? 1000);
const iters = Number(process.env.BENCH_ITERS ?? 10000);

const result = runAll(engine, scenarios, mode, { warmup, iters });

// 결과 JSON은 진짜 stdout으로 딱 한 줄
realStdoutWrite(JSON.stringify(result) + "\n");
