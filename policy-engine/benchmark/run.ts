/**
 * 벤치마크 오케스트레이터 — session·lineage 모드를 각각 하위 프로세스로 돌려
 * 결과를 모아 비교표를 출력한다.
 *
 * 실행: npm run bench --workspace=@icarus-tether/policy-engine
 */

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ModeResult, EvalRecord } from "./harness.js";
import { buildExtReport, printExtSummary } from "./report-ext.js";
import { buildLimitsReport, type LimitsCondition } from "./report-limits.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUN_MODE = path.join(__dirname, "run-mode.ts");

type BenchSet = "boundary" | "realistic" | "ext" | "limits";

function runMode(
  mode: "session" | "lineage",
  set: BenchSet,
  configPath?: string,
  relaxation?: string,
  engineDir?: string
): ModeResult {
  const proc = spawnSync("npx", ["tsx", RUN_MODE], {
    env: {
      ...process.env,
      BENCH_MODE: mode,
      BENCH_SET: set,
      // 설정 미지정이면 자식이 기존 기본값(config.dev-bench.json)을 쓴다.
      ...(configPath ? { BENCH_CONFIG: configPath } : { BENCH_CONFIG: "" }),
      // 바닥 완화 스위치 — ext/limits 세트에만 넘어온다. 빈 문자열이면 설정 파일 값(기본 off).
      BENCH_FALLBACK_RELAXATION: relaxation ?? "",
      // 엔진 소스 디렉터리 — "개선 전" 커밋의 worktree src/를 가리켜 옛 엔진으로 잰다. 빈 문자열이면 현재 엔진.
      BENCH_ENGINE_DIR: engineDir ?? "",
    },
    encoding: "utf8",
    shell: process.platform === "win32", // Windows에서 npx 해석
    maxBuffer: 64 * 1024 * 1024, // 자식 로그가 많아도 버퍼 넘치지 않게
  });
  if (proc.status !== 0) {
    console.error(`[bench] ${set}/${mode} 실행 실패 (exit ${proc.status})`);
    console.error(proc.stderr);
    process.exit(1);
  }
  // 결과 JSON은 stdout 마지막(유일) 줄
  const line = proc.stdout.trim().split("\n").filter(Boolean).pop() ?? "";
  try {
    return JSON.parse(line) as ModeResult;
  } catch {
    console.error(`[bench] ${set}/${mode} 결과 파싱 실패. stdout:\n${proc.stdout}\nstderr:\n${proc.stderr}`);
    process.exit(1);
  }
}

const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;
const us = (ns: number): string => `${(ns / 1000).toFixed(3)}µs`;

function pad(s: string, n: number): string {
  // 한글 폭 보정(대략): 한글은 2폭으로 계산
  const width = [...s].reduce((w, ch) => w + (ch.charCodeAt(0) > 0x2000 ? 2 : 1), 0);
  return s + " ".repeat(Math.max(0, n - width));
}

function line(cols: string[], widths: number[]): string {
  return "│ " + cols.map((c, i) => pad(c, widths[i])).join(" │ ") + " │";
}

const SET_LABEL: Record<BenchSet, string> = {
  boundary: "경계 케이스 세트 (모드 차이 증명용 — 절대 수치 아님)",
  realistic: "현실 분포 세트 (실운영 근사 — 절대 오탐률 추정용)",
  ext: "확장 세트 322 (동결 — 위협 모델 기반, 구현 미참조 생성)",
  limits: "한계 탐색 세트 112 (동결 565f11c — tag_all 기준, 구현 미참조 생성)",
};

/**
 * tier별 분해 — 현실 분포 세트 전용. "낮아진 오탐률이 쉬운 것만 넣어서가
 * 아니라 현실 분포라서"임을 계층 수치로 입증한다: easy(일상)와
 * boundary(아슬아슬)의 오탐, obvious(명백)와 subtle(교묘)의 미탐을 분리 표기.
 */
function printTierBreakdown(session: ModeResult, lineage: ModeResult): void {
  const W = [22, 22, 22];
  const tierRows: Array<{ label: string; tier: string; kind: "FP" | "FN" }> = [
    { label: "easy 정상 오탐", tier: "easy", kind: "FP" },
    { label: "boundary 정상 오탐", tier: "boundary", kind: "FP" },
    { label: "obvious 공격 미탐", tier: "obvious", kind: "FN" },
    { label: "subtle 공격 미탐", tier: "subtle", kind: "FN" },
  ];
  const cell = (r: ModeResult, tier: string, kind: "FP" | "FN"): string => {
    const inTier = r.records.filter((x) => x.tier === tier);
    const miss = inTier.filter((x) => x.outcome === kind).length;
    return inTier.length ? `${miss}/${inTier.length} (${((miss / inTier.length) * 100).toFixed(1)}%)` : "-";
  };
  console.log("═══ tier별 분해 (분포 정직성 — 어려운 계층이 실제로 포함돼 있고 거기서 틀린다) ═══");
  console.log(line(["계층", "session", "lineage"], W));
  console.log(line(["─".repeat(22), "─".repeat(22), "─".repeat(22)], W));
  for (const { label, tier, kind } of tierRows) {
    console.log(line([label, cell(session, tier, kind), cell(lineage, tier, kind)], W));
  }
  console.log("");
}

function runSet(
  set: BenchSet,
  opts: { configPath?: string; note?: string; relaxation?: string; engineDir?: string } = {}
): { session: ModeResult; lineage: ModeResult } {
  console.log(`\n████ ${SET_LABEL[set]}${opts.note ? ` — ${opts.note}` : ""} ████\n`);
  if (opts.configPath) console.log(`설정: ${opts.configPath}`);
  if (opts.relaxation) console.log(`바닥 완화: fallbackRelaxation=${opts.relaxation}`);
  if (opts.engineDir) console.log(`엔진: ${opts.engineDir}`);
  if (opts.configPath || opts.relaxation || opts.engineDir) console.log("");
  const session = runMode("session", set, opts.configPath, opts.relaxation, opts.engineDir);
  const lineage = runMode("lineage", set, opts.configPath, opts.relaxation, opts.engineDir);

  const totalNormals = session.records.filter((r) => r.category === "normal").length;
  const totalAttacks = session.records.filter((r) => r.category === "attack").length;

  // ---- 요약 표 ----
  const W = [14, 26, 26];
  console.log("═══ 정확도 요약 (같은 정답 대비 두 모드 채점) ═══");
  console.log(`정상 판정 지점 ${totalNormals}개 · 공격 판정 지점 ${totalAttacks}개`);
  if (set !== "boundary") {
    // 분포 요약 — 어려운 계층이 실제로 몇 개 들어있는지 투명하게 공개 (조작 방지)
    const count = (tier: string): number => session.records.filter((r) => r.tier === tier).length;
    console.log(
      `분포: 정상 = easy ${count("easy")} + boundary ${count("boundary")} · ` +
        `공격 = obvious ${count("obvious")} + subtle ${count("subtle")}`
    );
  }
  console.log("");
  console.log(line(["지표", "session (toy)", "lineage (real)"], W));
  console.log(line(["─".repeat(14), "─".repeat(26), "─".repeat(26)], W));
  const row = (label: string, s: string, l: string): void => console.log(line([label, s, l], W));
  row("정탐 TP", `${session.confusion.tp}`, `${lineage.confusion.tp}`);
  row("미탐 FN", `${session.confusion.fn}`, `${lineage.confusion.fn}`);
  row("정통 TN", `${session.confusion.tn}`, `${lineage.confusion.tn}`);
  row("오탐 FP", `${session.confusion.fp}`, `${lineage.confusion.fp}`);
  row("오탐률(FP/정상)", pct(session.fpRate), pct(lineage.fpRate));
  row("미탐률(FN/공격)", pct(session.fnRate), pct(lineage.fnRate));
  console.log("");

  // ---- 오버헤드 ----
  console.log("═══ 오버헤드 (evaluateToolCall 1회, 워밍업 후) ═══");
  console.log(line(["통계", "session", "lineage"], W));
  console.log(line(["─".repeat(14), "─".repeat(26), "─".repeat(26)], W));
  row("mean", us(session.overhead.meanNs), us(lineage.overhead.meanNs));
  row("median", us(session.overhead.medianNs), us(lineage.overhead.medianNs));
  row("p95", us(session.overhead.p95Ns), us(lineage.overhead.p95Ns));
  console.log(`(${session.overhead.samples.toLocaleString()}회 측정)\n`);

  // ---- 모드가 갈린 판정 지점 ----
  console.log("═══ 두 모드가 다르게 판정한 지점 (핵심) ═══");
  const byKey = new Map<string, { s: EvalRecord; l: EvalRecord }>();
  session.records.forEach((s, i) => byKey.set(`${s.scenarioId}#${i}`, { s, l: lineage.records[i] }));
  let anyDiff = false;
  for (const { s, l } of byKey.values()) {
    if (s.allowed === l.allowed) continue;
    anyDiff = true;
    const winner = s.outcome === "FP" || s.outcome === "FN" ? "lineage 승" : "session 승";
    console.log(
      `  ${s.scenarioId} (${s.tool}) 정답=${s.expect} · session=${s.outcome}/${s.allowed ? "통과" : "차단"} · ` +
        `lineage=${l.outcome}/${l.allowed ? "통과" : "차단"}  → ${winner}`
    );
  }
  if (!anyDiff) console.log("  (없음)");
  console.log("");

  if (set !== "boundary" && set !== "limits") printTierBreakdown(session, lineage);

  // ---- 정직성 체크 ----
  console.log("═══ 정직성 체크 ═══");
  const warn: string[] = [];
  for (const r of [session, lineage]) {
    if (r.confusion.fp === 0)
      warn.push(`⚠ ${r.mode}: 오탐 0 — 분포에 어려운 정상(경계급)이 충분한지 의심할 것`);
    if (r.confusion.fn === 0)
      warn.push(`⚠ ${r.mode}: 미탐 0 — 분포에 교묘한 공격이 충분한지 의심할 것(또는 모두 잡음)`);
  }
  if (set !== "boundary" && set !== "limits") {
    // 분포 자체의 조작 방지: 어려운 계층이 아예 빠졌으면 결과를 신뢰하면 안 된다
    if (!session.records.some((r) => r.tier === "boundary"))
      warn.push("⚠ 분포에 boundary 정상이 0개 — '쉬운 것만 넣은' 조작된 분포");
    if (!session.records.some((r) => r.tier === "subtle"))
      warn.push("⚠ 분포에 subtle 공격이 0개 — 미탐률이 공허함");
  }
  warn.forEach((w) => console.log("  " + w));
  console.log("  ⓘ 한계1: lineage의 오탐 감소는 sink 인자가 상류 데이터 내용을 담을 때만 발현된다");
  console.log("           (VALUE_MATCH). 그 근거가 없으면 lineage도 폴백으로 보수적으로 막는다.");
  console.log("  ⓘ 한계2: 미분류 도구는 default-deny로 보수적 처리 → 잠재 오탐원.");
  if (set === "boundary") {
    console.log("  ⓘ 한계3: 경계 케이스 고비중 합성 세트 — 절대 수치가 아니라 모드 간 상대 비교로 해석.");
  } else if (set === "ext") {
    console.log("  ⓘ 한계3: 322건은 독립 표본이 아니다 — 22가지 논리 유형의 변형이라 유형별로 읽어야 한다.");
    console.log("           (scenarios-ext.README.md '세트의 성질과 한계')");
  } else if (set === "limits") {
    console.log("  ⓘ 한계3: 경계 탐색 세트 — 절대 수치가 아니라 축별·조건별 분해로 읽는다 (scenarios-limits.README.md).");
  } else {
    console.log("  ⓘ 한계3: 합성 분포 — 비율은 코딩 에이전트 워크플로 추정이지 실측 트래픽이 아니다.");
    console.log("           절대 수치는 '추정'이며, 분포 가정은 README의 근거와 tier 분해로 검증할 것.");
  }
  console.log("  ⓘ 참고: session 모드의 오버헤드에는 섀도 로그용 계보 계산이 포함된다(mode!==lineage일 때).");
  return { session, lineage };
}

/**
 * 세트 선택 파싱 — CLI 플래그(`--set ext`)가 env(BENCH_SET)보다 우선한다.
 * 기본값은 기존과 같은 "both"(boundary+realistic) — ext는 기존 세트와 섞이지 않도록
 * 명시적으로 골라야만 실행된다.
 */
interface Args {
  setArg: string;
  out?: string;
  noReport: boolean;
  /** ext 세트에 쓸 대체 설정 파일 (미지정이면 config.dev-bench.json) */
  config?: string;
  /** 리포트 파일 이름표 — results-ext-<label>.md. 기본 A. --relax면 "-relax"가 붙는다 */
  label: string;
  /** 바닥 완화 스위치(fallbackRelaxation=scan-clean)를 ext 세트에 켠다 — 개선 전/후 비교용 */
  relax: boolean;
  /**
   * "개선 전" 엔진의 src 디렉터리 (git worktree로 받은 옛 커밋). limits 세트 전용.
   * 주어지면 [개선 전 / 스캔만(off) / 전부(scan-clean)] 세 조건을 한 실행에서 돌려 한 리포트에 쓴다.
   */
  engineOld?: string;
}

function parseArgs(argv: string[]): Args {
  let setArg = process.env.BENCH_SET ?? "both";
  let out: string | undefined;
  let config: string | undefined = process.env.BENCH_CONFIG || undefined;
  let label = "A";
  let noReport = false;
  let relax = false;
  let engineOld: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--relax") relax = true;
    else if (a === "--engine-old") engineOld = argv[++i];
    else if (a.startsWith("--engine-old=")) engineOld = a.slice("--engine-old=".length);
    else if (a === "--set" || a === "-s") setArg = argv[++i] ?? "";
    else if (a.startsWith("--set=")) setArg = a.slice("--set=".length);
    else if (a === "--out" || a === "-o") out = argv[++i];
    else if (a.startsWith("--out=")) out = a.slice("--out=".length);
    else if (a === "--config" || a === "-c") config = argv[++i];
    else if (a.startsWith("--config=")) config = a.slice("--config=".length);
    else if (a === "--label" || a === "-l") label = argv[++i] ?? "";
    else if (a.startsWith("--label=")) label = a.slice("--label=".length);
    else if (a === "--no-report") noReport = true;
    else {
      console.error(`[bench] 알 수 없는 인자: ${a}`);
      console.error(
        "사용법: npm run bench -- [--set boundary|realistic|ext|limits|both|all] [--config <path>] " +
          "[--label <이름>] [--relax] [--engine-old <src dir>] [--out <path>] [--no-report]"
      );
      process.exit(2);
    }
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(label)) {
    console.error(`[bench] --label은 파일명에 쓸 수 있는 문자만 허용한다: ${label}`);
    process.exit(2);
  }
  // 완화 실행은 이름표에 "-relax"를 붙여 끈 실행의 리포트를 덮어쓰지 않게 한다.
  if (relax) label = `${label}-relax`;
  return { setArg, out, noReport, config, label, relax, engineOld };
}

function gitHead(): string | undefined {
  const p = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
    encoding: "utf8",
    cwd: __dirname,
    shell: process.platform === "win32",
  });
  return p.status === 0 ? p.stdout.trim() : undefined;
}

const VALID_SETS = new Set(["boundary", "realistic", "ext", "limits", "both", "all"]);

const DEFAULT_CONFIG = path.join(__dirname, "config.dev-bench.json");

/**
 * 한계 탐색 세트(limits) 전용 흐름 — 세 조건을 한 실행에서 돌려 results-limits.md 한 파일에 쓴다.
 *   개선 전: --engine-old 의 옛 엔진, 완화 스위치 미주입(옛 config 로더는 그 키를 모른다)
 *   스캔만: 현재 엔진, fallbackRelaxation=off
 *   전부:   현재 엔진, fallbackRelaxation=scan-clean
 * --engine-old 가 없으면 현재 엔진으로 off/scan-clean 두 조건만 돈다.
 * 시나리오·설정·하네스는 세 조건 모두 현재 것이며 엔진 소스만 바뀐다.
 */
function mainLimits(args: Args): void {
  const configPath = args.config ? path.resolve(args.config) : DEFAULT_CONFIG;
  const relConfig = path.relative(path.join(__dirname, ".."), configPath).replace(/\\/g, "/");
  const engineOld = args.engineOld ? path.resolve(args.engineOld) : undefined;
  const conditions: LimitsCondition[] = [];
  if (engineOld) {
    const before = runSet("limits", { configPath, engineDir: engineOld, note: "조건: 개선 전 (bb0a2e9 엔진)" });
    conditions.push({ key: "before", label: "개선 전", commit: gitHeadAt(engineOld), relaxation: "미주입", engineDir: engineOld, ...before });
  }
  const scanOnly = runSet("limits", { configPath, relaxation: "off", note: "조건: 스캔만 (fallbackRelaxation=off)" });
  conditions.push({ key: "scan", label: "스캔만", commit: gitHead(), relaxation: "off", ...scanOnly });
  const all = runSet("limits", { configPath, relaxation: "scan-clean", note: "조건: 전부 (fallbackRelaxation=scan-clean)" });
  conditions.push({ key: "all", label: "전부", commit: gitHead(), relaxation: "scan-clean", ...all });

  if (args.noReport) return;
  const outPath = args.out ? path.resolve(args.out) : path.join(__dirname, "results-limits.md");
  const md = buildLimitsReport({
    conditions,
    configPath: relConfig,
    generatedAt: new Date().toISOString().slice(0, 10),
  });
  writeFileSync(outPath, md, "utf8");
  console.log(`[bench] 한계 탐색 세트 리포트 기록: ${outPath}`);
}

/** 주어진 디렉터리가 속한 git 체크아웃의 HEAD (worktree의 옛 커밋 확인용) */
function gitHeadAt(dir: string): string | undefined {
  const p = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
    encoding: "utf8",
    cwd: dir,
    shell: process.platform === "win32",
  });
  return p.status === 0 ? p.stdout.trim() : undefined;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const { setArg, out, noReport, config, label, relax } = args;
  const relaxation = relax ? "scan-clean" : undefined;
  if (!VALID_SETS.has(setArg)) {
    console.error(`[bench] 알 수 없는 세트: ${setArg} (boundary | realistic | ext | limits | both | all)`);
    process.exit(2);
  }
  if (args.engineOld && setArg !== "limits") {
    console.error("[bench] --engine-old는 limits 세트에만 적용된다. --set limits와 함께 쓸 것.");
    process.exit(2);
  }
  if (setArg === "limits") {
    if (relaxation) {
      console.error("[bench] limits 세트는 off/scan-clean 두 조건을 항상 함께 돈다. --relax는 쓰지 않는다.");
      process.exit(2);
    }
    console.log("한계 탐색 세트 벤치마크 실행 중... (조건×모드별 하위 프로세스)");
    mainLimits(args);
    return;
  }
  const sets: BenchSet[] =
    setArg === "both"
      ? ["boundary", "realistic"]
      : setArg === "all"
        ? ["boundary", "realistic", "ext"]
        : [setArg as BenchSet];

  // 대체 설정은 ext 세트에만 적용한다 — 기존 두 세트의 수치는 어떤 실행에서도
  // 같은 설정(config.dev-bench.json)으로 재현돼야 비교 기준이 된다.
  const extConfig = config ? path.resolve(config) : undefined;
  if ((extConfig || relaxation) && !sets.includes("ext")) {
    console.error("[bench] --config·--relax는 ext 세트에만 적용된다. --set ext와 함께 쓸 것.");
    process.exit(2);
  }

  console.log("dev 도메인 정확도 벤치마크 실행 중... (세트×모드별 하위 프로세스)");
  const results = new Map<BenchSet, { session: ModeResult; lineage: ModeResult }>();
  for (const set of sets) {
    results.set(
      set,
      set === "ext"
        ? runSet(set, { configPath: extConfig, relaxation, note: `실행 ${label}` })
        : runSet(set)
    );
  }

  // ---- 확장 세트 리포트 ----
  const ext = results.get("ext");
  if (!ext) return;

  const relConfig = path
    .relative(path.join(__dirname, ".."), extConfig ?? DEFAULT_CONFIG)
    .replace(/\\/g, "/");
  printExtSummary({ ext, configPath: relConfig });
  if (noReport) return;

  // 비교 기준을 같은 실행에서 뽑는다 — 리포트의 여러 열이 서로 다른 시점의 측정이
  // 되지 않도록. 기존 81개 세트는 항상 기본 설정으로, 대체 설정 실행이면 기본 설정의
  // 확장 세트 결과(기준선)도 함께 돌린다.
  const realistic = results.get("realistic") ?? runSet("realistic");
  // 기준선(실행 A)도 같은 완화 스위치로 돌린다 — 리포트의 A/B 열이 같은 규칙 아래 비교되게.
  const extBaseline = extConfig
    ? runSet("ext", { note: "기준 설정 (비교용)", relaxation })
    : undefined;

  const outPath = out ? path.resolve(out) : path.join(__dirname, `results-ext-${label}.md`);
  const md = buildExtReport({
    ext,
    extBaseline,
    realistic,
    configPath: relConfig,
    baselineConfigPath: path
      .relative(path.join(__dirname, ".."), DEFAULT_CONFIG)
      .replace(/\\/g, "/"),
    label,
    relaxation,
    commit: gitHead(),
    generatedAt: new Date().toISOString().slice(0, 10),
  });
  writeFileSync(outPath, md, "utf8");
  console.log(`[bench] 확장 세트 리포트 기록: ${outPath}`);
}

main();
