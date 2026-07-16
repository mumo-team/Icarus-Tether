/**
 * 벤치마크 오케스트레이터 — session·lineage 모드를 각각 하위 프로세스로 돌려
 * 결과를 모아 비교표를 출력한다.
 *
 * 실행: npm run bench --workspace=@icarus-tether/policy-engine
 */

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ModeResult, EvalRecord } from "./harness.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RUN_MODE = path.join(__dirname, "run-mode.ts");

type BenchSet = "boundary" | "realistic";

function runMode(mode: "session" | "lineage", set: BenchSet): ModeResult {
  const proc = spawnSync("npx", ["tsx", RUN_MODE], {
    env: { ...process.env, BENCH_MODE: mode, BENCH_SET: set },
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

function runSet(set: BenchSet): void {
  console.log(`\n████ ${SET_LABEL[set]} ████\n`);
  const session = runMode("session", set);
  const lineage = runMode("lineage", set);

  const totalNormals = session.records.filter((r) => r.category === "normal").length;
  const totalAttacks = session.records.filter((r) => r.category === "attack").length;

  // ---- 요약 표 ----
  const W = [14, 26, 26];
  console.log("═══ 정확도 요약 (같은 정답 대비 두 모드 채점) ═══");
  console.log(`정상 판정 지점 ${totalNormals}개 · 공격 판정 지점 ${totalAttacks}개`);
  if (set === "realistic") {
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

  if (set === "realistic") printTierBreakdown(session, lineage);

  // ---- 정직성 체크 ----
  console.log("═══ 정직성 체크 ═══");
  const warn: string[] = [];
  for (const r of [session, lineage]) {
    if (r.confusion.fp === 0)
      warn.push(`⚠ ${r.mode}: 오탐 0 — 분포에 어려운 정상(경계급)이 충분한지 의심할 것`);
    if (r.confusion.fn === 0)
      warn.push(`⚠ ${r.mode}: 미탐 0 — 분포에 교묘한 공격이 충분한지 의심할 것(또는 모두 잡음)`);
  }
  if (set === "realistic") {
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
  } else {
    console.log("  ⓘ 한계3: 합성 분포 — 비율은 코딩 에이전트 워크플로 추정이지 실측 트래픽이 아니다.");
    console.log("           절대 수치는 '추정'이며, 분포 가정은 README의 근거와 tier 분해로 검증할 것.");
  }
  console.log("  ⓘ 참고: session 모드의 오버헤드에는 섀도 로그용 계보 계산이 포함된다(mode!==lineage일 때).");
}

function main(): void {
  const setEnv = process.env.BENCH_SET ?? "both";
  if (setEnv !== "both" && setEnv !== "boundary" && setEnv !== "realistic") {
    console.error(`[bench] 알 수 없는 BENCH_SET: ${setEnv} (boundary | realistic | both)`);
    process.exit(2);
  }
  const sets: BenchSet[] = setEnv === "both" ? ["boundary", "realistic"] : [setEnv as BenchSet];
  console.log("dev 도메인 정확도 벤치마크 실행 중... (세트×모드별 하위 프로세스)");
  for (const set of sets) runSet(set);
}

main();
