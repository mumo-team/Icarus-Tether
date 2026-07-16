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

function runMode(mode: "session" | "lineage"): ModeResult {
  const proc = spawnSync("npx", ["tsx", RUN_MODE], {
    env: { ...process.env, BENCH_MODE: mode },
    encoding: "utf8",
    shell: process.platform === "win32", // Windows에서 npx 해석
    maxBuffer: 64 * 1024 * 1024, // 자식 로그가 많아도 버퍼 넘치지 않게
  });
  if (proc.status !== 0) {
    console.error(`[bench] ${mode} 모드 실행 실패 (exit ${proc.status})`);
    console.error(proc.stderr);
    process.exit(1);
  }
  // 결과 JSON은 stdout 마지막(유일) 줄
  const line = proc.stdout.trim().split("\n").filter(Boolean).pop() ?? "";
  try {
    return JSON.parse(line) as ModeResult;
  } catch {
    console.error(`[bench] ${mode} 결과 파싱 실패. stdout:\n${proc.stdout}\nstderr:\n${proc.stderr}`);
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

function main(): void {
  console.log("dev 도메인 정확도 벤치마크 실행 중... (모드별 하위 프로세스)\n");
  const session = runMode("session");
  const lineage = runMode("lineage");

  const totalNormals = session.records.filter((r) => r.category === "normal").length;
  const totalAttacks = session.records.filter((r) => r.category === "attack").length;

  // ---- 요약 표 ----
  const W = [14, 26, 26];
  console.log("═══ 정확도 요약 (같은 정답 대비 두 모드 채점) ═══");
  console.log(`정상 판정 지점 ${totalNormals}개 · 공격 판정 지점 ${totalAttacks}개\n`);
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

  // ---- 정직성 체크 ----
  console.log("═══ 정직성 체크 ═══");
  const warn: string[] = [];
  for (const r of [session, lineage]) {
    if (r.confusion.fp === 0) warn.push(`⚠ ${r.mode}: 오탐 0 — 정상 시나리오가 너무 쉬웠을 수 있음`);
    if (r.confusion.fn === 0) warn.push(`⚠ ${r.mode}: 미탐 0 — 공격 시나리오가 너무 쉬웠을 수 있음(또는 모두 잡음)`);
  }
  warn.forEach((w) => console.log("  " + w));
  console.log("  ⓘ 한계1: lineage의 오탐 감소는 sink 인자가 상류 데이터 내용을 담을 때만 발현된다");
  console.log("           (VALUE_MATCH). N6은 그 조건 미충족 시 lineage도 보수적으로 막는 것을 보여준다.");
  console.log("  ⓘ 한계2: 미분류 도구는 default-deny로 보수적 처리 → 잠재 오탐원.");
  console.log("  ⓘ 한계3: 합성 시나리오 10여 개 — 실트래픽 분포와 다르다. 절대 수치보다 모드 간 상대 비교로 해석.");
  console.log("  ⓘ 참고: session 모드의 오버헤드에는 섀도 로그용 계보 계산이 포함된다(mode!==lineage일 때).");
}

main();
