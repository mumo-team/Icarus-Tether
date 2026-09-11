/**
 * 한계 탐색 세트(scenarios-limits.ts, 565f11c 동결) 전용 리포트 생성기.
 *
 * 채점은 harness.ts가 기존 세트와 같은 로직(classify)으로 하고, 이 파일은 그 결과
 * 레코드를 조건별·축별로 "분해해서 보여주기"만 한다 — 판정·채점에 관여하지 않는다.
 * 수치와 id만 적고 해석은 쓰지 않는다.
 *
 * 분해 근거는 동결 파일이 공개한 메타데이터에서만 읽는다(무수정):
 *   축 1 — 제목의 "N자"(3/4/5) 표기와 형태(원문/base64/hex)
 *   축 2 — 각 evaluate 인자 문자열과 같은 시나리오 민감 record 값의 최장 공통 부분문자열 길이
 *   축 3 — 제목 태그 "[축3/변형명]"
 *   축 4 — id 범위 (4a L093~L110 / 4b L111~L124 / 4c L125~L128)
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ModeResult, EvalRecord } from "./harness.js";
import type { Scenario } from "./scenarios.js";
import { EXT_LIMIT_SCENARIOS } from "./scenarios-limits.js";
import { recId } from "./report-ext.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface LimitsCondition {
  key: "before" | "scan" | "all";
  label: string;
  /** 엔진 소스가 속한 체크아웃의 HEAD */
  commit?: string;
  /** 주입한 fallbackRelaxation 값 (개선 전은 "미주입") */
  relaxation: string;
  engineDir?: string;
  session: ModeResult;
  lineage: ModeResult;
}

export interface LimitsReportInput {
  conditions: LimitsCondition[];
  configPath: string;
  generatedAt: string;
}

// ---------------------------------------------------------------------------
// 공통
// ---------------------------------------------------------------------------

const pct = (n: number, d: number): string => (d ? `${((n / d) * 100).toFixed(1)}%` : "-");
const frac = (n: number, d: number): string => (d ? `${n}/${d} (${pct(n, d)})` : "-");

function mdTable(header: string[], rows: string[][]): string {
  const sep = header.map(() => "---");
  return [header, sep, ...rows].map((c) => `| ${c.join(" | ")} |`).join("\n");
}

const axisOf = (id: string): 1 | 2 | 3 | 4 => {
  const n = Number(id.slice(1));
  return n <= 30 ? 1 : n <= 58 ? 2 : n <= 92 ? 3 : 4;
};

const branchOf = (id: string): "4a" | "4b" | "4c" | "" => {
  const n = Number(id.slice(1));
  if (n < 93) return "";
  return n <= 110 ? "4a" : n <= 124 ? "4b" : "4c";
};

function loadSensitiveTools(configPath: string): Set<string> {
  const cfg = JSON.parse(readFileSync(path.join(__dirname, "..", configPath), "utf8"));
  return new Set<string>(cfg.sensitiveSourceTools ?? []);
}

/** 값 트리에서 문자열 토큰을 전부 모은다 (키 이름 포함 — L052류 "이름에 조각" 대응) */
function collectStrings(v: unknown, out: string[], withKeys: boolean): void {
  if (v == null) return;
  if (typeof v === "string") out.push(v);
  else if (typeof v === "number" || typeof v === "boolean") out.push(String(v));
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out, withKeys));
  else if (typeof v === "object") {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (withKeys) out.push(k);
      collectStrings(x, out, withKeys);
    }
  }
}

/** 최장 공통 부분문자열 길이 (코드포인트 단위) */
function lcsLen(a: string, b: string): number {
  const A = [...a];
  const B = [...b];
  let best = 0;
  let prev = new Int32Array(B.length + 1);
  for (let i = 1; i <= A.length; i++) {
    const cur = new Int32Array(B.length + 1);
    for (let j = 1; j <= B.length; j++) {
      if (A[i - 1] === B[j - 1]) {
        cur[j] = prev[j - 1] + 1;
        if (cur[j] > best) best = cur[j];
      }
    }
    prev = cur;
  }
  return best;
}

interface StepMeta {
  /** 축 2 — 이 evaluate 인자에 실린 민감값 조각의 길이 (민감 record 값과의 최장 공통 부분문자열) */
  fragmentLen: number;
}

/**
 * 시나리오별·evaluate별 메타데이터. 동결 파일을 읽기만 한다.
 * 키는 `${scenarioId}#${evalIndex}`.
 */
function computeStepMeta(sensitiveTools: Set<string>): Map<string, StepMeta> {
  const out = new Map<string, StepMeta>();
  for (const sc of EXT_LIMIT_SCENARIOS as Scenario[]) {
    const sensitiveVals: string[] = [];
    let evalIndex = 0;
    for (const st of sc.steps) {
      if (st.op === "record" && sensitiveTools.has(st.tool ?? "")) {
        collectStrings(st.result, sensitiveVals, true);
      } else if (st.op === "evaluate") {
        const argStrs: string[] = [];
        collectStrings(st.args, argStrs, true);
        let best = 0;
        for (const a of argStrs) for (const s of sensitiveVals) best = Math.max(best, lcsLen(a, s));
        out.set(`${sc.id}#${evalIndex}`, { fragmentLen: best });
        evalIndex++;
      }
    }
  }
  return out;
}

const titleOf = (id: string): string => EXT_LIMIT_SCENARIOS.find((s) => s.id === id)?.title ?? "";

/** 축 1 — 제목의 "N자"/"N자리" */
function secretLen(id: string): string {
  const m = titleOf(id).match(/(\d)자/);
  return m ? `${m[1]}자` : "?";
}
/** 축 1 — 형태 */
function secretForm(id: string): string {
  const t = titleOf(id);
  if (/base64/i.test(t)) return "base64";
  if (/hex/i.test(t)) return "hex";
  return "원문";
}
/** 축 3 — 제목 태그 */
function variantOf(id: string): string {
  const m = titleOf(id).match(/\[축3\/([^\]]+)\]/);
  return m ? m[1] : "?";
}

// ---------------------------------------------------------------------------
// 집계
// ---------------------------------------------------------------------------

const attacks = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.expect === "block");
const normals = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.expect === "pass");
const catAttacks = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.category === "attack");
const catNormals = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.category === "normal");
const fnOf = (rs: EvalRecord[]): EvalRecord[] => rs.filter((x) => x.outcome === "FN");
const fpOf = (rs: EvalRecord[]): EvalRecord[] => rs.filter((x) => x.outcome === "FP");
const ids = (rs: EvalRecord[]): string => (rs.length ? rs.map(recId).join(", ") : "-");

type Mode = "session" | "lineage";
const MODES: Mode[] = ["session", "lineage"];

/**
 * 버킷 분해표 — 행: 버킷, 열: 조건×모드. 셀은 miss/total(%).
 * kind=FN이면 expect=block 지점만, FP면 expect=pass 지점만 센다.
 */
function bucketTable(
  conds: LimitsCondition[],
  kind: "FN" | "FP",
  bucketOf: (r: EvalRecord) => string | null,
  bucketOrder?: string[]
): { table: string; idsPerCond: string[] } {
  const pick = (r: ModeResult): EvalRecord[] => (kind === "FN" ? attacks(r) : normals(r));
  const buckets = new Map<string, EvalRecord[]>();
  for (const r of pick(conds[0].session)) {
    const b = bucketOf(r);
    if (b === null) continue;
    if (!buckets.has(b)) buckets.set(b, []);
    buckets.get(b)!.push(r);
  }
  const order = bucketOrder
    ? [...bucketOrder.filter((b) => buckets.has(b)), ...[...buckets.keys()].filter((b) => !bucketOrder.includes(b))]
    : [...buckets.keys()].sort((a, b) => a.localeCompare(b, "ko", { numeric: true }));
  const header = ["버킷", "지점", ...conds.flatMap((c) => MODES.map((m) => `${c.label}·${m}`))];
  const rows: string[][] = [];
  const idsPerCond: string[] = [];
  const idLines: string[][] = conds.map(() => []);
  for (const b of order) {
    const members = buckets.get(b)!;
    const keys = new Set(members.map((r) => `${r.scenarioId}#${r.evalIndex ?? 0}`));
    const row = [b, `${members.length}`];
    conds.forEach((c, ci) => {
      for (const m of MODES) {
        const rs = pick(c[m]).filter((r) => keys.has(`${r.scenarioId}#${r.evalIndex ?? 0}`));
        const miss = rs.filter((r) => r.outcome === kind);
        row.push(frac(miss.length, rs.length));
        if (miss.length) idLines[ci].push(`  - ${b} · ${m}: ${ids(miss)}`);
      }
    });
    rows.push(row);
  }
  conds.forEach((c, ci) => {
    idsPerCond.push(`- ${c.label}\n${idLines[ci].length ? idLines[ci].join("\n") : "  - (없음)"}`);
  });
  return { table: mdTable(header, rows), idsPerCond };
}

// ---------------------------------------------------------------------------
// 리포트 본문
// ---------------------------------------------------------------------------

export function buildLimitsReport(input: LimitsReportInput): string {
  const conds = input.conditions;
  const sensitiveTools = loadSensitiveTools(input.configPath);
  const meta = computeStepMeta(sensitiveTools);
  const fragLen = (r: EvalRecord): number => meta.get(`${r.scenarioId}#${r.evalIndex ?? 0}`)?.fragmentLen ?? 0;
  const out: string[] = [];
  const p = (s = ""): void => void out.push(s);

  const first = conds[0].session;
  const nScen = new Set(first.records.map((r) => r.scenarioId)).size;

  p(`# 한계 탐색 세트(scenarios-limits.ts) 측정 결과`);
  p();
  p(`- 세트: \`benchmark/scenarios-limits.ts\` (커밋 565f11c 동결, 무수정) — 시나리오 ${nScen}개, 판정 지점 ${first.records.length}개 (block ${attacks(first).length} / pass ${normals(first).length})`);
  p(`- 설정: \`${input.configPath}\` (무수정, 세 조건 공통)`);
  p(`- 하네스: \`benchmark/run.ts --set limits\` — 시나리오·설정·하네스는 세 조건 모두 현재 것, 엔진 소스만 조건별로 다름`);
  p(`- 생성일: ${input.generatedAt}`);
  p();
  p(`## 조건`);
  p();
  p(
    mdTable(
      ["조건", "엔진 커밋", "fallbackRelaxation", "엔진 경로"],
      conds.map((c) => [c.label, c.commit ?? "?", c.relaxation, c.engineDir ? `\`${c.engineDir.replace(/\\/g, "/")}\`` : "현재 트리 `src/`"])
    )
  );
  p();

  // ---- 1. 조건별 요약 ----
  p(`## 1. 조건별 오탐·미탐 (session / lineage)`);
  p();
  p(`분모는 판정 지점의 정답(expect) 기준. category 기준 분모는 괄호 없이 별도 행.`);
  p();
  for (const c of conds) {
    p(`### ${c.label}`);
    p();
    const rows: string[][] = [];
    for (const m of MODES) {
      const r = c[m];
      rows.push([
        m,
        `${r.confusion.tp}`,
        `${r.confusion.fn}`,
        `${r.confusion.tn}`,
        `${r.confusion.fp}`,
        frac(r.confusion.fp, normals(r).length),
        frac(r.confusion.fn, attacks(r).length),
        frac(r.confusion.fp, catNormals(r).length),
        frac(r.confusion.fn, catAttacks(r).length),
      ]);
    }
    p(
      mdTable(
        ["모드", "TP", "FN", "TN", "FP", "오탐 FP/expect=pass", "미탐 FN/expect=block", "오탐 FP/category=normal", "미탐 FN/category=attack"],
        rows
      )
    );
    p();
    for (const m of MODES) {
      p(`- ${m} 미탐 id: ${ids(fnOf(c[m].records))}`);
      p(`- ${m} 오탐 id: ${ids(fpOf(c[m].records))}`);
    }
    p();
  }

  // ---- 2. 축별 미탐 분해 ----
  p(`## 2. 축별 미탐 분해`);
  p();
  p(`셀은 미탐/지점(%) — expect=block 지점만. 열은 조건·모드.`);
  p();

  const axisT = bucketTable(conds, "FN", (r) => `축 ${axisOf(r.scenarioId)}`, ["축 1", "축 2", "축 3", "축 4"]);
  p(`### 2.0 축 전체`);
  p();
  p(axisT.table);
  p();

  const a1len = bucketTable(conds, "FN", (r) => (axisOf(r.scenarioId) === 1 ? secretLen(r.scenarioId) : null), ["3자", "4자", "5자"]);
  p(`### 2.1 축 1 — 시크릿 길이별`);
  p();
  p(a1len.table);
  p();
  p(`미탐 id:`);
  p(a1len.idsPerCond.join("\n"));
  p();
  const a1form = bucketTable(conds, "FN", (r) => (axisOf(r.scenarioId) === 1 ? secretForm(r.scenarioId) : null), ["원문", "base64", "hex"]);
  p(`### 2.1b 축 1 — 형태별`);
  p();
  p(a1form.table);
  p();
  const a1cross = bucketTable(
    conds,
    "FN",
    (r) => (axisOf(r.scenarioId) === 1 ? `${secretLen(r.scenarioId)}·${secretForm(r.scenarioId)}` : null)
  );
  p(`### 2.1c 축 1 — 길이×형태`);
  p();
  p(a1cross.table);
  p();

  const a2 = bucketTable(conds, "FN", (r) => (axisOf(r.scenarioId) === 2 ? `${fragLen(r)}자` : null));
  p(`### 2.2 축 2 — 조각 길이별`);
  p();
  p(`조각 길이 = evaluate 인자 문자열과 같은 시나리오 민감 record 값(키 이름 포함)의 최장 공통 부분문자열 길이.`);
  p();
  p(a2.table);
  p();
  p(`미탐 id:`);
  p(a2.idsPerCond.join("\n"));
  p();
  {
    // 시나리오별 조각 길이 목록 (분해 근거 공개)
    const rows: string[][] = [];
    for (const sc of EXT_LIMIT_SCENARIOS) {
      if (axisOf(sc.id) !== 2) continue;
      const lens: string[] = [];
      let i = 0;
      for (const st of sc.steps) {
        if (st.op !== "evaluate") continue;
        const k = `${sc.id}#${i}`;
        lens.push(`${meta.get(k)?.fragmentLen ?? 0}${st.expect === "pass" ? "(pass)" : ""}`);
        i++;
      }
      rows.push([sc.id, lens.join(" / ")]);
    }
    p(`조각 길이 근거 (시나리오별, evaluate 순):`);
    p();
    p(mdTable(["id", "조각 길이(자)"], rows));
    p();
  }

  const a3 = bucketTable(conds, "FN", (r) => (axisOf(r.scenarioId) === 3 ? variantOf(r.scenarioId) : null));
  p(`### 2.3 축 3 — 변형 종류별`);
  p();
  p(a3.table);
  p();
  p(`미탐 id:`);
  p(a3.idsPerCond.join("\n"));
  p();

  const a4fn = bucketTable(conds, "FN", (r) => (axisOf(r.scenarioId) === 4 ? branchOf(r.scenarioId) : null), ["4b", "4c"]);
  p(`### 2.4 축 4 — 갈래별 미탐 (4b·4c, expect=block)`);
  p();
  p(a4fn.table);
  p();
  p(`미탐 id:`);
  p(a4fn.idsPerCond.join("\n"));
  p();

  // ---- 3. 오탐 분해 ----
  p(`## 3. 오탐 분해 (expect=pass 지점)`);
  p();
  const fpT = bucketTable(
    conds,
    "FP",
    (r) => (axisOf(r.scenarioId) === 4 ? "4a (L093~L110)" : `축 ${axisOf(r.scenarioId)} 안의 pass 스텝`),
    ["4a (L093~L110)"]
  );
  p(fpT.table);
  p();
  p(`오탐 id:`);
  p(fpT.idsPerCond.join("\n"));
  p();

  // ---- 4. 두 모드가 갈린 지점 ----
  p(`## 4. 두 모드가 갈린 지점 (조건별)`);
  p();
  for (const c of conds) {
    p(`### ${c.label}`);
    p();
    const rows: string[][] = [];
    c.session.records.forEach((s, i) => {
      const l = c.lineage.records[i];
      if (s.allowed === l.allowed) return;
      rows.push([
        recId(s),
        s.tool,
        s.expect,
        `${s.outcome}/${s.allowed ? "통과" : "차단"}`,
        `${l.outcome}/${l.allowed ? "통과" : "차단"}`,
      ]);
    });
    if (rows.length) p(mdTable(["지점", "도구", "정답", "session", "lineage"], rows));
    else p(`(없음)`);
    p();
  }

  // ---- 5. 세 조건 비교표 ----
  p(`## 5. 조건 비교표`);
  p();
  {
    const header = ["지표", ...conds.flatMap((c) => MODES.map((m) => `${c.label}·${m}`))];
    const rows: string[][] = [];
    const row = (label: string, f: (r: ModeResult) => string): void =>
      void rows.push([label, ...conds.flatMap((c) => MODES.map((m) => f(c[m])))]);
    row("오탐 FP/expect=pass", (r) => frac(r.confusion.fp, normals(r).length));
    row("미탐 FN/expect=block", (r) => frac(r.confusion.fn, attacks(r).length));
    row("오탐 FP/category=normal", (r) => frac(r.confusion.fp, catNormals(r).length));
    row("미탐 FN/category=attack", (r) => frac(r.confusion.fn, catAttacks(r).length));
    for (const ax of [1, 2, 3, 4] as const) {
      row(`축 ${ax} 미탐`, (r) => {
        const rs = attacks(r).filter((x) => axisOf(x.scenarioId) === ax);
        return frac(fnOf(rs).length, rs.length);
      });
    }
    row("4a 오탐", (r) => {
      const rs = normals(r).filter((x) => branchOf(x.scenarioId) === "4a");
      return frac(fpOf(rs).length, rs.length);
    });
    row("모드 갈린 지점", (r) => "");
    // 마지막 행은 조건 단위 값이라 모드 열 두 개에 같은 수를 적는다
    rows[rows.length - 1] = [
      "모드 갈린 지점",
      ...conds.flatMap((c) => {
        const n = c.session.records.filter((s, i) => s.allowed !== c.lineage.records[i].allowed).length;
        return [`${n}`, `${n}`];
      }),
    ];
    row("오버헤드 median", (r) => `${(r.overhead.medianNs / 1000).toFixed(3)}µs`);
    row("오버헤드 p95", (r) => `${(r.overhead.p95Ns / 1000).toFixed(3)}µs`);
    p(mdTable(header, rows));
  }
  p();

  // ---- 6. 조건 간 판정이 바뀐 지점 ----
  if (conds.length > 1) {
    p(`## 6. 조건 간 판정이 바뀐 지점`);
    p();
    for (let ci = 1; ci < conds.length; ci++) {
      const a = conds[ci - 1];
      const b = conds[ci];
      for (const m of MODES) {
        const rows: string[][] = [];
        a[m].records.forEach((ra, i) => {
          const rb = b[m].records[i];
          if (ra.allowed === rb.allowed) return;
          rows.push([recId(ra), ra.tool, ra.expect, `${ra.outcome}/${ra.allowed ? "통과" : "차단"}`, `${rb.outcome}/${rb.allowed ? "통과" : "차단"}`]);
        });
        p(`### ${a.label} → ${b.label} · ${m}`);
        p();
        if (rows.length) p(mdTable(["지점", "도구", "정답", a.label, b.label], rows));
        else p(`(없음)`);
        p();
      }
    }
  }

  return out.join("\n");
}
