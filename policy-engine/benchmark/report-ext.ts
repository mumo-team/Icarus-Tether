/**
 * 확장 세트(scenarios-ext.ts) 전용 리포트 생성기.
 *
 * 채점은 harness.ts가 기존 세트와 완전히 같은 로직(classify)으로 하고, 이 파일은
 * 그 결과 레코드를 "분해해서 보여주기"만 한다 — 판정·채점에 일절 관여하지 않는다.
 *
 * 분해 축:
 *   - tier(easy/boundary/obvious/subtle)
 *   - ★ 싱크 도구를 실제로 호출한 정상 / 중립 도구만 평가하는 정상
 *   - 유출 형태(원문·base64·hex·URL·공백삽입·분할·필드위장·요약은닉·정화흉내·역순·다중전송)
 *   - 미등록 도구(default-deny) 여부
 *
 * 도구 분류와 유출 형태는 scenarios-ext.ts를 수정하지 않고, 그 세트가 공개한
 * 메타데이터(도구 이름 목록 · 시나리오 제목)에서만 끌어온다.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ModeResult, EvalRecord } from "./harness.js";
import type { Scenario } from "./scenarios.js";
import { EXT_SCENARIOS } from "./scenarios-ext.js";
import { detectSecrets } from "../src/secret-detection.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// 확장 세트의 도구 분류 (scenarios-ext.README.md "사용한 도구 목록과 분류 의도")
// ---------------------------------------------------------------------------

/** 외부 싱크 — 전송/게시/설치/외부 쓰기. 정상 시나리오 중 이 도구를 호출한 것만이
 *  "정책이 실제로 막을 기회가 있었던" 정상이다. */
export const EXT_SINK_TOOLS = new Set([
  "http_post",
  "push_to_remote",
  "install_package",
  "send_email",
  "create_calendar_invite",
  "crm_webhook_post",
  "crm_export_report",
  "post_summary_to_slack",
  "deploy_service",
  "upload_report",
]);

/** 중립 — 소스도 싱크도 아닌 내부 작업/안전한 로컬 쓰기 (연쇄 노이즈) */
export const EXT_NEUTRAL_TOOLS = new Set([
  "run_tests",
  "format_code",
  "git_status",
  "list_files",
  "search_contacts",
  "read_email_draft",
  "list_folders",
  "list_free_slots",
  "get_timezone",
  "lookup_account_owner",
  "count_open_tickets",
  "save_local_note",
  "word_count",
  "restart_service",
  "check_health",
  "write_local_csv",
  "describe_schema",
]);

/** 민감 소스 — 값에 비밀/PII/내부 기밀이 담긴다고 간주 */
export const EXT_SENSITIVE_TOOLS = new Set([
  "read_env_file",
  "read_secrets",
  "get_db_credentials",
  "read_internal_doc",
  "get_deploy_config",
  "read_internal_memo",
  "get_smtp_credentials",
  "read_private_notes",
  "read_meeting_notes",
  "query_customer_db",
  "query_analytics_db",
]);

const DEFAULT_CONFIG = path.join(__dirname, "config.dev-bench.json");

function loadConfig(configPath?: string): Record<string, any> {
  return JSON.parse(readFileSync(configPath ? path.resolve(configPath) : DEFAULT_CONFIG, "utf8"));
}

/**
 * 설정에 등록된 도구 = 엔진이 성질을 아는 도구 (index.ts isClassifiedTool과 같은 기준).
 * ★ config.ts는 신형 `outboundSinkTools`(배열)와 구형 `sinks`(맵)를 하나의 sinks 맵으로
 * 병합한다(config.ts:296-318). 그래서 여기서도 둘 다 봐야 엔진과 같은 집합이 된다 —
 * outboundSinkTools를 빠뜨리면 http_post 같은 등록 싱크가 "미등록"으로 잘못 집계된다.
 */
function loadRegisteredTools(configPath?: string): Set<string> {
  const cfg = loadConfig(configPath);
  return new Set<string>([
    ...(cfg.sensitiveSourceTools ?? []),
    ...(cfg.untrustedSourceTools ?? []),
    ...(cfg.outboundSinkTools ?? []),
    ...Object.keys(cfg.sinks ?? {}),
    ...(cfg.destructiveTools ?? []),
  ]);
}

/**
 * 시나리오별 "엔진 입력 사실" — 판정이 아니라 입력의 성질만 계산한다.
 *  - sensitiveTagged: 그 세션의 민감값에 SENSITIVE 태그가 붙을 근거가 있는가
 *    (설정의 sensitiveSourceTools 등록 = 출처 기반 1순위, 또는 secretDetection이
 *     그 값에서 비밀을 찾는 내용 기반 2·3순위)
 *  - hasRegisteredUntrusted: 설정에 등록된 비신뢰 소스를 실제로 읽었는가
 *  - hasUnregisteredRecord: 미등록 도구의 결과를 기록했는가 (default-deny로 U가 붙는 경로)
 */
export interface ScenarioFacts {
  sensitiveTagged: boolean;
  bySourceRegistration: boolean;
  byContentDetection: boolean;
  hasRegisteredUntrusted: boolean;
  hasUnregisteredRecord: boolean;
}

function computeScenarioFacts(configPath?: string): Map<string, ScenarioFacts> {
  const cfg = loadConfig(configPath);
  const sens = new Set<string>(cfg.sensitiveSourceTools ?? []);
  const untr = new Set<string>(cfg.untrustedSourceTools ?? []);
  const registered = loadRegisteredTools(configPath);
  const facts = new Map<string, ScenarioFacts>();
  for (const sc of EXT_SCENARIOS as Scenario[]) {
    const recordSteps = sc.steps.filter((s) => s.op === "record");
    const sensSteps = recordSteps.filter((s) => EXT_SENSITIVE_TOOLS.has(s.tool ?? ""));
    const bySourceRegistration = sensSteps.some((s) => sens.has(s.tool ?? ""));
    const byContentDetection = sensSteps.some(
      (s) => detectSecrets(String(s.result ?? ""), cfg.secretDetection).length > 0
    );
    facts.set(sc.id, {
      sensitiveTagged: bySourceRegistration || byContentDetection,
      bySourceRegistration,
      byContentDetection,
      hasRegisteredUntrusted: recordSteps.some((s) => untr.has(s.tool ?? "")),
      hasUnregisteredRecord: recordSteps.some((s) => !registered.has(s.tool ?? "")),
    });
  }
  return facts;
}

// ---------------------------------------------------------------------------
// 유출 형태 — 시나리오 제목에서 추출 (공격 시나리오만 의미 있음)
// ---------------------------------------------------------------------------

const LEAK_FORMS: Array<{ key: string; label: string; match: (t: string) => boolean }> = [
  { key: "raw", label: "원문 그대로", match: (t) => t.includes("원문 전송") },
  { key: "base64", label: "base64 인코딩", match: (t) => t.includes("base64") },
  { key: "hex", label: "hex 인코딩", match: (t) => t.includes("hex") },
  { key: "url", label: "URL 인코딩", match: (t) => t.includes("URL 인코딩") },
  { key: "space", label: "공백 삽입", match: (t) => t.includes("공백 삽입") },
  { key: "split", label: "두 호출로 분할", match: (t) => t.includes("두 호출로 분할") },
  { key: "field", label: "필드 위장", match: (t) => t.includes("필드로 위장") },
  { key: "summary", label: "요약문 속 은닉", match: (t) => t.includes("요약문 속에") },
  { key: "fakeSanitize", label: "정화 흉내 후 재유출", match: (t) => t.includes("정화 선언 후") },
  { key: "reverse", label: "역순 등 변형", match: (t) => t.includes("역순") },
  { key: "multi", label: "다중 전송 중 하나만", match: (t) => t.includes("다중 전송 중 하나만") },
];

export function leakForm(title: string | undefined): string {
  if (!title) return "미분류";
  for (const f of LEAK_FORMS) if (f.match(title)) return f.label;
  return "미분류";
}

/** 정상 시나리오의 논리 유형 — 제목에서 도메인 접두사를 뗀 나머지 */
function normalForm(title: string | undefined): string {
  if (!title) return "미분류";
  const i = title.indexOf(": ");
  return i >= 0 ? title.slice(i + 2) : title;
}

// ---------------------------------------------------------------------------
// 집계 헬퍼
// ---------------------------------------------------------------------------

export interface Bucket {
  total: number;
  miss: number; // 정상 버킷이면 FP, 공격 버킷이면 FN
}

const rate = (b: Bucket): string =>
  b.total ? `${b.miss}/${b.total} (${((b.miss / b.total) * 100).toFixed(1)}%)` : "-";

function bucket(records: EvalRecord[], kind: "FP" | "FN"): Bucket {
  return { total: records.length, miss: records.filter((r) => r.outcome === kind).length };
}

/**
 * ★ 분모는 시나리오 category가 아니라 판정 지점의 정답(expect)으로 잡는다.
 * 확장 세트의 "다중 전송 중 하나만 유출" 공격 시나리오는 한 시나리오 안에 정답이
 * pass인 전송과 block인 전송을 함께 갖는다(category=attack, expect=pass인 지점 7개).
 * 채점(harness.classify)은 원래부터 expect 기준이므로 FP/FN 수는 그대로고, 비율의
 * 분모만 정답 기준으로 맞춘 것이다. category 기준 분모의 수치도 리포트에 함께 싣는다.
 */
const normals = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.expect === "pass");
const attacks = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.expect === "block");
const catNormals = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.category === "normal");
const catAttacks = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.category === "attack");

/** 레코드 식별자 — 한 시나리오에 evaluate가 여럿이면 #n을 붙인다 */
export function recId(r: EvalRecord): string {
  return (r.evalIndex ?? 0) > 0 ? `${r.scenarioId}#${(r.evalIndex ?? 0) + 1}` : r.scenarioId;
}

function mdTable(header: string[], rows: string[][]): string {
  const sep = header.map(() => "---");
  return [header, sep, ...rows].map((c) => `| ${c.join(" | ")} |`).join("\n");
}

// ---------------------------------------------------------------------------
// 리포트 본문
// ---------------------------------------------------------------------------

export interface ExtReportInput {
  ext: { session: ModeResult; lineage: ModeResult };
  /** 같은 확장 세트를 기본 설정으로 돌린 결과 — 설정을 바꾼 실행의 비교 기준(실행 A) */
  extBaseline?: { session: ModeResult; lineage: ModeResult };
  /** 기존 81개 세트(realistic) — 마지막 비교표용 */
  realistic?: { session: ModeResult; lineage: ModeResult };
  /** 이 실행이 쓴 설정 파일 (패키지 루트 기준 상대경로) */
  configPath?: string;
  /** 기준선 실행이 쓴 설정 파일 */
  baselineConfigPath?: string;
  /** 실행 이름표 (A/B …) */
  label?: string;
  /** ext 세트에 주입한 바닥 완화 스위치 값 (미지정 = 설정 파일 기본 "off") */
  relaxation?: string;
  commit?: string;
  generatedAt?: string;
}

export function buildExtReport(input: ExtReportInput): string {
  const { ext, extBaseline, realistic } = input;
  const label = input.label ?? "A";
  const S = ext.session;
  const L = ext.lineage;
  // ★ 등록 여부·민감 태그 근거는 "이 실행이 쓴 설정" 기준으로 계산한다.
  const registered = loadRegisteredTools(input.configPath && path.join(__dirname, "..", input.configPath));
  const facts = computeScenarioFacts(input.configPath && path.join(__dirname, "..", input.configPath));
  const out: string[] = [];

  const p = (s = ""): void => void out.push(s);

  p(`# 확장 세트(scenarios-ext.ts) 측정 결과 — 실행 ${label}`);
  p();
  p(`- 세트: \`benchmark/scenarios-ext.ts\` (커밋 bb0a2e9 동결, 무수정) — 시나리오 322개`);
  p(`- 설정: \`${input.configPath ?? "benchmark/config.dev-bench.json"}\` (무수정)`);
  p(
    `- 바닥 완화 스위치: \`fallbackRelaxation=${input.relaxation ?? "off"}\`` +
      (input.relaxation ? " (ext 세트에만 주입 · lineage 전용 규칙)" : " (설정 파일 기본값)")
  );
  {
    const baseLabel = label.replace(/-relax$/, "");
    const cfgFlag =
      input.configPath && input.configPath !== input.baselineConfigPath
        ? ` --config ${input.configPath}`
        : "";
    const labelFlag = cfgFlag || input.relaxation ? ` --label ${baseLabel}` : "";
    const relaxFlag = input.relaxation ? " --relax" : "";
    p(`- 재현: \`npm run bench -- --set ext${cfgFlag}${labelFlag}${relaxFlag}\``);
  }
  if (input.commit) p(`- 측정 시점 HEAD: \`${input.commit}\``);
  if (input.generatedAt) p(`- 생성: ${input.generatedAt}`);
  p();

  // ---- 1. 전체 ----
  p("## 1. 전체 (모드별)");
  p();
  p(
    "분모는 판정 지점의 정답(`expect`) 기준이다. 확장 세트에는 시나리오 category가 " +
      `attack이면서 정답이 pass인 판정 지점이 ${catAttacks(S).filter((r) => r.expect === "pass").length}개 있다` +
      "(\"다중 전송 중 하나만 인코딩 유출\" 유형의 안전한 전송). " +
      "채점(TP/FP/TN/FN) 자체는 기존 하네스와 동일한 `expect` 기준이다."
  );
  p();
  const nS = normals(S).length;
  const aS = attacks(S).length;
  const fpr = (m: ModeResult): string => `${((m.confusion.fp / normals(m).length) * 100).toFixed(1)}%`;
  const fnr = (m: ModeResult): string => `${((m.confusion.fn / attacks(m).length) * 100).toFixed(1)}%`;
  p(
    mdTable(
      ["지표", "session", "lineage"],
      [
        ["판정 지점 총계", `${S.records.length}`, `${L.records.length}`],
        ["정상 판정 지점 (expect=pass)", `${nS}`, `${normals(L).length}`],
        ["공격 판정 지점 (expect=block)", `${aS}`, `${attacks(L).length}`],
        ["정탐 TP", `${S.confusion.tp}`, `${L.confusion.tp}`],
        ["정통 TN", `${S.confusion.tn}`, `${L.confusion.tn}`],
        ["**오탐 FP**", `**${S.confusion.fp}**`, `**${L.confusion.fp}**`],
        ["**오탐률 FP/정상**", `**${fpr(S)}**`, `**${fpr(L)}**`],
        ["**미탐 FN**", `**${S.confusion.fn}**`, `**${L.confusion.fn}**`],
        ["**미탐률 FN/공격**", `**${fnr(S)}**`, `**${fnr(L)}**`],
      ]
    )
  );
  p();
  p("참고 — 시나리오 category 기준으로 나눈 비율(하네스 기본값):");
  p();
  p(
    mdTable(
      ["지표", "session", "lineage"],
      [
        ["category=normal 지점", `${catNormals(S).length}`, `${catNormals(L).length}`],
        ["category=attack 지점", `${catAttacks(S).length}`, `${catAttacks(L).length}`],
        ["오탐률 FP/category=normal", `${(S.fpRate * 100).toFixed(1)}%`, `${(L.fpRate * 100).toFixed(1)}%`],
        ["미탐률 FN/category=attack", `${(S.fnRate * 100).toFixed(1)}%`, `${(L.fnRate * 100).toFixed(1)}%`],
      ]
    )
  );
  p();

  // ---- 2. tier별 ----
  p("## 2. tier별 분해");
  p();
  const tierRows = [
    { tier: "easy", kind: "FP" as const, label: "easy 정상 오탐" },
    { tier: "boundary", kind: "FP" as const, label: "boundary 정상 오탐" },
    { tier: "obvious", kind: "FN" as const, label: "obvious 공격 미탐" },
    { tier: "subtle", kind: "FN" as const, label: "subtle 공격 미탐" },
  ];
  const tierRecs = (m: ModeResult, tier: string, kind: "FP" | "FN"): EvalRecord[] =>
    m.records.filter((r) => r.tier === tier && r.expect === (kind === "FP" ? "pass" : "block"));
  p(
    mdTable(
      ["계층", "판정 지점", "session", "lineage"],
      tierRows.map(({ tier, kind, label }) => {
        const bs = bucket(tierRecs(S, tier, kind), kind);
        const bl = bucket(tierRecs(L, tier, kind), kind);
        return [label, `${bs.total}`, rate(bs), rate(bl)];
      })
    )
  );
  p();

  // ---- 3. 싱크 호출 정상 ----
  p("## 3. ★ 싱크 도구를 실제로 호출한 정상만 (오탐률)");
  p();
  p(
    "중립 도구만 평가하는 정상은 정책이 막을 기회 자체가 없으므로 분리해 집계한다. " +
      "싱크 도구 목록은 `scenarios-ext.README.md`의 분류 의도를 따른다."
  );
  p();
  const sinkNormalS = normals(S).filter((r) => EXT_SINK_TOOLS.has(r.tool));
  const sinkNormalL = normals(L).filter((r) => EXT_SINK_TOOLS.has(r.tool));
  const otherNormalS = normals(S).filter((r) => !EXT_SINK_TOOLS.has(r.tool));
  const otherNormalL = normals(L).filter((r) => !EXT_SINK_TOOLS.has(r.tool));
  p(
    mdTable(
      ["구분", "판정 지점", "session 오탐", "lineage 오탐"],
      [
        [
          "★ 싱크 도구 호출 정상",
          `${sinkNormalS.length}`,
          rate(bucket(sinkNormalS, "FP")),
          rate(bucket(sinkNormalL, "FP")),
        ],
        [
          "중립 도구만 평가하는 정상",
          `${otherNormalS.length}`,
          rate(bucket(otherNormalS, "FP")),
          rate(bucket(otherNormalL, "FP")),
        ],
        ["정상 판정 지점 전체", `${nS}`, rate(bucket(normals(S), "FP")), rate(bucket(normals(L), "FP"))],
        [
          "└ 그중 category=normal 시나리오의 싱크 호출",
          `${sinkNormalS.filter((r) => r.category === "normal").length}`,
          rate(bucket(sinkNormalS.filter((r) => r.category === "normal"), "FP")),
          rate(bucket(sinkNormalL.filter((r) => r.category === "normal"), "FP")),
        ],
        [
          "└ 그중 category=attack 시나리오의 안전한 전송",
          `${sinkNormalS.filter((r) => r.category === "attack").length}`,
          rate(bucket(sinkNormalS.filter((r) => r.category === "attack"), "FP")),
          rate(bucket(sinkNormalL.filter((r) => r.category === "attack"), "FP")),
        ],
      ]
    )
  );
  p();
  p("### 3-1. 싱크 호출 정상의 논리 유형별 오탐");
  p();
  {
    const forms = [...new Set(sinkNormalS.map((r) => normalForm(r.title)))].sort();
    p(
      mdTable(
        ["논리 유형", "판정 지점", "session 오탐", "lineage 오탐"],
        forms.map((f) => {
          const bs = bucket(sinkNormalS.filter((r) => normalForm(r.title) === f), "FP");
          const bl = bucket(sinkNormalL.filter((r) => normalForm(r.title) === f), "FP");
          return [f, `${bs.total}`, rate(bs), rate(bl)];
        })
      )
    );
  }
  p();

  // ---- 4. 유출 형태별 미탐 ----
  p("## 4. 유출 형태별 미탐 분해");
  p();
  {
    const forms = [...new Set(attacks(S).map((r) => leakForm(r.title)))];
    const order = LEAK_FORMS.map((f) => f.label).filter((l) => forms.includes(l));
    const rest = forms.filter((f) => !order.includes(f));
    p(
      mdTable(
        ["유출 형태", "공격 판정 지점", "session 미탐", "lineage 미탐"],
        [...order, ...rest].map((f) => {
          const bs = bucket(attacks(S).filter((r) => leakForm(r.title) === f), "FN");
          const bl = bucket(attacks(L).filter((r) => leakForm(r.title) === f), "FN");
          return [f, `${bs.total}`, rate(bs), rate(bl)];
        })
      )
    );
  }
  p();

  p("### 4-1. 공격 판정 지점 × 민감값에 SENSITIVE 태그가 붙을 근거의 유무");
  p();
  p(
    "근거 = 설정 `sensitiveSourceTools`에 그 민감 소스 도구가 등록됨(출처 기반) " +
      "또는 `secretDetection`이 그 민감값에서 비밀을 찾음(내용 기반). 시나리오 정의 입력만으로 계산한 값이며 판정 결과가 아니다."
  );
  p();
  {
    const rowsOf = (m: ModeResult): string[][] => {
      const combos: Array<[string, (f: ScenarioFacts) => boolean]> = [
        ["출처 등록 O · 내용 탐지 O", (f) => f.bySourceRegistration && f.byContentDetection],
        ["출처 등록 O · 내용 탐지 X", (f) => f.bySourceRegistration && !f.byContentDetection],
        ["출처 등록 X · 내용 탐지 O", (f) => !f.bySourceRegistration && f.byContentDetection],
        ["출처 등록 X · 내용 탐지 X", (f) => !f.bySourceRegistration && !f.byContentDetection],
      ];
      return combos.map(([label, pred]) => {
        const rs = attacks(m).filter((r) => pred(facts.get(r.scenarioId)!));
        const fn = rs.filter((r) => r.outcome === "FN").length;
        return [label, `${rs.length}`, `${rs.length - fn}`, `${fn}`];
      });
    };
    p("session:");
    p();
    p(mdTable(["민감 태그 근거", "공격 판정 지점", "정탐 TP", "미탐 FN"], rowsOf(S)));
    p();
    p("lineage:");
    p();
    p(mdTable(["민감 태그 근거", "공격 판정 지점", "정탐 TP", "미탐 FN"], rowsOf(L)));
  }
  p();

  // ---- 5. 미등록 도구 default-deny ----
  p("## 5. 미등록 도구 default-deny 오탐");
  p();
  p(
    `\`${input.configPath ?? "benchmark/config.dev-bench.json"}\`의 \`sensitiveSourceTools\`·` +
      "`untrustedSourceTools`·`outboundSinkTools`·`sinks`·`destructiveTools` 어디에도 없는 " +
      "도구를 미등록으로 센다(config.ts:296-318이 outboundSinkTools와 sinks를 한 맵으로 병합한다)."
  );
  p();
  const unregS = normals(S).filter((r) => !registered.has(r.tool));
  const unregL = normals(L).filter((r) => !registered.has(r.tool));
  const regS = normals(S).filter((r) => registered.has(r.tool));
  const regL = normals(L).filter((r) => registered.has(r.tool));
  p(
    mdTable(
      ["구분", "정상 판정 지점", "session 오탐", "lineage 오탐"],
      [
        ["미등록 도구 호출", `${unregS.length}`, rate(bucket(unregS, "FP")), rate(bucket(unregL, "FP"))],
        ["등록 도구 호출", `${regS.length}`, rate(bucket(regS, "FP")), rate(bucket(regL, "FP"))],
      ]
    )
  );
  p();
  p("### 5-1. 미등록 오탐의 도구 성격별 분해");
  p();
  const unregSink = (rs: EvalRecord[]): EvalRecord[] => rs.filter((r) => EXT_SINK_TOOLS.has(r.tool));
  const unregNeutral = (rs: EvalRecord[]): EvalRecord[] =>
    rs.filter((r) => EXT_NEUTRAL_TOOLS.has(r.tool));
  const unregOther = (rs: EvalRecord[]): EvalRecord[] =>
    rs.filter((r) => !EXT_SINK_TOOLS.has(r.tool) && !EXT_NEUTRAL_TOOLS.has(r.tool));
  p(
    mdTable(
      ["미등록 도구 성격", "정상 판정 지점", "session 오탐", "lineage 오탐"],
      [
        [
          "미등록 + 싱크 성격",
          `${unregSink(unregS).length}`,
          rate(bucket(unregSink(unregS), "FP")),
          rate(bucket(unregSink(unregL), "FP")),
        ],
        [
          "미등록 + 중립 성격",
          `${unregNeutral(unregS).length}`,
          rate(bucket(unregNeutral(unregS), "FP")),
          rate(bucket(unregNeutral(unregL), "FP")),
        ],
        [
          "미등록 + 그 외",
          `${unregOther(unregS).length}`,
          rate(bucket(unregOther(unregS), "FP")),
          rate(bucket(unregOther(unregL), "FP")),
        ],
      ]
    )
  );
  p();
  p("### 5-2. 오탐에서 미등록 도구가 차지하는 비중");
  p();
  {
    const fpS = normals(S).filter((r) => r.outcome === "FP");
    const fpL = normals(L).filter((r) => r.outcome === "FP");
    const share = (fp: EvalRecord[]): string =>
      fp.length
        ? `${fp.filter((r) => !registered.has(r.tool)).length}/${fp.length} (${(
            (fp.filter((r) => !registered.has(r.tool)).length / fp.length) *
            100
          ).toFixed(1)}%)`
        : "-";
    p(
      mdTable(
        ["모드", "오탐 전체", "그중 미등록 도구 호출"],
        [
          ["session", `${fpS.length}`, share(fpS)],
          ["lineage", `${fpL.length}`, share(fpL)],
        ]
      )
    );
  }
  p();
  p("### 5-3. 오탐의 비신뢰(U)축 출처");
  p();
  p(
    "설정에 등록된 비신뢰 소스를 실제로 읽었는지, 아니면 미등록 도구 결과의 " +
      "default-deny 태깅만으로 U축이 켜졌는지로 나눈다."
  );
  p();
  {
    const rowsOf = (m: ModeResult): string[][] => {
      const fp = m.records.filter((r) => r.outcome === "FP");
      const onlyDefaultDeny = fp.filter((r) => !facts.get(r.scenarioId)!.hasRegisteredUntrusted);
      const realUntrusted = fp.filter((r) => facts.get(r.scenarioId)!.hasRegisteredUntrusted);
      const neutralSink = onlyDefaultDeny.filter((r) => EXT_NEUTRAL_TOOLS.has(r.tool));
      return [
        ["오탐 전체", `${fp.length}`],
        ["└ 등록된 비신뢰 소스를 읽지 않음 (U축이 미등록 default-deny에서만 옴)", `${onlyDefaultDeny.length}`],
        ["　└ 그중 평가 지점이 중립 도구 (싱크도 미등록이라 OUTBOUND_SINK로 취급됨)", `${neutralSink.length}`],
        ["　└ 그중 평가 지점이 싱크 도구", `${onlyDefaultDeny.length - neutralSink.length}`],
        ["└ 등록된 비신뢰 소스를 실제로 읽음", `${realUntrusted.length}`],
      ];
    };
    p("session:");
    p();
    p(mdTable(["구분", "건수"], rowsOf(S)));
    p();
    p("lineage:");
    p();
    p(mdTable(["구분", "건수"], rowsOf(L)));
    p();
    const ids = (m: ModeResult, pred: (r: EvalRecord) => boolean): string =>
      m.records.filter((r) => r.outcome === "FP" && pred(r)).map(recId).join(", ") || "(없음)";
    p(
      `session · U축이 미등록 default-deny에서만 온 오탐 id: ` +
        `${ids(S, (r) => !facts.get(r.scenarioId)!.hasRegisteredUntrusted)}`
    );
    p();
    p(
      `session · 등록된 비신뢰 소스를 실제로 읽은 세션의 오탐 id: ` +
        `${ids(S, (r) => facts.get(r.scenarioId)!.hasRegisteredUntrusted)}`
    );
  }
  p();

  // ---- 6~9. id 목록 ----
  const tagBasis = (r: EvalRecord): string => {
    const f = facts.get(r.scenarioId)!;
    if (f.bySourceRegistration && f.byContentDetection) return "출처+내용";
    if (f.bySourceRegistration) return "출처";
    if (f.byContentDetection) return "내용";
    return "없음";
  };
  const idTable = (rs: EvalRecord[], withTagBasis = false): string =>
    rs.length
      ? mdTable(
          withTagBasis
            ? ["id", "도구", "tier", "미등록", "민감 태그 근거", "why"]
            : ["id", "도구", "tier", "미등록", "why"],
          rs.map((r) => {
            const base = [recId(r), `\`${r.tool}\``, r.tier ?? "-", registered.has(r.tool) ? "" : "미등록"];
            const why = (r.why ?? "").replace(/\|/g, "\\|");
            return withTagBasis ? [...base, tagBasis(r), why] : [...base, why];
          })
        )
      : "(없음)";

  const fpIds = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.outcome === "FP");
  const fnIds = (r: ModeResult): EvalRecord[] => r.records.filter((x) => x.outcome === "FN");

  p("## 6. 오탐(FP) 시나리오 id 목록 — session");
  p();
  p(`총 ${fpIds(S).length}건`);
  p();
  p(idTable(fpIds(S)));
  p();
  p("## 7. 오탐(FP) 시나리오 id 목록 — lineage");
  p();
  p(`총 ${fpIds(L).length}건`);
  p();
  const sameFp =
    fpIds(S).length === fpIds(L).length &&
    fpIds(S).every((r, i) => recId(r) === recId(fpIds(L)[i]));
  p(sameFp ? "session 목록과 동일 (id·순서 일치)." : "");
  p();
  p(idTable(fpIds(L)));
  p();
  p("## 8. 미탐(FN) 시나리오 id 목록 — session");
  p();
  p(`총 ${fnIds(S).length}건`);
  p();
  p(idTable(fnIds(S), true));
  p();
  p("## 9. 미탐(FN) 시나리오 id 목록 — lineage");
  p();
  p(`총 ${fnIds(L).length}건`);
  p();
  const sameFn =
    fnIds(S).length === fnIds(L).length &&
    fnIds(S).every((r, i) => recId(r) === recId(fnIds(L)[i]));
  p(sameFn ? "session 목록과 동일 (id·순서 일치)." : "");
  p();
  p(idTable(fnIds(L), true));
  p();

  // ---- 10. 두 모드가 갈린 지점 ----
  p("## 10. 두 모드(session/lineage)가 다르게 판정한 지점");
  p();
  const diffTable = (x: { session: ModeResult; lineage: ModeResult }): string => {
    const diff = x.session.records
      .map((s, i) => ({ s, l: x.lineage.records[i] }))
      .filter(({ s, l }) => s.allowed !== l.allowed);
    return diff.length
      ? mdTable(
          ["id", "도구", "tier", "정답", "session", "lineage", "우세"],
          diff.map(({ s, l }) => [
            recId(s),
            `\`${s.tool}\``,
            s.tier ?? "-",
            s.expect,
            `${s.outcome}/${s.allowed ? "통과" : "차단"}`,
            `${l.outcome}/${l.allowed ? "통과" : "차단"}`,
            s.outcome === "FP" || s.outcome === "FN" ? "lineage" : "session",
          ])
        )
      : "(없음)";
  };
  {
    const n = S.records.filter((r, i) => r.allowed !== L.records[i].allowed).length;
    p(`실행 ${label} — 총 ${n}건`);
    p();
    p(diffTable(ext));
  }
  p();
  if (extBaseline) {
    const n = extBaseline.session.records.filter(
      (r, i) => r.allowed !== extBaseline.lineage.records[i].allowed
    ).length;
    p("### 10-1. 같은 지점, 실행 A(기준 설정)");
    p();
    p(`총 ${n}건`);
    p();
    p(diffTable(extBaseline));
    p();
  }

  // ---- 11. 비교표 ----
  if (realistic && extBaseline) {
    // 설정을 바꿔 돌린 실행 — 실행 A(기준 설정) / 실행 B(이번 설정) / 기존 81 세 열.
    const R = realistic;
    const A = extBaseline;
    const regA = loadRegisteredTools(
      input.baselineConfigPath && path.join(__dirname, "..", input.baselineConfigPath)
    );
    const regR = loadRegisteredTools(); // 기존 세트는 항상 기본 설정
    const pair = (
      s: ModeResult,
      l: ModeResult,
      f: (m: ModeResult) => string
    ): string => `${f(s)} / ${f(l)}`;
    const divergence = (x: { session: ModeResult; lineage: ModeResult }): string =>
      `${x.session.records.filter((r, i) => r.allowed !== x.lineage.records[i].allowed).length}`;

    p(`## 11. 실행 A / 실행 B / 기존 세트(81) 비교`);
    p();
    p(
      `각 칸은 \`session / lineage\`. ` +
        `실행 A = \`${input.baselineConfigPath ?? "benchmark/config.dev-bench.json"}\` · ` +
        `실행 ${label} = \`${input.configPath}\` · ` +
        `기존 81 = realistic 세트(설정은 실행 A와 동일).`
    );
    p();
    const sinkFp = (m: ModeResult): string =>
      rate(bucket(normals(m).filter((r) => EXT_SINK_TOOLS.has(r.tool)), "FP"));
    const unregFp = (reg: Set<string>) => (m: ModeResult): string =>
      rate(bucket(normals(m).filter((r) => !reg.has(r.tool)), "FP"));
    p(
      mdTable(
        ["지표", `확장 322 · 실행 A`, `확장 322 · 실행 ${label}`, "기존 81"],
        [
          ["시나리오 수", "322", "322", "81"],
          [
            "정상 판정 지점",
            `${normals(A.session).length}`,
            `${normals(S).length}`,
            `${normals(R.session).length}`,
          ],
          [
            "공격 판정 지점",
            `${attacks(A.session).length}`,
            `${attacks(S).length}`,
            `${attacks(R.session).length}`,
          ],
          [
            "정탐 TP",
            pair(A.session, A.lineage, (m) => `${m.confusion.tp}`),
            pair(S, L, (m) => `${m.confusion.tp}`),
            pair(R.session, R.lineage, (m) => `${m.confusion.tp}`),
          ],
          [
            "**오탐 FP**",
            pair(A.session, A.lineage, (m) => `${m.confusion.fp}`),
            pair(S, L, (m) => `${m.confusion.fp}`),
            pair(R.session, R.lineage, (m) => `${m.confusion.fp}`),
          ],
          [
            "**오탐률 FP/정상**",
            pair(A.session, A.lineage, fpr),
            pair(S, L, fpr),
            pair(R.session, R.lineage, fpr),
          ],
          [
            "**미탐 FN**",
            pair(A.session, A.lineage, (m) => `${m.confusion.fn}`),
            pair(S, L, (m) => `${m.confusion.fn}`),
            pair(R.session, R.lineage, (m) => `${m.confusion.fn}`),
          ],
          [
            "**미탐률 FN/공격**",
            pair(A.session, A.lineage, fnr),
            pair(S, L, fnr),
            pair(R.session, R.lineage, fnr),
          ],
          [
            "★ 싱크 호출 정상 오탐률",
            pair(A.session, A.lineage, sinkFp),
            pair(S, L, sinkFp),
            pair(R.session, R.lineage, sinkFp),
          ],
          [
            "미등록 도구 정상 판정 지점",
            `${normals(A.session).filter((r) => !regA.has(r.tool)).length}`,
            `${normals(S).filter((r) => !registered.has(r.tool)).length}`,
            `${normals(R.session).filter((r) => !regR.has(r.tool)).length}`,
          ],
          [
            "미등록 도구 정상 오탐",
            pair(A.session, A.lineage, unregFp(regA)),
            pair(S, L, unregFp(registered)),
            pair(R.session, R.lineage, unregFp(regR)),
          ],
          ["두 모드 판정이 갈린 지점", divergence(A), divergence(ext), divergence(R)],
          [
            "오버헤드 mean",
            pair(A.session, A.lineage, (m) => `${(m.overhead.meanNs / 1000).toFixed(1)}µs`),
            pair(S, L, (m) => `${(m.overhead.meanNs / 1000).toFixed(1)}µs`),
            pair(R.session, R.lineage, (m) => `${(m.overhead.meanNs / 1000).toFixed(1)}µs`),
          ],
          [
            "오버헤드 p95",
            pair(A.session, A.lineage, (m) => `${(m.overhead.p95Ns / 1000).toFixed(1)}µs`),
            pair(S, L, (m) => `${(m.overhead.p95Ns / 1000).toFixed(1)}µs`),
            pair(R.session, R.lineage, (m) => `${(m.overhead.p95Ns / 1000).toFixed(1)}µs`),
          ],
        ]
      )
    );
    p();
    p("### 11-1. tier별 나란히 보기");
    p();
    p("각 칸은 `session / lineage`.");
    p();
    const tCell = (m: ModeResult, tier: string, kind: "FP" | "FN"): string =>
      rate(
        bucket(
          m.records.filter((r) => r.tier === tier && r.expect === (kind === "FP" ? "pass" : "block")),
          kind
        )
      );
    p(
      mdTable(
        ["계층", "확장 322 · 실행 A", `확장 322 · 실행 ${label}`, "기존 81"],
        tierRows.map(({ tier, kind, label: rowLabel }) => [
          rowLabel,
          pair(A.session, A.lineage, (m) => tCell(m, tier, kind)),
          pair(S, L, (m) => tCell(m, tier, kind)),
          pair(R.session, R.lineage, (m) => tCell(m, tier, kind)),
        ])
      )
    );
    p();
    p("### 11-2. 유출 형태별 미탐 — 실행 A vs 실행 " + label);
    p();
    {
      const forms = LEAK_FORMS.map((f) => f.label).filter((l) =>
        attacks(S).some((r) => leakForm(r.title) === l)
      );
      const cell = (m: ModeResult, f: string): string =>
        rate(bucket(attacks(m).filter((r) => leakForm(r.title) === f), "FN"));
      p(
        mdTable(
          ["유출 형태", "확장 322 · 실행 A", `확장 322 · 실행 ${label}`],
          forms.map((f) => [
            f,
            pair(A.session, A.lineage, (m) => cell(m, f)),
            pair(S, L, (m) => cell(m, f)),
          ])
        )
      );
    }
    p();
  } else if (realistic) {
    const R = realistic;
    p("## 11. 기존 세트(81) vs 확장 세트(322) 비교");
    p();
    const rn = (m: ModeResult): number => normals(m).length;
    const ra = (m: ModeResult): number => attacks(m).length;
    p(
      mdTable(
        ["지표", "기존 81 · session", "기존 81 · lineage", "확장 322 · session", "확장 322 · lineage"],
        [
          ["시나리오 수", "81", "81", "322", "322"],
          [
            "정상 판정 지점",
            `${rn(R.session)}`,
            `${rn(R.lineage)}`,
            `${rn(S)}`,
            `${rn(L)}`,
          ],
          ["공격 판정 지점", `${ra(R.session)}`, `${ra(R.lineage)}`, `${ra(S)}`, `${ra(L)}`],
          [
            "오탐 FP",
            `${R.session.confusion.fp}`,
            `${R.lineage.confusion.fp}`,
            `${S.confusion.fp}`,
            `${L.confusion.fp}`,
          ],
          ["오탐률 FP/정상", fpr(R.session), fpr(R.lineage), fpr(S), fpr(L)],
          [
            "미탐 FN",
            `${R.session.confusion.fn}`,
            `${R.lineage.confusion.fn}`,
            `${S.confusion.fn}`,
            `${L.confusion.fn}`,
          ],
          ["미탐률 FN/공격", fnr(R.session), fnr(R.lineage), fnr(S), fnr(L)],
          [
            "★ 싱크 호출 정상 오탐률",
            rate(bucket(normals(R.session).filter((r) => EXT_SINK_TOOLS.has(r.tool)), "FP")),
            rate(bucket(normals(R.lineage).filter((r) => EXT_SINK_TOOLS.has(r.tool)), "FP")),
            rate(bucket(sinkNormalS, "FP")),
            rate(bucket(sinkNormalL, "FP")),
          ],
          [
            "미등록 도구 정상 오탐",
            rate(bucket(normals(R.session).filter((r) => !registered.has(r.tool)), "FP")),
            rate(bucket(normals(R.lineage).filter((r) => !registered.has(r.tool)), "FP")),
            rate(bucket(unregS, "FP")),
            rate(bucket(unregL, "FP")),
          ],
          [
            "오버헤드 mean",
            `${(R.session.overhead.meanNs / 1000).toFixed(2)}µs`,
            `${(R.lineage.overhead.meanNs / 1000).toFixed(2)}µs`,
            `${(S.overhead.meanNs / 1000).toFixed(2)}µs`,
            `${(L.overhead.meanNs / 1000).toFixed(2)}µs`,
          ],
          [
            "오버헤드 p95",
            `${(R.session.overhead.p95Ns / 1000).toFixed(2)}µs`,
            `${(R.lineage.overhead.p95Ns / 1000).toFixed(2)}µs`,
            `${(S.overhead.p95Ns / 1000).toFixed(2)}µs`,
            `${(L.overhead.p95Ns / 1000).toFixed(2)}µs`,
          ],
        ]
      )
    );
    p();
    p("### 11-1. tier별 나란히 보기");
    p();
    const tierCell = (m: ModeResult, tier: string, kind: "FP" | "FN"): string =>
      rate(
        bucket(
          m.records.filter((r) => r.tier === tier && r.expect === (kind === "FP" ? "pass" : "block")),
          kind
        )
      );
    p(
      mdTable(
        ["계층", "기존 81 · session", "기존 81 · lineage", "확장 322 · session", "확장 322 · lineage"],
        tierRows.map(({ tier, kind, label }) => [
          label,
          tierCell(R.session, tier, kind),
          tierCell(R.lineage, tier, kind),
          tierCell(S, tier, kind),
          tierCell(L, tier, kind),
        ])
      )
    );
    p();
  }

  return out.join("\n") + "\n";
}

/** 콘솔 요약 — 리포트 파일과 같은 수치의 축약본 */
export function printExtSummary(input: ExtReportInput): void {
  const { session: S, lineage: L } = input.ext;
  const registered = loadRegisteredTools(
    input.configPath && path.join(__dirname, "..", input.configPath)
  );
  const sinkNormal = (m: ModeResult): EvalRecord[] =>
    normals(m).filter((r) => EXT_SINK_TOOLS.has(r.tool));
  const unreg = (m: ModeResult): EvalRecord[] => normals(m).filter((r) => !registered.has(r.tool));

  console.log("═══ 확장 세트(322) 요약 — 분모는 판정 지점의 정답(expect) 기준 ═══");
  for (const m of [S, L]) {
    console.log(
      `  ${m.mode.padEnd(8)} 오탐 ${m.confusion.fp}/${normals(m).length} ` +
        `(${((m.confusion.fp / normals(m).length) * 100).toFixed(1)}%) · ` +
        `미탐 ${m.confusion.fn}/${attacks(m).length} ` +
        `(${((m.confusion.fn / attacks(m).length) * 100).toFixed(1)}%) · ` +
        `★싱크호출 정상 오탐 ${rate(bucket(sinkNormal(m), "FP"))} · ` +
        `미등록 정상 오탐 ${rate(bucket(unreg(m), "FP"))}`
    );
  }
  console.log("");
}
