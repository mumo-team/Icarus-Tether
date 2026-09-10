/**
 * PolicyConfig — 정책 엔진의 모든 "값"이 모이는 단일 소스.
 *
 * 원칙: 코드에는 결정론적 로직만, 값(도구 분류·스키마·패턴·임계값)은 JSON으로.
 *
 * 설정 파일 선택 우선순위:
 *   1. loadPolicyConfig(filePath) 인자
 *   2. 환경변수 TAINTGUARD_TOOL_REGISTRY (파일 경로)
 *   3. 환경변수 TAINTGUARD_DOMAIN (예: "dev" → <policy-engine>/config/dev.json)
 *   4. 기본값: <policy-engine>/config/tool-registry.json (default 도메인)
 *
 * 두 가지 키 형식을 모두 정규화해서 받아들인다:
 *   - 신형: sensitiveSourceTools / untrustedSourceTools / outboundSinkTools(배열)
 *   - 구형: sensitiveSources / untrustedSources / sinks(맵) — 하위 호환
 *
 * 설정이 없거나 형식이 틀리면 예외(fail-closed) — 조용한 기본값 폴백 없음.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { SinkClass } from "@icarus-tether/types";

// ---------------------------------------------------------------------------
// 타입
// ---------------------------------------------------------------------------

/** 미분류(설정의 어느 목록에도 없는) 도구를 어떻게 취급할지 — 원칙 4(default-deny) */
export type UnknownToolPolicy = "deny" | "warn";

/** 민감 소스에서 나온 값의 태깅 정책. 현재는 "형식 무관 전부 SENSITIVE"만 지원 */
export type SensitiveSourcePolicy = "tag_all";

/**
 * 계보 태그 전파 모드:
 * - "snapshot" (기본): 노드 생성 시점에 부모 태그를 한 번만 복사. 가볍다.
 * - "live": 생성 후 부모에 태그가 "추가"되면 자손도 하향 전파로 물려받는다. 정밀하지만 무겁다.
 *   (두 모드 모두 태그 제거는 절대 전파하지 않는다 — 전파/정화 비대칭)
 */
export type PropagationMode = "snapshot" | "live";

/**
 * 실제 차단을 누가 결정하는가:
 * - "session" (기본): toy — 세션 boolean(sessionStore). 섀도 로그는 계속 남긴다.
 * - "shadow": session과 동일한 동작 (toy 차단 + real 로그) — 전환 준비 기간용 명시적 이름.
 * - "lineage": real — 나가려는 값의 계보만 보고 판정. 설정으로 명시해야만 켜진다
 *   (검증 안 된 채 전 사용자가 real로 바뀌는 사고 방지).
 */
export type JudgmentMode = "session" | "lineage" | "shadow";

/**
 * HITL(사람 승인) 오버라이드 정책 — lineage 판정에만 적용:
 * - "off" (기본): 기존 동작 그대로 — 트라이펙타는 무조건 차단, 오버라이드 불가.
 * - "weak-only": 오염이 전부 약한(weak) 연결로만 유입된 트라이펙타에 한해
 *   사람이 오버라이드를 요청할 수 있다. 판정은 결정론 규칙(hitl.ts) — AI 아님.
 */
export type HitlPolicy = "off" | "weak-only";

/**
 * 계보 가지치기 정책:
 * - "off" (기본): 아무것도 지우지 않는다 (기존 동작).
 * - "declassified": 정화돼 태그가 전부 없어진 childless 노드를 묘비(tombstone)로
 *   압축한다. 묘비가 명시 참조·값 매칭 연결을 보존하므로 판정 결과는 불변.
 */
export type PruningPolicy = "off" | "declassified";

/**
 * 안전 바닥(TEMPORAL_FALLBACK) 완화 정책 — lineage 모드 전용.
 * - "off" (기본): 기존 동작. 연결 근거가 폴백뿐이어도 frontier의 S가 값-민감으로 간주돼 차단.
 * - "scan-clean": 연결 근거가 TEMPORAL_FALLBACK뿐이고(값 매칭·명시 참조가 오염 노드를 하나도
 *   못 잡음), 값의 내용을 직접 보는 검사(출력 스캔·볼트 원본 재전송)가 아무것도 못 찾았으면
 *   통과. session 모드에는 출력 스캔이 없으므로 이 값을 무시한다 — session은 기존 동작 그대로
 *   두어야 두 정책의 비교가 성립한다.
 * ★ 형식모델(formal/TaintLineage.tla)의 ReachSink 가드는 tags[n]에 S가 있으면 무조건 차단이라
 *   이 완화보다 강하다. 모델은 아직 이 규칙을 반영하지 않는다(benchmark/results-ext-scan-hardening.md).
 */
export type FallbackRelaxation = "off" | "scan-clean";

/**
 * 파괴적 액션 게이트 정책 — "삭제 자체"가 아니라 "비신뢰가 유발한 파괴"만 다룬다.
 * 판정: destructiveTools 등록 도구 호출 AND 세션이 살아있는 비신뢰(U)에 노출.
 * 사용자 직접 지시 삭제(깨끗한 세션)는 통과 — 비개발자의 정상 삭제를 방해하지 않는다.
 * - "off" (기본): 게이트 비활성 (기존 동작 불변).
 * - "hitl": 차단하되 항상 사람 승인 제안 발급 — "이 파일 보고 필요없으면 지워줘"
 *   같은 애매 케이스(사용자가 시켰지만 비신뢰 내용이 결정에 관여)를 사람이 해소.
 *   유출 HITL의 weak-only 규칙은 값-계보 연결 신뢰도 개념이라 여기 적용하지 않는다.
 * - "block": 확정 차단 (승인 우회 없음).
 * judgmentMode와 독립. 의미론은 formal/TaintDestructiveHITL.tla가 선행 확정 (위반 0).
 */
export type DestructivePolicy = "off" | "hitl" | "block";

export interface PatternSpec {
  /** 토큰 이름에 들어가는 식별자 (대문자·숫자·언더스코어) */
  type: string;
  /** 정규식 소스 문자열 (JSON에 저장, 코드가 컴파일) */
  pattern: string;
}

export interface EntropyConfig {
  /** 이 길이 이상의 연속 문자열(run)만 후보로 본다 */
  minLength: number;
  /** Shannon 엔트로피(비트/문자)가 이 값 이상이면 비밀로 판정 */
  entropyThreshold: number;
}

export interface SecretDetectionConfig {
  /** 1순위: 민감 소스 출처면 내용을 보지 않고 민감 처리 */
  bySource: boolean;
  /** 2순위: 엔트로피 기반 — 형식을 몰라도 무작위 문자열 탐지 */
  byEntropy: EntropyConfig | null;
  /** 3순위: 유명 포맷 정규식 (보조용) */
  byRegex: PatternSpec[];
}

export type FieldSpec =
  | { kind: "enum"; values: string[] }
  | { kind: "string"; maxLength: number; charset: string };

export interface ExtractionSchemaConfig {
  fields: Record<string, FieldSpec>;
}

export interface PolicyConfig {
  domain: string;
  sensitiveSourceTools: ReadonlySet<string>;
  untrustedSourceTools: ReadonlySet<string>;
  sinks: ReadonlyMap<string, SinkClass>;
  unknownToolPolicy: UnknownToolPolicy;
  sensitiveSourcePolicy: SensitiveSourcePolicy;
  propagationMode: PropagationMode;
  judgmentMode: JudgmentMode;
  hitlPolicy: HitlPolicy;
  pruningPolicy: PruningPolicy;
  /** 안전 바닥 완화 — lineage 전용, 기본 "off"(기존 동작). FallbackRelaxation 주석 참조. */
  fallbackRelaxation: FallbackRelaxation;
  /** 파괴적 액션(DROP·대량삭제·파일삭제 등) 도구 목록 — SinkClass와 직교인 별도 축.
   *  주의: 여기 등록한 도구도 sinks에 실제 등급("WRITE_INTERNAL" 등)을 명시할 것 —
   *  안 하면 미선언 싱크 default-deny(OUTBOUND 취급)로 유출 축에도 걸린다. */
  destructiveTools: ReadonlySet<string>;
  destructivePolicy: DestructivePolicy;
  /** 사용자용 설명 계층에서 쓰는 도구의 사람 말 라벨 (예: read_secrets → "비밀 파일 읽기") */
  toolLabels: Record<string, string>;
  /**
   * 신뢰 리소스 URI 접두사 목록 (C-7) — resources/read·prompts/get의 URI가 이 중
   * 하나로 시작하면 신뢰(내부) 콘텐츠로 본다. 매칭 안 되면 비신뢰(원칙 4 default-deny).
   * 기본 [] = 아무것도 신뢰하지 않음.
   *
   * ★ 위장 방지 규칙(로드 시 fail-closed 검증): 각 접두사는 "://"를 포함하고 "/"로
   * 끝나야 한다. URL 파싱을 아예 하지 않는 순수 접두사 매칭이므로(파서 차이 공격 배제),
   * 경계 없는 접두사("https://corp")는 "https://corp.evil.com"에도 매칭되는 확장 위장을
   * 허용한다 — 그래서 구조적으로 금지한다. 예: ["file:///", "file://localhost/",
   * "internal://", "https://intranet.corp.local/"].
   * ("file:///"는 호스트 없는 로컬만 매칭 — "file://evil-host/"(원격 UNC)는 안 걸린다.)
   */
  trustedResourceUris: readonly string[];
  secretDetection: SecretDetectionConfig | null;
  piiPatterns: PatternSpec[];
  extractionSchema: ExtractionSchemaConfig | null;
}

// ---------------------------------------------------------------------------
// 이름 참조 문자셋 — 문자셋 자체는 보안 로직이므로 코드에 고정하고,
// 설정은 이름("safe-text")으로만 참조한다 (설정 실수로 문자셋이 느슨해지는 사고 방지)
// ---------------------------------------------------------------------------

/** safe-text: 글자(한글 포함)·숫자·공백·. _ - 만. 콜론/슬래시/따옴표가 없어 URL·지시문·코드 성립 불가 */
export const NAMED_CHARSETS: Record<string, RegExp> = {
  "safe-text": /^[\p{L}\p{N} ._-]+$/u,
};

// ---------------------------------------------------------------------------
// 경로 해석 (src/ 와 dist/ 어디서 실행되든 <policy-engine>/config 을 가리킨다)
// ---------------------------------------------------------------------------

const CONFIG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "config");
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, "tool-registry.json");

function resolveConfigPath(): string {
  if (process.env.TAINTGUARD_TOOL_REGISTRY) return process.env.TAINTGUARD_TOOL_REGISTRY;
  if (process.env.TAINTGUARD_DOMAIN) {
    return path.join(CONFIG_DIR, `${process.env.TAINTGUARD_DOMAIN}.json`);
  }
  return DEFAULT_CONFIG_PATH;
}

// ---------------------------------------------------------------------------
// 검증 헬퍼 (전부 fail-closed)
// ---------------------------------------------------------------------------

function fail(message: string): never {
  throw new Error(`[policy-config] ${message}`);
}

function assertStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    fail(`"${field}"는 문자열 배열이어야 합니다`);
  }
  return value;
}

const PATTERN_TYPE_FORMAT = /^[A-Z0-9_]+$/;

function parsePatternList(value: unknown, field: string): PatternSpec[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(`"${field}"는 배열이어야 합니다`);
  return value.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) fail(`"${field}[${i}]"는 객체여야 합니다`);
    const { type, pattern } = entry as Record<string, unknown>;
    if (typeof type !== "string" || !PATTERN_TYPE_FORMAT.test(type)) {
      fail(`"${field}[${i}].type"은 대문자·숫자·_ 형식이어야 합니다 (토큰 이름에 사용됨)`);
    }
    if (typeof pattern !== "string") fail(`"${field}[${i}].pattern"은 문자열이어야 합니다`);
    try {
      new RegExp(pattern, "g"); // 컴파일 가능성 검증
    } catch (err) {
      fail(`"${field}[${i}].pattern" 정규식이 유효하지 않습니다: ${(err as Error).message}`);
    }
    return { type, pattern };
  });
}

function parseSecretDetection(value: unknown): SecretDetectionConfig | null {
  if (value === undefined) return null;
  if (typeof value !== "object" || value === null) fail(`"secretDetection"은 객체여야 합니다`);
  const obj = value as Record<string, unknown>;

  const bySource = obj.bySource ?? true;
  if (typeof bySource !== "boolean") fail(`"secretDetection.bySource"는 boolean이어야 합니다`);

  let byEntropy: EntropyConfig | null = null;
  if (obj.byEntropy !== undefined) {
    if (typeof obj.byEntropy !== "object" || obj.byEntropy === null) {
      fail(`"secretDetection.byEntropy"는 객체여야 합니다`);
    }
    const e = obj.byEntropy as Record<string, unknown>;
    if (typeof e.minLength !== "number" || !Number.isInteger(e.minLength) || e.minLength < 1) {
      fail(`"secretDetection.byEntropy.minLength"는 양의 정수여야 합니다`);
    }
    if (typeof e.entropyThreshold !== "number" || !Number.isFinite(e.entropyThreshold) || e.entropyThreshold <= 0) {
      fail(`"secretDetection.byEntropy.entropyThreshold"는 양수여야 합니다`);
    }
    byEntropy = { minLength: e.minLength, entropyThreshold: e.entropyThreshold };
  }

  return { bySource, byEntropy, byRegex: parsePatternList(obj.byRegex, "secretDetection.byRegex") };
}

function parseExtractionSchema(value: unknown): ExtractionSchemaConfig | null {
  if (value === undefined) return null;
  if (typeof value !== "object" || value === null) fail(`"extractionSchema"는 객체여야 합니다`);
  const rawFields = (value as Record<string, unknown>).fields;
  if (typeof rawFields !== "object" || rawFields === null || Array.isArray(rawFields)) {
    fail(`"extractionSchema.fields"는 객체여야 합니다`);
  }
  const entries = Object.entries(rawFields as Record<string, unknown>);
  if (entries.length === 0) fail(`"extractionSchema.fields"가 비어 있습니다`);

  const fields: Record<string, FieldSpec> = {};
  for (const [name, raw] of entries) {
    if (typeof raw !== "object" || raw === null) fail(`extractionSchema 필드 "${name}"는 객체여야 합니다`);
    const spec = raw as Record<string, unknown>;
    if (spec.kind === "enum") {
      const values = assertStringArray(spec.values, `extractionSchema.fields.${name}.values`);
      if (values.length === 0) fail(`extractionSchema 필드 "${name}"의 enum values가 비어 있습니다`);
      fields[name] = { kind: "enum", values };
    } else if (spec.kind === "string") {
      if (typeof spec.maxLength !== "number" || !Number.isInteger(spec.maxLength) || spec.maxLength < 1) {
        fail(`extractionSchema 필드 "${name}".maxLength는 양의 정수여야 합니다`);
      }
      const charset = spec.charset;
      if (typeof charset !== "string" || !(charset in NAMED_CHARSETS)) {
        fail(
          `extractionSchema 필드 "${name}".charset "${String(charset)}"는 등록된 문자셋이 아닙니다 (${Object.keys(NAMED_CHARSETS).join(", ")})`
        );
      }
      fields[name] = { kind: "string", maxLength: spec.maxLength, charset };
    } else {
      fail(`extractionSchema 필드 "${name}".kind는 "enum" | "string"이어야 합니다`);
    }
  }
  return { fields };
}

// ---------------------------------------------------------------------------
// 로더
// ---------------------------------------------------------------------------

const VALID_SINK_CLASSES = new Set<string>(Object.values(SinkClass));

export function loadPolicyConfig(filePath: string = resolveConfigPath()): PolicyConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (err) {
    fail(`설정 파일을 읽을 수 없습니다: ${filePath} (${(err as Error).message})`);
  }
  if (typeof raw !== "object" || raw === null) fail(`최상위 값은 객체여야 합니다: ${filePath}`);
  const obj = raw as Record<string, unknown>;

  // 소스 목록 — 신형(…SourceTools) / 구형(…Sources) 키 모두 수용
  const sensitiveRaw = obj.sensitiveSourceTools ?? obj.sensitiveSources;
  const untrustedRaw = obj.untrustedSourceTools ?? obj.untrustedSources;
  const sensitiveSourceTools = new Set(
    assertStringArray(sensitiveRaw, "sensitiveSourceTools(구형: sensitiveSources)")
  );
  const untrustedSourceTools = new Set(
    assertStringArray(untrustedRaw, "untrustedSourceTools(구형: untrustedSources)")
  );

  // 싱크 — 신형 outboundSinkTools(배열) / 구형 sinks(맵) 모두 수용, 둘 다 있으면 병합
  if (obj.outboundSinkTools === undefined && obj.sinks === undefined) {
    fail(`"outboundSinkTools" 또는 "sinks" 중 하나는 필요합니다`);
  }
  const sinks = new Map<string, SinkClass>();
  if (obj.outboundSinkTools !== undefined) {
    for (const name of assertStringArray(obj.outboundSinkTools, "outboundSinkTools")) {
      sinks.set(name, SinkClass.OUTBOUND_SINK);
    }
  }
  if (obj.sinks !== undefined) {
    if (typeof obj.sinks !== "object" || obj.sinks === null || Array.isArray(obj.sinks)) {
      fail(`"sinks"는 { 도구이름: SinkClass } 객체여야 합니다`);
    }
    for (const [toolName, sinkClass] of Object.entries(obj.sinks as Record<string, unknown>)) {
      if (typeof sinkClass !== "string" || !VALID_SINK_CLASSES.has(sinkClass)) {
        fail(
          `sinks["${toolName}"] 값 "${String(sinkClass)}"는 유효한 SinkClass가 아닙니다 (${[...VALID_SINK_CLASSES].join(", ")})`
        );
      }
      sinks.set(toolName, sinkClass as SinkClass);
    }
  }

  // default-deny 스위치 — 기본값 deny (원칙 4)
  const unknownToolPolicy = obj.unknownToolPolicy ?? "deny";
  if (unknownToolPolicy !== "deny" && unknownToolPolicy !== "warn") {
    fail(`"unknownToolPolicy"는 "deny" | "warn" 중 하나여야 합니다`);
  }

  const sensitiveSourcePolicy = obj.sensitiveSourcePolicy ?? "tag_all";
  if (sensitiveSourcePolicy !== "tag_all") {
    fail(`"sensitiveSourcePolicy"는 현재 "tag_all"만 지원합니다`);
  }

  const propagationMode = obj.propagationMode ?? "snapshot";
  if (propagationMode !== "snapshot" && propagationMode !== "live") {
    fail(`"propagationMode"는 "snapshot" | "live" 중 하나여야 합니다`);
  }

  // 기본은 "session"(toy) — real("lineage")은 설정으로 명시해야만 켜진다
  const judgmentMode = obj.judgmentMode ?? "session";
  if (judgmentMode !== "session" && judgmentMode !== "lineage" && judgmentMode !== "shadow") {
    fail(`"judgmentMode"는 "session" | "lineage" | "shadow" 중 하나여야 합니다`);
  }

  // 기본은 "off" — HITL은 설정으로 명시해야만 켜진다 (기존 동작 불변)
  const hitlPolicy = obj.hitlPolicy ?? "off";
  if (hitlPolicy !== "off" && hitlPolicy !== "weak-only") {
    fail(`"hitlPolicy"는 "off" | "weak-only" 중 하나여야 합니다`);
  }

  // 기본은 "off" — 가지치기도 설정으로 명시해야만 켜진다 (기존 동작 불변)
  const pruningPolicy = obj.pruningPolicy ?? "off";
  if (pruningPolicy !== "off" && pruningPolicy !== "declassified") {
    fail(`"pruningPolicy"는 "off" | "declassified" 중 하나여야 합니다`);
  }

  // 기본은 "off" — 안전 바닥 완화도 설정으로 명시해야만 켜진다 (기존 동작 불변, 논문 전/후 비교)
  const fallbackRelaxation = obj.fallbackRelaxation ?? "off";
  if (fallbackRelaxation !== "off" && fallbackRelaxation !== "scan-clean") {
    fail(`"fallbackRelaxation"는 "off" | "scan-clean" 중 하나여야 합니다`);
  }

  // 기본은 "off" — 파괴 게이트도 설정으로 명시해야만 켜진다 (기존 동작 불변)
  const destructivePolicy = obj.destructivePolicy ?? "off";
  if (destructivePolicy !== "off" && destructivePolicy !== "hitl" && destructivePolicy !== "block") {
    fail(`"destructivePolicy"는 "off" | "hitl" | "block" 중 하나여야 합니다`);
  }
  const destructiveTools = new Set(
    obj.destructiveTools === undefined
      ? []
      : assertStringArray(obj.destructiveTools, "destructiveTools")
  );

  const domain = obj.domain ?? "default";
  if (typeof domain !== "string") fail(`"domain"은 문자열이어야 합니다`);

  // 사용자용 설명 계층의 도구 라벨 — 생략 시 빈 맵 (도구 이름 그대로 폴백)
  const toolLabels: Record<string, string> = {};
  if (obj.toolLabels !== undefined) {
    if (typeof obj.toolLabels !== "object" || obj.toolLabels === null || Array.isArray(obj.toolLabels)) {
      fail(`"toolLabels"는 { 도구이름: 라벨 } 객체여야 합니다`);
    }
    for (const [tool, label] of Object.entries(obj.toolLabels as Record<string, unknown>)) {
      if (typeof label !== "string") fail(`toolLabels["${tool}"]는 문자열이어야 합니다`);
      toolLabels[tool] = label;
    }
  }

  // 신뢰 리소스 URI 접두사 (C-7) — 생략 시 [] (default-deny: 아무 URI도 신뢰 안 함)
  const trustedResourceUris =
    obj.trustedResourceUris === undefined
      ? []
      : assertStringArray(obj.trustedResourceUris, "trustedResourceUris");
  for (const prefix of trustedResourceUris) {
    // 위장 방지 경계 규칙: "://" 포함 + "/" 종료. "https://corp" 같은 경계 없는
    // 접두사는 "https://corp.evil.com"에도 매칭(확장 위장)되므로 로드 자체를 거부한다.
    if (!prefix.includes("://") || !prefix.endsWith("/")) {
      fail(
        `trustedResourceUris "${prefix}"는 "://"를 포함하고 "/"로 끝나야 합니다 ` +
          `(경계 없는 접두사는 "corp" → "corp.evil.com" 확장 위장을 허용 — 예: "file:///", "internal://")`
      );
    }
  }

  return {
    domain,
    sensitiveSourceTools,
    untrustedSourceTools,
    sinks,
    unknownToolPolicy,
    sensitiveSourcePolicy,
    propagationMode,
    judgmentMode,
    hitlPolicy,
    pruningPolicy,
    fallbackRelaxation,
    destructiveTools,
    destructivePolicy,
    toolLabels,
    trustedResourceUris,
    secretDetection: parseSecretDetection(obj.secretDetection),
    piiPatterns: parsePatternList(obj.piiPatterns, "piiPatterns"),
    extractionSchema: parseExtractionSchema(obj.extractionSchema),
  };
}

let cached: PolicyConfig | null = null;

/** 활성 설정. 최초 호출 시 로드해 캐시한다 (reloadPolicyConfig로 핫리로드 가능). */
export function getPolicyConfig(): PolicyConfig {
  cached ??= loadPolicyConfig();
  return cached;
}

/**
 * 정책 핫리로드 — 설정을 다시 로드해 캐시를 교체한다. 프록시가 설정 파일 변경을
 * 감지해 호출하면, 세션을 끊지 않고 다음 판정부터 새 정책이 적용된다.
 *
 * ★ 검증-후-교체(fail-closed): loadPolicyConfig가 새 설정을 "전부" 검증한 뒤에만
 * 캐시를 교체한다 — 형식 오류·경계 규칙 위반(trustedResourceUris 등)이면 여기서
 * throw하고 캐시는 건드리지 않으므로, 잘못된 설정으로 재로드해도 기존 정책이
 * 그대로 유지된다(운영 중 프록시가 죽거나 무정책 상태가 되는 경로 없음).
 *
 * ★ 동시성: 엔진 판정 경로(evaluateToolCall·attemptSanitization 등)는 전부 동기라
 * 이벤트루프를 놓지 않는다 — 재로드는 동기 블록 "사이"에서만 일어날 수 있어, 진행
 * 중인 판정이 교체 전/후 설정을 섞어 읽는 상황이 구조적으로 불가능하다(단일 대입
 * 교체로 충분). 판정 경로에 await를 넣게 되면 이 전제가 깨지므로 그때는 판정 시작
 * 시 스냅샷으로 바꿔야 한다.
 *
 * 세션 상태(오염 그래프·노출이력·볼트)는 config와 별개 저장소라 영향받지 않는다.
 *
 * @param filePath 생략 시 표준 해석 순서(환경변수 → 기본 경로)로 다시 찾는다.
 * @returns 적용된 새 설정.
 */
export function reloadPolicyConfig(filePath?: string): PolicyConfig {
  const next = filePath === undefined ? loadPolicyConfig() : loadPolicyConfig(filePath);
  cached = next; // 검증 통과 후에만 도달 — 원자적 교체(단일 대입)
  return next;
}
