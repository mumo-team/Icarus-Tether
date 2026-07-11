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
import { SinkClass } from "@taintguard/types";

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

  const domain = obj.domain ?? "default";
  if (typeof domain !== "string") fail(`"domain"은 문자열이어야 합니다`);

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
    secretDetection: parseSecretDetection(obj.secretDetection),
    piiPatterns: parsePatternList(obj.piiPatterns, "piiPatterns"),
    extractionSchema: parseExtractionSchema(obj.extractionSchema),
  };
}

let cached: PolicyConfig | null = null;

/** 활성 설정. 프로세스당 1회 로드해 캐시한다. */
export function getPolicyConfig(): PolicyConfig {
  cached ??= loadPolicyConfig();
  return cached;
}
