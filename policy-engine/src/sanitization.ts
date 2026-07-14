/**
 * 검증된 정화(declassification)의 실제 구현 — 로직만. 값은 전부 설정에서.
 *
 * 두 방식 모두 AI 판단이 아니라 결정론적 규칙이며, "검증을 통과했을 때만"
 * 성공을 반환한다. 호출부(attemptSanitization)는 성공한 경우에만 태그를
 * 해제하고, 실패하거나 설정에 검증 근거가 없으면 태그를 유지한다(fail-safe).
 *
 * 1. 구조화 추출(STRUCTURED_EXTRACTION):
 *    활성 설정의 extractionSchema에 정의된 좁은 필드만 새 객체로 복사하고
 *    나머지는 전부 버린다. 각 필드는 enum 멤버십·길이 상한·이름 참조 문자셋을
 *    통과해야 하므로, 인젝션 지시문·URL·코드가 담길 그릇 자체가 없다.
 *    → UNTRUSTED_ORIGIN 해제 근거.
 *
 * 2. 토큰화(TOKENIZATION):
 *    설정의 piiPatterns + secretDetection(정규식·엔트로피)이 찾은 값을 불투명
 *    토큰으로 치환한다. 원본은 인메모리 볼트에만 남는다. 치환 후 전체를
 *    재스캔(자체 토큰 제외)해 잔여물이 없어야 성공. → SENSITIVE 해제 근거.
 */

import { createHash } from "node:crypto";
import {
  getPolicyConfig,
  NAMED_CHARSETS,
  type EntropyConfig,
  type PatternSpec,
} from "./config.js";
import {
  candidateRunRegex,
  shannonEntropy,
  stripVaultTokens,
  VAULT_TOKEN_PATTERN,
} from "./secret-detection.js";

// ---------------------------------------------------------------------------
// 하위 호환 미러 — 값의 원본은 config/tool-registry.json (default 도메인).
// export 계약 유지를 위해 남겨둔 것이며, 런타임 로직은 항상 활성 설정을 읽는다.
// ---------------------------------------------------------------------------

/** @deprecated default 도메인 설정(extractionSchema.fields.type.values)의 미러 */
export const ALLOWED_RECORD_TYPES = ["order", "invoice", "ticket", "note"] as const;
export type AllowedRecordType = (typeof ALLOWED_RECORD_TYPES)[number];

/** @deprecated default 도메인 설정(extractionSchema.fields.name.maxLength)의 미러 */
export const NAME_MAX_LENGTH = 20;

/** default 도메인 스키마의 추출 결과 형태 (도메인별 스키마는 필드가 다를 수 있음) */
export interface ExtractedRecord {
  type: AllowedRecordType;
  name: string;
}

export type SanitizeOutcome =
  | { ok: true; value: unknown }
  | { ok: false; reason: string };

// ---------------------------------------------------------------------------
// 1. 스키마 기반 구조화 추출 — 범용 필드 검증기
// ---------------------------------------------------------------------------

export function extractStructured(payload: unknown): SanitizeOutcome {
  const schema = getPolicyConfig().extractionSchema;
  if (!schema) {
    return { ok: false, reason: "extractionSchema가 설정에 없음 — 검증 불가(fail-safe)" };
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, reason: "페이로드가 객체가 아님 — 구조화 추출 불가" };
  }
  const obj = payload as Record<string, unknown>;

  // 스키마에 정의된 필드만 복사 — 그 외 키는 전부 버려진다 (그릇 제거)
  const value: Record<string, string> = {};
  for (const [field, spec] of Object.entries(schema.fields)) {
    const raw = obj[field];
    if (typeof raw !== "string") {
      return { ok: false, reason: `필드 "${field}" 누락 또는 문자열 아님` };
    }
    if (spec.kind === "enum") {
      if (!spec.values.includes(raw)) {
        return { ok: false, reason: `"${field}"가 허용 enum(${spec.values.join("|")})에 없음` };
      }
    } else {
      if (raw.length === 0 || raw.length > spec.maxLength) {
        return { ok: false, reason: `"${field}"는 1~${spec.maxLength}자 문자열이어야 함` };
      }
      if (!NAMED_CHARSETS[spec.charset].test(raw)) {
        return { ok: false, reason: `"${field}"에 문자셋(${spec.charset}) 밖의 문자가 포함됨` };
      }
    }
    value[field] = raw;
  }
  return { ok: true, value };
}

// ---------------------------------------------------------------------------
// 2. 토큰화 — PII 패턴 + 비밀 정규식 + 엔트로피 후보를 불투명 토큰으로
// ---------------------------------------------------------------------------

/** 토큰 → 원본. 인메모리 볼트(데모용). 실제 배포에서는 별도 암호화 저장소로 교체. */
const vault = new Map<string, string>();

type TokenCategory = "PII" | "SECRET";

function makeToken(category: TokenCategory, type: string, original: string): string {
  // 같은 값 → 같은 토큰 (결정론). 해시라 토큰에서 원본 역산 불가.
  const digest = createHash("sha256").update(original).digest("hex").slice(0, 12);
  const token = `[${category}_${type}_${digest}]`;
  vault.set(token, original);
  return token;
}

/** 볼트에서 원본 복원 (승인된 내부 소비자 전용) */
export function resolveToken(token: string): string | undefined {
  return vault.get(token);
}

/**
 * 이미 만들어진 볼트 토큰 구간은 건드리지 않고, 그 사이 구간에만 치환기를 적용한다.
 * (설정의 패턴이 우연히 토큰 내부 문자열과 겹쳐도 이중 치환되지 않게)
 */
function replaceOutsideTokens(text: string, replacer: (segment: string) => string): string {
  const parts = text.split(new RegExp(`(${VAULT_TOKEN_PATTERN.source})`, "g"));
  return parts.map((part, i) => (i % 2 === 1 ? part : replacer(part))).join("");
}

function tokenizeByPatterns(text: string, patterns: PatternSpec[], category: TokenCategory): string {
  let result = text;
  for (const { type, pattern } of patterns) {
    result = replaceOutsideTokens(result, (seg) =>
      seg.replace(new RegExp(pattern, "g"), (match) => makeToken(category, type, match))
    );
  }
  return result;
}

function tokenizeEntropyRuns(text: string, cfg: EntropyConfig): string {
  return replaceOutsideTokens(text, (seg) =>
    seg.replace(candidateRunRegex(cfg.minLength), (run) =>
      shannonEntropy(run) >= cfg.entropyThreshold
        ? makeToken("SECRET", "HIGH_ENTROPY", run)
        : run
    )
  );
}

/** 문자열을 재귀적으로 치환하고, 결과 문자열들을 수집해 재검증에 쓴다 */
function walkAndTokenize(
  value: unknown,
  tokenize: (s: string) => string,
  collected: string[]
): unknown {
  if (typeof value === "string") {
    const replaced = tokenize(value);
    collected.push(replaced);
    return replaced;
  }
  if (Array.isArray(value)) {
    return value.map((v) => walkAndTokenize(v, tokenize, collected));
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = walkAndTokenize(v, tokenize, collected);
    }
    return out;
  }
  return value; // number/boolean/null 등은 그대로
}

export function tokenizePII(payload: unknown): SanitizeOutcome {
  const cfg = getPolicyConfig();
  const piiPatterns = cfg.piiPatterns;
  const secretPatterns = cfg.secretDetection?.byRegex ?? [];
  const entropy = cfg.secretDetection?.byEntropy ?? null;

  // 검사할 수단이 하나도 없으면 "아무것도 안 봤는데 성공"이 되므로 실패 (fail-safe)
  if (piiPatterns.length === 0 && secretPatterns.length === 0 && !entropy) {
    return { ok: false, reason: "토큰화 대상 패턴이 설정에 없음 — 검증 불가(fail-safe)" };
  }

  const tokenize = (s: string): string => {
    let result = tokenizeByPatterns(s, piiPatterns, "PII");
    result = tokenizeByPatterns(result, secretPatterns, "SECRET");
    if (entropy) result = tokenizeEntropyRuns(result, entropy);
    return result;
  };

  const collected: string[] = [];
  const value = walkAndTokenize(payload, tokenize, collected);

  // 검증 단계: 자체 토큰을 제거한 뒤 재스캔 — 잔여 PII/비밀이 있으면 실패 (fail-safe)
  for (const s of collected) {
    const clean = stripVaultTokens(s);
    for (const { pattern } of [...piiPatterns, ...secretPatterns]) {
      if (new RegExp(pattern).test(clean)) {
        return { ok: false, reason: "토큰화 후에도 PII/비밀 패턴이 잔존 — 검증 실패" };
      }
    }
    if (entropy) {
      const runs = clean.match(candidateRunRegex(entropy.minLength)) ?? [];
      if (runs.some((run) => shannonEntropy(run) >= entropy.entropyThreshold)) {
        return { ok: false, reason: "토큰화 후에도 고엔트로피 문자열이 잔존 — 검증 실패" };
      }
    }
  }
  return { ok: true, value };
}
