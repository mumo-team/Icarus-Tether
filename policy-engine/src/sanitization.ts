/**
 * 검증된 정화(declassification)의 실제 구현.
 *
 * 두 방식 모두 AI 판단이 아니라 결정론적 규칙이며, "검증을 통과했을 때만"
 * 성공을 반환한다. 호출부(attemptSanitization)는 성공한 경우에만 태그를
 * 해제하고, 실패하면 태그를 유지한다(fail-safe).
 *
 * 1. 구조화 추출(STRUCTURED_EXTRACTION):
 *    미리 정의된 좁은 스키마의 필드만 새 객체로 복사하고 나머지는 전부
 *    버린다. 각 필드는 enum 멤버십·길이 상한·안전 문자셋을 통과해야 하므로,
 *    프롬프트 인젝션 지시문·URL·코드 같은 위험 페이로드가 담길 그릇 자체가
 *    없다. → UNTRUSTED_ORIGIN 해제 근거.
 *
 * 2. PII 토큰화(TOKENIZATION):
 *    이메일·주민등록번호·전화번호·카드번호를 정규식으로 탐지해 불투명
 *    토큰으로 치환한다. 원본은 인메모리 볼트에만 남는다. 치환 후 전체를
 *    재스캔해 잔여 PII가 없음을 확인해야 성공. → SENSITIVE 해제 근거.
 */

import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// 1. 스키마 기반 구조화 추출
// ---------------------------------------------------------------------------

export const ALLOWED_RECORD_TYPES = ["order", "invoice", "ticket", "note"] as const;
export type AllowedRecordType = (typeof ALLOWED_RECORD_TYPES)[number];

/** 추출 결과로 허용되는 유일한 형태 — 이 좁은 그릇 밖의 값은 존재할 수 없다 */
export interface ExtractedRecord {
  type: AllowedRecordType;
  name: string;
}

export const NAME_MAX_LENGTH = 20;
/** 글자(한글 포함)·숫자·공백·. _ - 만 허용. 콜론/따옴표/괄호/슬래시가 없으므로 URL·지시문·코드가 성립 불가 */
const SAFE_NAME_PATTERN = /^[\p{L}\p{N} ._-]+$/u;

export type SanitizeOutcome =
  | { ok: true; value: unknown }
  | { ok: false; reason: string };

export function extractStructured(payload: unknown): SanitizeOutcome {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, reason: "페이로드가 객체가 아님 — 구조화 추출 불가" };
  }
  const obj = payload as Record<string, unknown>;

  const type = obj.type;
  if (typeof type !== "string" || !(ALLOWED_RECORD_TYPES as readonly string[]).includes(type)) {
    return { ok: false, reason: `type이 허용 enum(${ALLOWED_RECORD_TYPES.join("|")})에 없음` };
  }

  const name = obj.name;
  if (typeof name !== "string" || name.length === 0 || name.length > NAME_MAX_LENGTH) {
    return { ok: false, reason: `name은 1~${NAME_MAX_LENGTH}자 문자열이어야 함` };
  }
  if (!SAFE_NAME_PATTERN.test(name)) {
    return { ok: false, reason: "name에 안전 문자셋 밖의 문자가 포함됨" };
  }

  // 스키마에 정의된 필드만 복사 — 그 외 키는 전부 버려진다
  const value: ExtractedRecord = { type: type as AllowedRecordType, name };
  return { ok: true, value };
}

// ---------------------------------------------------------------------------
// 2. PII 토큰화
// ---------------------------------------------------------------------------

const PII_PATTERNS: ReadonlyArray<{ type: string; regex: RegExp }> = [
  // 주민등록번호 (YYMMDD-#######)
  { type: "RRN", regex: /\b\d{6}-[1-4]\d{6}\b/g },
  // 카드번호 (4-4-4-4, 구분자 유무 허용)
  { type: "CARD", regex: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g },
  // 휴대전화 (01x)
  { type: "PHONE", regex: /\b01[016789]-?\d{3,4}-?\d{4}\b/g },
  // 이메일
  { type: "EMAIL", regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
];

/** 토큰 → 원본. 인메모리 볼트(데모용). 실제 배포에서는 별도 암호화 저장소로 교체. */
const vault = new Map<string, string>();

function makeToken(type: string, original: string): string {
  // 같은 값 → 같은 토큰 (결정론). 해시라 토큰에서 원본 역산 불가.
  const digest = createHash("sha256").update(original).digest("hex").slice(0, 12);
  const token = `[PII_${type}_${digest}]`;
  vault.set(token, original);
  return token;
}

/** 볼트에서 원본 복원 (승인된 내부 소비자 전용) */
export function resolveToken(token: string): string | undefined {
  return vault.get(token);
}

function tokenizeString(text: string): string {
  let result = text;
  for (const { type, regex } of PII_PATTERNS) {
    result = result.replace(regex, (match) => makeToken(type, match));
  }
  return result;
}

function containsPII(text: string): boolean {
  return PII_PATTERNS.some(({ regex }) => new RegExp(regex.source, "u").test(text));
}

/** 문자열을 재귀적으로 치환하고, 남은 문자열들을 수집해 재검증에 쓴다 */
function walkAndTokenize(value: unknown, collected: string[]): unknown {
  if (typeof value === "string") {
    const replaced = tokenizeString(value);
    collected.push(replaced);
    return replaced;
  }
  if (Array.isArray(value)) {
    return value.map((v) => walkAndTokenize(v, collected));
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = walkAndTokenize(v, collected);
    }
    return out;
  }
  return value; // number/boolean/null 등은 그대로
}

export function tokenizePII(payload: unknown): SanitizeOutcome {
  const collected: string[] = [];
  const value = walkAndTokenize(payload, collected);

  // 검증 단계: 치환 후에도 PII 패턴이 남아 있으면 실패 (fail-safe)
  const leftover = collected.find((s) => containsPII(s));
  if (leftover !== undefined) {
    return { ok: false, reason: "토큰화 후에도 PII 패턴이 잔존 — 검증 실패" };
  }
  return { ok: true, value };
}
