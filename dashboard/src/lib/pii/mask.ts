/**
 * PII 마스킹 — C 담당(책임 2).
 *
 * 정규식 기반이다. NER 기반 고급 탐지는 시간 제약으로 명시적으로 범위에서 뺐다.
 * 따라서 "형식이 정해진 식별자"만 잡고, 사람 이름·주소처럼 형식이 없는 값은 못 잡는다.
 * 구조화된 값의 해제는 정책 엔진의 검증된 정화(attemptSanitization)가 담당하고,
 * 이쪽은 자유 텍스트 안에 섞여 들어온 식별자를 담당한다.
 */

interface PiiPattern {
  /** 진단·테스트용 이름 */
  name: string;
  pattern: RegExp;
  replacement: string;
  /** 정규식만으론 오탐이 많은 패턴의 2차 검증 — 통과한 것만 마스킹한다 */
  validate?: (match: string) => boolean;
}

/**
 * 카드번호 체크섬(Luhn).
 * 정규식만 쓰면 16자리 주문번호·송장번호까지 전부 가려져 로그를 읽을 수 없게 된다.
 * 체크섬을 통과한 것만 카드로 보아, "가려야 할 것"과 "가리면 안 되는 것"을 나눈다.
 */
export function luhnValid(candidate: string): boolean {
  const d = candidate.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** IPv4 각 옥텟이 0~255인지. \d{1,3}만으론 999.999.999.999도 통과한다. */
function ipv4Valid(match: string): boolean {
  return match.split(".").every((o) => o.length <= 3 && Number(o) <= 255);
}

// 순서에 의미가 있다: 더 구체적인 형식을 먼저 적용해야, 뒤 패턴이 앞 패턴의
// 대상 일부만 먹고 나머지 조각을 흘리는 일이 없다.
const PATTERNS: PiiPattern[] = [
  { name: "RRN", pattern: /\b\d{6}-[1-4]\d{6}\b/g, replacement: "[RRN_REDACTED]" },
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[SSN_REDACTED]" },
  {
    name: "CARD",
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    replacement: "[CARD_REDACTED]",
    validate: luhnValid,
  },
  { name: "EMAIL", pattern: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, replacement: "[EMAIL_REDACTED]" },
  { name: "PHONE", pattern: /\b01[016789][- ]?\d{3,4}[- ]?\d{4}\b/g, replacement: "[PHONE_REDACTED]" },
  {
    name: "IP",
    pattern: /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
    replacement: "[IP_REDACTED]",
    validate: ipv4Valid,
  },
];

/** 자유 텍스트 한 덩어리에서 식별자를 가린다. */
export function maskPii(text: string): string {
  return PATTERNS.reduce(
    (acc, { pattern, replacement, validate }) =>
      acc.replace(pattern, (match) => (validate && !validate(match) ? match : replacement)),
    text
  );
}

/**
 * 객체·배열 안에 박힌 문자열까지 재귀로 가린다.
 * 도구 인자/결과는 중첩 JSON이라, 최상위 문자열만 가리면 한 겹만 들어가도 그대로 샌다.
 * 문자열이 아닌 값(숫자·불리언·null)은 형태를 보존한다 — 마스킹은 표시의 문제이지
 * 구조를 바꾸는 일이 아니다.
 */
export function maskPiiDeep<T>(value: T, seen: WeakSet<object> = new WeakSet()): T {
  if (typeof value === "string") return maskPii(value) as unknown as T;
  if (value === null || typeof value !== "object") return value;
  // 순환 참조가 있으면 무한 재귀로 프로세스가 죽는다. 이미 본 객체는 그대로 돌려준다.
  if (seen.has(value as object)) return value;
  seen.add(value as object);
  if (Array.isArray(value)) {
    return value.map((v) => maskPiiDeep(v, seen)) as unknown as T;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = maskPiiDeep(v, seen);
  }
  return out as unknown as T;
}