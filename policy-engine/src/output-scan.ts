/**
 * TIER3 출력-스캔 — 나가는 값(sink args)의 *내용*을 직접 검사해 "세탁된 민감 유출"을
 * 값-축에서 잡는다. 값-계보(VALUE_MATCH)는 세탁(청크·인코딩)으로 무력화되지만, 실제
 * 민감 바이트가 출력에 남아 있으면 여기서 잡힌다 (미탐 #1 벡터 A 대응).
 *
 * 두 결정론적 검사만 (AI 판단 없음):
 *  1. 포함검사(containment) — 이 세션이 실제로 읽은 민감 원본값(payloadStore의
 *     SENSITIVE 레코드)이 출력 문자열(또는 그 concat)의 부분문자열인가. concat은 단순
 *     청크 재조립(예: parts:["MYSECRE","TPASSW",...])을 잡는다.
 *  2. 정규식(regex) — 설정 secretDetection.byRegex(AWS/GitHub 등)로 출력에서 verbatim
 *     키를 잡는다. ★엔트로피(byEntropy)는 쓰지 않는다 — 고엔트로피 정상값(git SHA·UUID·
 *     JWT·integrity 해시)을 대량 과차단하기 때문(그 착시를 벤치가 숨긴다).
 *
 * 프라이버시: finding에 원본을 싣지 않는다 (길이 + sha256 접두만).
 */

import { createHash } from "node:crypto";
import { detectSecretsInString } from "./secret-detection.js";
import type { SecretDetectionConfig } from "./config.js";

/**
 * 이 길이 미만의 민감 필드값은 포함검사에서 제외한다 — 짧은 공통값("VIP"·등급·
 * 흔한 단어)이 정상 출력에 우연히 포함돼 오탐 나는 것을 막는다. 설정으로 하향 가능.
 * (트레이드오프: 이 길이 미만의 짧은 민감값은 evade — 문서화된 한계.)
 */
export const OUTPUT_SCAN_MIN_LENGTH = 12;

export interface SensitivePayload {
  toolName: string;
  payload: unknown;
}

export interface OutputScanFinding {
  kind: "containment" | "regex";
  /** containment일 때, 그 민감 원본을 만든 소스 도구 */
  sourceTool?: string;
  matchLen: number;
  valueHash: string;
  /** 정규화 매칭으로 잡혔는가 (재포맷 세탁 — 대소문자·구분자 차이) */
  normalized?: boolean;
}

/**
 * 정규화 — 소문자 + 문자/숫자만 남긴다(구분자·구두점·공백 제거, 유니코드 letter 유지).
 * 재포맷 세탁(대소문자·`=`·`-`·`_`·공백 변경, 예: "SECRET=Kx.." ↔ "SecretKx..")을 견디는 매칭용.
 * min-length는 normalize 후 길이에 적용하므로 짧은 자연어값(예 "홍길동 VIP"→6자)은 자동 제외된다.
 * (짧은 needle 정규화에만 쓴다 — 대용량 haystack은 normalize하지 않고 matchNormalizedNeedle 사용.)
 */
function normalizeText(s: string): string {
  return s.replace(/[^\p{L}\p{N}]/gu, "").toLowerCase();
}

/**
 * 이 길이 이하의 정규화 needle은 needle-regex로 매칭한다(대용량 haystack을 normalize하지 않음).
 * 초과 시에만 normalize(haystack) 폴백 — 무손실 유지(아주 긴 민감값은 드묾).
 */
const NEEDLE_REGEX_MAX = 512;

/**
 * ★ 성능(대용량 무손실): "normalize(needle) ⊂ normalize(haystack)"를, 거대한 haystack을
 * normalize해 만들지 않고 **원본 haystack을 짧은 needle에서 만든 정규식으로 1패스** 검사한다.
 * nv(정규화된 needle)의 각 문자 사이에 "비영숫자만"(`[^\p{L}\p{N}]*`)을 허용하면, 그 사이에 다른
 * 영숫자가 없다는 뜻 = 정규화 후 연속 = 정규화 부분문자열과 논리적 동치. nv는 normalize 결과라
 * 소문자 영숫자·유니코드 문자뿐이라 정규식 메타문자가 없어 안전하다. 대소문자는 `i` 플래그로.
 * (구분자만 있는 병리 입력·준일치에서도 백트래킹이 선형 유계임을 실측 확인.)
 */
function matchNormalizedNeedle(nv: string, haystacks: readonly string[]): boolean {
  const pattern = Array.from(nv).join("[^\\p{L}\\p{N}]*");
  const re = new RegExp(pattern, "iu");
  return haystacks.some((h) => re.test(h));
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) collectStrings(v, out);
  else if (typeof value === "object" && value !== null)
    for (const v of Object.values(value)) collectStrings(v, out);
}

function hashValue(v: string): string {
  return createHash("sha256").update(v).digest("hex").slice(0, 16);
}

/**
 * base64로 보이는 연속 구간(run). 표준 base64 charset만(url변형 -_ 는 다음 단계).
 * 인코딩 ≥16자만 후보 — 디코딩 ≥12바이트라야 포함검사(min-length 12) 통과 가능하고,
 * 짧은 정상 단어("test"·"name")는 애초에 후보에서 빠져 우연 디코드 오탐을 원천 차단.
 */
const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}/g;

/** 유효 UTF-8 텍스트인가 — 디코딩이 replacement(U+FFFD) 없이 왕복하면 "의미있는 평문". */
function isMeaningfulText(decoded: string, bytes: Buffer): boolean {
  if (decoded.includes("�")) return false; // 이진 쓰레기(SHA 디코딩 등) 탈락
  return Buffer.from(decoded, "utf8").equals(bytes); // utf8 왕복 일치
}

/**
 * 출력 문자열들(+concat)에서 base64 run을 찾아 "의미있는 평문"으로 디코딩한 목록을 만든다.
 * 세탁(base64 인코딩) 민감을 포함검사가 볼 수 있게 하는 전처리. 결정론(Buffer + 문자열 검사만).
 * 게이트: charset/길이(정규식) → 정준성(재인코딩 일치) → 유효 UTF-8 → (호출부의 min-length).
 */
function decodeBase64Runs(strings: readonly string[]): string[] {
  const decoded: string[] = [];
  for (const s of strings) {
    for (const run of s.match(BASE64_RUN) ?? []) {
      if (run.replace(/=+$/, "").length % 4 === 1) continue; // base64로 불가능한 길이
      let bytes: Buffer;
      try {
        bytes = Buffer.from(run, "base64");
      } catch {
        continue;
      }
      if (bytes.length < OUTPUT_SCAN_MIN_LENGTH) continue; // 디코딩 <12바이트 → 매치 불가
      // 정준성: 재인코딩이 원본 run과 일치해야(패딩 정규화 후) — 비정준/우연 base64 배제
      if (bytes.toString("base64").replace(/=+$/, "") !== run.replace(/=+$/, "")) continue;
      const text = bytes.toString("utf8");
      if (!isMeaningfulText(text, bytes)) continue;
      decoded.push(text);
    }
  }
  return decoded;
}

/**
 * 나가는 값에서 세탁된 민감 유출을 탐지한다. 첫 finding에서 즉시 반환(차단엔 하나면 충분).
 * OUTBOUND_SINK 판정 경로에서만 호출됨 (핫패스 비용 제한).
 */
export function scanOutputForSensitive(
  sensitivePayloads: readonly SensitivePayload[],
  args: unknown,
  secretDetection: SecretDetectionConfig | null | undefined,
  minLength: number = OUTPUT_SCAN_MIN_LENGTH
): OutputScanFinding | null {
  const outStrings: string[] = [];
  collectStrings(args, outStrings);

  // ★ 성능(무손실): 포함검사 haystack은 "전체 concat" 하나면 충분하다. 개별 문자열의 내용은
  // 전부 concat의 부분문자열이므로(개별에 있으면 concat에도 있음), 개별을 따로 훑을 필요가 없다
  // — 매치 집합이 완전히 동일. 이렇게 하면 대용량에서 1MB를 여러 번 스캔하지 않는다. concat은
  // 청크 재조립(parts[])도 커버한다. base64 세탁 전처리도 이 concat에서만 수행.
  const concat = outStrings.length > 1 ? outStrings.join("") : outStrings[0] ?? "";
  const containmentBases = concat.length > 0 ? [concat] : [];
  const decodedStrings = decodeBase64Runs(containmentBases);

  // 1. 포함검사: concat + 디코딩 평문을 haystack으로. min-length가 우연 매치를 막는다.
  if (containmentBases.length > 0) {
    const haystacks = [...containmentBases, ...decodedStrings];
    // 정규화 폴백용 haystack은 "아주 긴 needle"이 나올 때만 지연 생성(대부분 생략 → 대용량 무손실 최적화).
    let normHaystacksLazy: string[] | null = null;
    const normHaystacks = (): string[] => (normHaystacksLazy ??= haystacks.map(normalizeText));
    for (const { toolName, payload } of sensitivePayloads) {
      const values: string[] = [];
      collectStrings(payload, values);
      for (const v of values) {
        // (a) 정확 포함검사 — 무손실. 원문/base64 그대로 실린 경우.
        if (v.length >= minLength && haystacks.some((h) => h.includes(v))) {
          return { kind: "containment", sourceTool: toolName, matchLen: v.length, valueHash: hashValue(v) };
        }
        // (b) 정규화 포함검사 — 대소문자·구분자 재포맷을 견딘다. min-length는 normalize 후 길이에.
        //     짧은 needle은 needle-regex(대용량 haystack normalize 안 함), 초과분만 폴백(무손실).
        const nv = normalizeText(v);
        if (nv.length < minLength) continue;
        const matched =
          nv.length <= NEEDLE_REGEX_MAX
            ? matchNormalizedNeedle(nv, haystacks)
            : normHaystacks().some((h) => h.includes(nv));
        if (matched) {
          return { kind: "containment", sourceTool: toolName, matchLen: nv.length, valueHash: hashValue(v), normalized: true };
        }
      }
    }
  }

  // 2. 정규식(byRegex)만 — byEntropy는 의도적으로 제외(고엔트로피 정상값 과차단 방지).
  //    디코딩 평문도 함께 스캔 → base64된 AWS/GitHub 키도 덤으로 잡힌다.
  const byRegex = secretDetection?.byRegex ?? [];
  if (byRegex.length > 0) {
    const regexOnly: SecretDetectionConfig = { bySource: false, byEntropy: null, byRegex };
    for (const s of [...outStrings, ...decodedStrings]) {
      const found = detectSecretsInString(s, regexOnly);
      if (found.length > 0) {
        return { kind: "regex", matchLen: found[0].value.length, valueHash: hashValue(found[0].value) };
      }
    }
  }

  return null;
}
