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

  // 1. 포함검사: 개별 출력 문자열 + 전체 concat(청크 재조립) 을 haystack으로.
  if (outStrings.length > 0) {
    const haystacks = outStrings.length > 1 ? [...outStrings, outStrings.join("")] : outStrings;
    for (const { toolName, payload } of sensitivePayloads) {
      const values: string[] = [];
      collectStrings(payload, values);
      for (const v of values) {
        if (v.length < minLength) continue; // 짧은 값은 우연일치 방지로 제외
        if (haystacks.some((h) => h.includes(v))) {
          return { kind: "containment", sourceTool: toolName, matchLen: v.length, valueHash: hashValue(v) };
        }
      }
    }
  }

  // 2. 정규식(byRegex)만 — byEntropy는 의도적으로 제외(고엔트로피 정상값 과차단 방지).
  const byRegex = secretDetection?.byRegex ?? [];
  if (byRegex.length > 0) {
    const regexOnly: SecretDetectionConfig = { bySource: false, byEntropy: null, byRegex };
    for (const s of outStrings) {
      const found = detectSecretsInString(s, regexOnly);
      if (found.length > 0) {
        return { kind: "regex", matchLen: found[0].value.length, valueHash: hashValue(found[0].value) };
      }
    }
  }

  return null;
}
