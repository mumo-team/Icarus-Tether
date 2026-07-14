/**
 * 비밀 탐지 3단 중 2·3순위의 결정론적 로직.
 * (1순위 "출처 기반"은 태깅 시점(index.ts)에서 처리 — 내용을 볼 필요가 없으므로)
 *
 *   2순위: 엔트로피 기반 — 형식을 몰라도 "길고 무작위한 문자열"을 잡는다.
 *          블랙리스트(알려진 패턴)에 없는 새 형식의 토큰·키까지 커버.
 *   3순위: 정규식 — AWS 키·GitHub 토큰 등 유명 포맷만 보조로. 타입명이 붙어
 *          감사로그 가독성이 좋다는 것 외의 역할은 없다.
 *
 * 임계값·패턴은 전부 설정(SecretDetectionConfig)에서 온다. 코드는 로직만.
 */

import type { EntropyConfig, SecretDetectionConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Shannon 엔트로피
// ---------------------------------------------------------------------------

/** 문자 빈도 기반 Shannon 엔트로피 (비트/문자). 무작위일수록 높다. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// 후보 추출 — 비밀이 될 수 있는 "긴 연속 문자열(run)"만 검사한다.
// 한글·일반 문장은 공백과 문자 종류 때문에 긴 run이 생기지 않아 오탐이 없다.
// ---------------------------------------------------------------------------

/** base64·hex·URL-safe 토큰류에 쓰이는 문자들의 연속 구간 */
export function candidateRunRegex(minLength: number): RegExp {
  return new RegExp(`[A-Za-z0-9+/=_-]{${minLength},}`, "g");
}

// ---------------------------------------------------------------------------
// 자체 볼트 토큰 제외 — 우리가 치환해 넣은 토큰([PII_…]/[SECRET_…])을
// 다시 비밀로 오탐하면 토큰화 검증이 영원히 실패하므로, 검사 전에 제거한다.
// ---------------------------------------------------------------------------

export const VAULT_TOKEN_PATTERN = /\[(?:PII|SECRET)_[A-Z0-9_]+_[0-9a-f]{12}\]/;

/** 볼트 토큰을 공백으로 치환해 run이 이어지지 않게 한다 */
export function stripVaultTokens(text: string): string {
  return text.replace(new RegExp(VAULT_TOKEN_PATTERN.source, "g"), " ");
}

// ---------------------------------------------------------------------------
// 탐지
// ---------------------------------------------------------------------------

export interface DetectedSecret {
  /** 3순위 매치는 설정의 type(예: AWS_KEY), 2순위 매치는 "HIGH_ENTROPY" */
  type: string;
  value: string;
}

export function detectSecretsInString(text: string, det: SecretDetectionConfig): DetectedSecret[] {
  const found: DetectedSecret[] = [];
  // 자체 토큰은 검사 대상에서 제외 (자기-오탐 방지)
  let remainder = stripVaultTokens(text);

  // 3순위: 정규식 (보조). 매치 구간은 제거해 2순위와 중복 탐지되지 않게 한다.
  for (const { type, pattern } of det.byRegex) {
    remainder = remainder.replace(new RegExp(pattern, "g"), (match) => {
      found.push({ type, value: match });
      return " ";
    });
  }

  // 2순위: 엔트로피 — 형식을 몰라도 잡는 본선
  if (det.byEntropy) {
    found.push(...detectByEntropy(remainder, det.byEntropy));
  }
  return found;
}

function detectByEntropy(text: string, cfg: EntropyConfig): DetectedSecret[] {
  const runs = text.match(candidateRunRegex(cfg.minLength)) ?? [];
  return runs
    .filter((run) => shannonEntropy(run) >= cfg.entropyThreshold)
    .map((run) => ({ type: "HIGH_ENTROPY", value: run }));
}

/** 페이로드(문자열/객체/배열 중첩)를 재귀 순회하며 비밀을 수집한다 */
export function detectSecrets(value: unknown, det: SecretDetectionConfig): DetectedSecret[] {
  if (typeof value === "string") return detectSecretsInString(value, det);
  if (Array.isArray(value)) return value.flatMap((v) => detectSecrets(v, det));
  if (typeof value === "object" && value !== null) {
    return Object.values(value).flatMap((v) => detectSecrets(v, det));
  }
  return [];
}
