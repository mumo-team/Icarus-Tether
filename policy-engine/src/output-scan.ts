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
 * 은닉 채널(covert channel) 세탁 전처리 — 위 두 검사가 볼 haystack을 확장한다:
 *  ① percent-decoding — 마크다운/이미지 URL에 `%40`처럼 인코딩돼 실린 민감값을
 *     원문으로 되돌린다(malformed는 안전 스킵, 이중 인코딩 2패스). 정상 URL은 no-op.
 *  ② URL 세그먼트 분할 + base64 다경로 디코딩 — base64가 URL 경로(`/<b64>.png`)에 실릴 때
 *     `/`·`.`가 base64 charset(+/)과 겹쳐 run에 병합돼 디코딩이 깨지는 것을 막는다. 구분자
 *     분할 + URL-safe(-_) 정규화 + 리딩 쓰레기 오프셋 재시도(decodeBase64Runs). 전체 문자열
 *     스캔은 유지하므로 정상 base64는 그대로 잡혀 순수 additive(쿼리 `?d=` 탐지 회귀 없음).
 *  ③ hex 인코딩 (RS13) — ★ 방향을 뒤집는다: 임의 hex를 디코딩(decode-haystack)하면
 *     SHA·UUID·색상코드 등 정상 hex가 도처에 있어 과차단이 터진다. 대신 민감값을
 *     hex 인코딩해 원문에서 찾는다(encode-needle, 포함검사 (c)). 아는 시크릿의 hex만
 *     needle이므로 과차단이 "구조적으로" 0 — base64 정준성 게이트의 hex판이다. hex는
 *     바이트별이라 hex(v)가 hex(blob-of-v)의 부분문자열로 들어가 blob도 자동 커버.
 *
 * 프라이버시: finding에 원본을 싣지 않는다 (길이 + sha256 접두만).
 *
 * ★ 문서화된 한계 (정직성 — fail-open 한계들과 동일 취급):
 *  - AI 응답 텍스트: 프록시는 도구 호출(tools/call) args만 검사한다. LLM 호스트가
 *    사용자에게 직접 렌더하는 응답 텍스트의 마크다운 이미지/링크는 도구 호출이
 *    아니라 게이트를 통과하지 않는다 — 이 스캐너의 범위 밖(설계 경계). 우리 방어는
 *    "행동(도구 호출)의 길목"을 검사하는 것이므로, 응답-텍스트 exfil은 out of scope.
 *  - min-length(12) 미만 짧은 민감값은 우연 매치 방지를 위해 제외 → evade 가능.
 *  - 인코딩 "전에" 변형(압축·암호화)한 뒤 hex/base64 하는 세탁은 미탐 — 그건 hex/base64
 *    인코딩이 아니라 별개 변환이라 결정론 디코더로는 원본 바이트가 남지 않는다.
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
 * base64로 보이는 연속 구간(run). 표준 charset(`+/`)과 URL-safe charset(`-_`)을 각각.
 * 인코딩 ≥16자만 후보 — 디코딩 ≥12바이트라야 포함검사(min-length 12) 통과 가능하고,
 * 짧은 정상 단어("test"·"name")는 애초에 후보에서 빠져 우연 디코드 오탐을 원천 차단.
 */
const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}/g;
const URLSAFE_B64_RUN = /[A-Za-z0-9_-]{16,}/g;

/** 리딩 URL 쓰레기(`host/…/`) 대응으로 시도할 내부 `/` 접미부 최대 개수 (성능 유계). */
const OFFSET_SLASH_TRIES = 8;

/** 유효 UTF-8 텍스트인가 — 디코딩이 replacement(U+FFFD) 없이 왕복하면 "의미있는 평문". */
function isMeaningfulText(decoded: string, bytes: Buffer): boolean {
  if (decoded.includes("�")) return false; // 이진 쓰레기(SHA 디코딩 등) 탈락
  return Buffer.from(decoded, "utf8").equals(bytes); // utf8 왕복 일치
}

/**
 * base64 후보 하나를 게이트 통과 시 디코딩 평문으로 out에 추가하고 성공 여부를 돌려준다.
 * 표준 run·정규화된 URL-safe·오프셋 접미부가 공유하는 단일 판정부.
 * 게이트: 길이 → base64 가능 길이 → 디코딩 → min-length → ★정준성(재인코딩 일치) → 유효 UTF-8.
 * ★ 정준성 검사가 핵심 과차단 가드다 — URL-safe(-_)·오프셋 확장이 정상 텍스트
 *   (snake_case·kebab-case·UUID·파일경로)를 디코딩해도, 재인코딩이 원본과 왕복하지
 *   않으면(정상 텍스트는 거의 항상 비정준) 폐기된다.
 */
function tryDecodeBase64Candidate(candidate: string, out: string[]): boolean {
  const noPad = candidate.replace(/=+$/, "");
  if (noPad.length < 16 || noPad.length % 4 === 1) return false; // 짧거나 base64 불가능 길이
  let bytes: Buffer;
  try {
    bytes = Buffer.from(candidate, "base64");
  } catch {
    return false;
  }
  if (bytes.length < OUTPUT_SCAN_MIN_LENGTH) return false; // 디코딩 <12바이트 → 매치 불가
  if (bytes.toString("base64").replace(/=+$/, "") !== noPad) return false; // 정준성
  const text = bytes.toString("utf8");
  if (!isMeaningfulText(text, bytes)) return false;
  out.push(text);
  return true;
}

/**
 * 출력 문자열들(+concat)에서 base64 run을 찾아 "의미있는 평문"으로 디코딩한 목록을 만든다.
 * 세탁(base64 인코딩) 민감을 포함검사가 볼 수 있게 하는 전처리. 결정론(Buffer + 문자열 검사만).
 *
 * 세 경로(전부 tryDecodeBase64Candidate의 동일 게이트 통과):
 *  1) 표준 base64 run.
 *  2) ★ URL-safe base64(-_) — `-_`를 실제 포함한 run만(순수 영숫자는 표준 패스가 처리)
 *     `-→+ _→/` 정규화 후. URL-safe는 `/`를 안 쓰므로 URL 경로에서 charset이 자연히
 *     경계를 만들어(세그먼트 분할 불필요) 깨끗이 잡힌다.
 *  3) ★ 리딩 URL 쓰레기 대응(미탐 ②) — 표준 run의 통짜 디코딩이 실패했을 때만, run 내부
 *     각 `/` 뒤 접미부를 재시도(최대 OFFSET_SLASH_TRIES). `host/<b64>` 병합으로 앞부분이
 *     쓰레기가 되는 경우, 내부 `/`를 유지한 접미부가 깨끗한 base64가 된다. 실패 시에만
 *     돌므로 정상 base64 비용은 불변, 정준성 게이트가 정상 경로 텍스트를 거른다.
 */
function decodeBase64Runs(strings: readonly string[]): string[] {
  const decoded: string[] = [];
  for (const s of strings) {
    for (const run of s.match(BASE64_RUN) ?? []) {
      if (tryDecodeBase64Candidate(run, decoded)) continue; // 통짜 성공이면 오프셋 불필요
      let idx = run.indexOf("/");
      for (let tries = 0; idx !== -1 && tries < OFFSET_SLASH_TRIES; tries++) {
        tryDecodeBase64Candidate(run.slice(idx + 1), decoded);
        idx = run.indexOf("/", idx + 1);
      }
    }
    for (const run of s.match(URLSAFE_B64_RUN) ?? []) {
      if (!/[-_]/.test(run)) continue; // 순수 영숫자 run은 표준 패스가 이미 처리
      tryDecodeBase64Candidate(run.replace(/-/g, "+").replace(/_/g, "/"), decoded);
    }
  }
  return decoded;
}

/**
 * ★ 미탐 ① percent-decoding (안전) — `%40` 등으로 URL에 실린 민감값을 원문으로 되돌린다.
 * 유효한 `%XX` 연속 런만 함께 디코딩하고(멀티바이트 UTF-8 왕복 대응), malformed 런은 그대로
 * 둔다(throw 없음). 이중 인코딩(`%2540`) 대비 최대 2패스 — 원본과 같아지면 조기 종료.
 * 정상 URL(퍼센트 없음/변화 없음)은 입력을 그대로 돌려주므로 호출부가 no-op으로 버린다.
 */
const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2})+/g;
function percentDecodeLoose(s: string): string {
  let cur = s;
  for (let pass = 0; pass < 2 && cur.includes("%"); pass++) {
    const next = cur.replace(PERCENT_RUN, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m; // malformed 시퀀스는 안전하게 원문 유지
      }
    });
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/**
 * ★ 미탐 ② URL 구조 세그먼트 분할 — base64가 URL 경로(`/<b64>.png`)에 실릴 때 `/`·`.`가
 * base64 charset(`+/`)과 겹쳐 하나의 run으로 병합되면, 디코딩 결과 앞부분이 쓰레기 바이트가
 * 되어 유효 UTF-8 검사에 걸려 run 전체가 폐기된다(그 안에 진짜 시크릿이 있어도). 구분자로
 * 잘라 각 세그먼트를 깨끗한 base64 후보로 만든다. base64 run 최소 길이(16) 미만은 제외.
 *
 * `=`(base64 패딩)·`%`(percent-decoding이 담당)는 구분자에서 뺀다. 전체 문자열 스캔은
 * 그대로 유지되므로(호출부), `/` 포함 정상 base64는 여전히 통짜로 잡혀 이 분할은 additive다.
 */
const URL_DELIM = /[/?&#.:@]+/;
function urlSegments(s: string): string[] {
  return s.split(URL_DELIM).filter((seg) => seg.length >= 16);
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

  // ★ 은닉 채널 세탁 전처리 (미탐 ①②). 전부 결정론·O(size), needle-regex 최적화 불변.
  //  ① percent-decoding한 변형을 haystack 계열에 추가(변화 있을 때만 — 정상 URL은 no-op).
  const percentDecoded: string[] = [];
  for (const b of containmentBases) {
    const d = percentDecodeLoose(b);
    if (d !== b) percentDecoded.push(d);
  }
  const scanBases = [...containmentBases, ...percentDecoded]; // 포함검사·정규식이 볼 원문 계열
  //  ② base64 디코딩 입력을 구성한다. concat(청크 재조립 parts[] 커버)에 더해 ★개별 인자
  //     문자열(outStrings)도 넣는다 — 여러 인자를 구분자 없이 이어붙인 concat에서는 앞 인자의
  //     ASCII 꼬리가 base64 run에 접합돼 4바이트 정렬이 깨지고 정준성 게이트에서 폐기된다
  //     (send_email({to,subject,body:<b64>}) 같은 필드 단위 세탁 미탐 — e2e 발견). 개별 필드는
  //     깨끗한 경계를 줘 그대로 디코딩된다. URL 세그먼트도 더해 경로에 실린 base64를 잡는다.
  //     전부 정준성 게이트(재인코딩 왕복)를 통과해야 하므로 순수 additive(과차단 0). 단일 필드일
  //     땐 concat===outStrings[0]이라 개별 추가가 무의미하므로 다필드일 때만 더한다(핫패스 비용 불변).
  const b64Inputs = outStrings.length > 1 ? [...scanBases, ...outStrings] : scanBases;
  const b64Sources = [...b64Inputs, ...b64Inputs.flatMap(urlSegments)];
  // dedup: concat과 개별 필드가 같은 run을 중복 디코딩할 수 있어 haystack 비용을 여기서 상한한다.
  const decodedStrings = [...new Set(decodeBase64Runs(b64Sources))];

  // 1. 포함검사: (concat·percent-decoded) + 디코딩 평문을 haystack으로. min-length가 우연 매치를 막는다.
  if (scanBases.length > 0) {
    const haystacks = [...scanBases, ...decodedStrings];
    // 정규화 폴백용 haystack은 "아주 긴 needle"이 나올 때만 지연 생성(대부분 생략 → 대용량 무손실 최적화).
    let normHaystacksLazy: string[] | null = null;
    const normHaystacks = (): string[] => (normHaystacksLazy ??= haystacks.map(normalizeText));
    for (const { toolName, payload } of sensitivePayloads) {
      const values: string[] = [];
      collectStrings(payload, values);
      for (const v of values) {
        if (v.length < minLength) continue; // 짧은 값은 어떤 needle도 안 씀 (우연 매치 방지)
        // (a) 정확 포함검사 — 무손실. 원문/base64 그대로 실린 경우.
        if (haystacks.some((h) => h.includes(v))) {
          return { kind: "containment", sourceTool: toolName, matchLen: v.length, valueHash: hashValue(v) };
        }
        // (b) 정규화 포함검사 — 대소문자·구분자 재포맷을 견딘다. min-length는 normalize 후 길이에.
        //     짧은 needle은 needle-regex(대용량 haystack normalize 안 함), 초과분만 폴백(무손실).
        const nv = normalizeText(v);
        if (nv.length >= minLength) {
          const matched =
            nv.length <= NEEDLE_REGEX_MAX
              ? matchNormalizedNeedle(nv, haystacks)
              : normHaystacks().some((h) => h.includes(nv));
          if (matched) {
            return { kind: "containment", sourceTool: toolName, matchLen: nv.length, valueHash: hashValue(v), normalized: true };
          }
        }
        // (c) ★ hex 세탁 탐지 (RS13) — encode-needle: 민감값을 hex 인코딩해 원문에서 찾는다.
        //     decode-haystack(임의 hex 디코딩)과 달리 SHA·UUID·색상코드 등 정상 hex를
        //     디코딩하지 않으므로 과차단이 "구조적으로" 0이다(정준성 게이트의 hex판).
        //     hex는 바이트별 인코딩이라 hex(v)가 hex(v를 품은 더 큰 블롭)의 부분문자열로
        //     그대로 들어가므로, blob-of-secret도 별도 디코딩 없이 자동 커버된다.
        //
        //     ★ 정규화 haystack에 plain includes로 검색한다(matchNormalizedNeedle 정규식이
        //     아니라). 이유: hex needle은 charset이 16심볼뿐이라 needle-regex
        //     `4[^X]*d[^X]*5…`가 구분자 많은 haystack(`#a1 #b2 …`)에서 준일치 폭증으로
        //     catastrophic backtracking을 일으킨다(실측 확인). 정규화(구분자 제거+소문자)
        //     후 substring 검색은 O(size) 선형이고, 대소문자(4D..)·바이트 구분자
        //     (4d:59, 4d 59)를 그대로 흡수해 동일 탐지력을 낸다. normHaystacks는 메모이즈.
        const hv = Buffer.from(v, "utf8").toString("hex"); // 소문자, 길이 2·v.length ≥ 2·minLength
        if (normHaystacks().some((h) => h.includes(hv))) {
          return { kind: "containment", sourceTool: toolName, matchLen: hv.length, valueHash: hashValue(v), normalized: true };
        }
      }
    }
  }

  // 2. 정규식(byRegex)만 — byEntropy는 의도적으로 제외(고엔트로피 정상값 과차단 방지).
  //    디코딩 평문도 함께 스캔 → base64된 AWS/GitHub 키도 덤으로 잡힌다.
  const byRegex = secretDetection?.byRegex ?? [];
  if (byRegex.length > 0) {
    const regexOnly: SecretDetectionConfig = { bySource: false, byEntropy: null, byRegex };
    for (const s of [...outStrings, ...percentDecoded, ...decodedStrings]) {
      const found = detectSecretsInString(s, regexOnly);
      if (found.length > 0) {
        return { kind: "regex", matchLen: found[0].value.length, valueHash: hashValue(found[0].value) };
      }
    }
  }

  return null;
}
