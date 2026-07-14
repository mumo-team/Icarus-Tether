/**
 * 비밀 탐지(2·3순위) 단위 테스트 — 엔트로피·정규식·자기-오탐 방지.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { detectSecrets, shannonEntropy } from "./secret-detection.js";
import type { SecretDetectionConfig } from "./config.js";

const DET: SecretDetectionConfig = {
  bySource: true,
  byEntropy: { minLength: 20, entropyThreshold: 3.8 },
  byRegex: [
    { type: "AWS_KEY", pattern: "\\bAKIA[0-9A-Z]{16}\\b" },
    { type: "GITHUB_TOKEN", pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b" },
  ],
};

test("shannonEntropy: 반복 문자열은 낮고 무작위 문자열은 높다", () => {
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
  // 32자 전부 서로 다른 문자 → log2(32) = 5.0
  const distinct32 = "kJ8xQ2mZ9vL4nR7tB1wY5cF3hD6pS0aG";
  assert.ok(shannonEntropy(distinct32) > 4.5);
});

test("3순위 정규식: AWS 키·GitHub 토큰을 타입명과 함께 탐지 (보조)", () => {
  const found = detectSecrets("빌드 로그: AKIAIOSFODNN7EXAMPLE 노출됨", DET);
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "AWS_KEY");
  assert.equal(found[0].value, "AKIAIOSFODNN7EXAMPLE");

  const gh = detectSecrets("token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", DET);
  assert.ok(gh.some((s) => s.type === "GITHUB_TOKEN"));
});

test("2순위 엔트로피: 형식을 모르는 무작위 문자열도 탐지 (블랙리스트 탈피)", () => {
  const found = detectSecrets("custom_key=kJ8xQ2mZ9vL4nR7tB1wY5cF3hD6pS0aG", DET);
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "HIGH_ENTROPY");
});

test("일반 문장(한국어·영어)은 탐지하지 않는다 — 오탐 없음", () => {
  assert.deepEqual(detectSecrets("이것은 평범한 한국어 문장입니다. 비밀이 없어요.", DET), []);
  assert.deepEqual(
    detectSecrets("this is a perfectly normal sentence about code review", DET),
    []
  );
});

test("자기-오탐 방지: 이미 치환된 볼트 토큰은 비밀로 재탐지하지 않는다", () => {
  assert.deepEqual(detectSecrets("[SECRET_HIGH_ENTROPY_0a1b2c3d4e5f] 처리 완료", DET), []);
  assert.deepEqual(detectSecrets("[PII_EMAIL_abcdef012345]로 연락", DET), []);
});

test("중첩 객체·배열 내부까지 재귀 탐지한다", () => {
  const found = detectSecrets(
    { logs: [{ line: "key: AKIAIOSFODNN7EXAMPLE" }], meta: { ok: true, n: 1 } },
    DET
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].type, "AWS_KEY");
});

test("byEntropy가 꺼져 있으면(null) 정규식 티어만 동작한다", () => {
  const regexOnly: SecretDetectionConfig = { ...DET, byEntropy: null };
  assert.deepEqual(detectSecrets("kJ8xQ2mZ9vL4nR7tB1wY5cF3hD6pS0aG", regexOnly), []);
  assert.equal(detectSecrets("AKIAIOSFODNN7EXAMPLE", regexOnly).length, 1);
});
