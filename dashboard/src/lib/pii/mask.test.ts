/**
 * PII 마스킹 테스트.
 * policy-engine(B)과 같은 규약으로 맞춘다 — node:test + node:assert/strict.
 * 실행: npm run test -w @icarus-tether/dashboard
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { maskPii, maskPiiDeep, luhnValid } from "./mask";

test("이메일을 가린다", () => {
  assert.equal(maskPii("연락처는 hong@example.com 입니다"), "연락처는 [EMAIL_REDACTED] 입니다");
});

test("한국 휴대폰을 하이픈 유무·공백 구분 없이 가린다", () => {
  assert.equal(maskPii("010-1234-5678"), "[PHONE_REDACTED]");
  assert.equal(maskPii("01012345678"), "[PHONE_REDACTED]");
  assert.equal(maskPii("010 1234 5678"), "[PHONE_REDACTED]");
  assert.equal(maskPii("017-123-4567"), "[PHONE_REDACTED]");
});

test("주민등록번호를 가린다", () => {
  assert.equal(maskPii("901231-1234567"), "[RRN_REDACTED]");
});

test("미국식 SSN을 가린다", () => {
  assert.equal(maskPii("123-45-6789"), "[SSN_REDACTED]");
});

test("체크섬을 통과한 카드번호만 가린다", () => {
  assert.equal(maskPii("4111 1111 1111 1111"), "[CARD_REDACTED]");
  assert.equal(maskPii("4111-1111-1111-1111"), "[CARD_REDACTED]");
});

test("카드처럼 생겼지만 체크섬이 틀린 값은 건드리지 않는다 (주문번호 오탐 방지)", () => {
  const orderNo = "1234567890123456";
  assert.equal(luhnValid(orderNo), false);
  assert.equal(maskPii(`주문번호 ${orderNo}`), `주문번호 ${orderNo}`);
});

test("IPv4를 가리되, 옥텟 범위를 벗어난 값은 IP가 아니므로 두 번 손대지 않는다", () => {
  assert.equal(maskPii("접속 192.168.0.1 에서"), "접속 [IP_REDACTED] 에서");
  assert.equal(maskPii("999.999.999.999"), "999.999.999.999");
});

test("한 문장에 여러 종류가 섞여 있어도 전부 가린다", () => {
  const raw = "고객 홍길동, 이메일 hong@example.com, 연락처 010-1234-5678, 카드 4111111111111111";
  const masked = maskPii(raw);
  assert.match(masked, /\[EMAIL_REDACTED\]/);
  assert.match(masked, /\[PHONE_REDACTED\]/);
  assert.match(masked, /\[CARD_REDACTED\]/);
  // 형식 없는 이름은 정규식으로 못 잡는다 — 알려진 한계를 테스트로 못박아 둔다.
  assert.match(masked, /홍길동/);
});

test("가릴 것이 없으면 원문을 그대로 돌려준다", () => {
  const raw = "오늘 회의는 3시입니다";
  assert.equal(maskPii(raw), raw);
});

test("maskPiiDeep은 중첩 객체·배열 안의 문자열까지 가린다", () => {
  const input = {
    to: "hong@example.com",
    meta: { phones: ["010-1234-5678", "010-9999-8888"] },
  };
  assert.deepEqual(maskPiiDeep(input), {
    to: "[EMAIL_REDACTED]",
    meta: { phones: ["[PHONE_REDACTED]", "[PHONE_REDACTED]"] },
  });
});

test("maskPiiDeep은 문자열이 아닌 값의 형태를 보존한다", () => {
  const input = { count: 3, ok: true, none: null, when: "010-1234-5678" };
  assert.deepEqual(maskPiiDeep(input), {
    count: 3,
    ok: true,
    none: null,
    when: "[PHONE_REDACTED]",
  });
});

test("maskPiiDeep은 원본 객체를 변형하지 않는다", () => {
  const input = { to: "hong@example.com" };
  maskPiiDeep(input);
  assert.equal(input.to, "hong@example.com");
});

test("maskPiiDeep은 순환 참조에서 무한 재귀로 죽지 않는다", () => {
  const node: Record<string, unknown> = { email: "hong@example.com" };
  node.self = node;
  const out = maskPiiDeep(node) as Record<string, unknown>;
  assert.equal(out.email, "[EMAIL_REDACTED]");
});