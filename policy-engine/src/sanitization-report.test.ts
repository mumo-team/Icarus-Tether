/**
 * 정화 보고 정직화 — "완전 정화" vs "부분 정화" 구분 (발견 #2 후속, UX 정직성).
 *
 * 배경: tag_all 소스(query_customer_db 등)는 내용 전체가 SENSITIVE인데 TOKENIZATION은
 * 패턴에 걸린 값만 가린다 → "홍길동"·"VIP" 같은 비정형 값은 정화 후에도 잔존한다.
 * 판정이 계속 막는 건 그 잔존을 가드하는 fail-safe(옳음)지만, 보고가 "정화 완료"라
 * 사용자가 통과를 기대하는 모순이 있었다. 여기서는 attemptSanitization의 보고 필드
 * (maskedCount / residualSensitiveData)가 그 구분을 정직하게 싣는지 검증한다.
 *
 * ★ 판정 무변경 검증 포함 — 보고 필드는 resultTags/이후 판정에 영향이 없어야 한다.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ToolRiskTag, SanitizationMethod, type ToolCallContext } from "@icarus-tether/types";
import { recordToolPayload, attemptSanitization, evaluateToolCall } from "./index.js";

function ctx(sessionId: string, toolName: string): ToolCallContext {
  return { sessionId, toolName, args: {}, argTags: [], timestamp: new Date().toISOString() };
}

test("부분 정화: tag_all 소스에 비정형 값 잔존 → residualSensitiveData=true + 치환 수 보고", () => {
  const sid = "rep-partial";
  // 이름(비정형)·이메일(패턴)이 섞인 tag_all 소스 페이로드 — 이메일만 가릴 수 있다
  recordToolPayload(sid, "query_customer_db", {
    customer: "홍길동",
    grade: "VIP",
    email: "hong@example.com",
  });

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual(result.resultTags, [], "태그 해제 자체는 기존과 동일");
  assert.ok((result.maskedCount ?? 0) >= 1, "치환된 값 수가 보고돼야 함 (이메일 1건 이상)");
  assert.equal(result.residualSensitiveData, true, "비정형 잔존(홍길동·VIP) → 부분 정화로 보고");
});

test("완전 정화: tag_all 소스지만 내용이 전부 패턴(PII) → residualSensitiveData=false", () => {
  const sid = "rep-full";
  // 페이로드의 모든 문자열이 통째로 패턴에 걸린다 → 토큰화 후 토큰 밖 내용이 없다
  recordToolPayload(sid, "query_customer_db", {
    email: "hong@example.com",
    phone: "010-1234-5678",
  });

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual(result.resultTags, []);
  assert.ok((result.maskedCount ?? 0) >= 2, "이메일+전화 각각 치환");
  assert.equal(result.residualSensitiveData, false, "토큰 밖 내용 없음 → 완전 정화");
});

test("정화 실패(fail-safe)면 보고 필드는 생략된다", () => {
  const sid = "rep-fail";
  // 페이로드에 패턴 매치가 전혀 없으면 no-op 게이트(S4)로 정화 실패 → 태그 유지
  recordToolPayload(sid, "query_customer_db", { customer: "홍길동" });

  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual([...result.resultTags].sort(), [...result.originalTags].sort(), "태그 유지");
  assert.equal(result.maskedCount, undefined);
  assert.equal(result.residualSensitiveData, undefined);
});

test("STRUCTURED_EXTRACTION은 보고 필드를 싣지 않는다 (토큰화 전용 보고)", () => {
  const sid = "rep-se";
  recordToolPayload(sid, "fetch_web_page", { type: "ticket", name: "환불 문의" });

  const result = attemptSanitization(sid, SanitizationMethod.STRUCTURED_EXTRACTION);
  assert.deepEqual(result.resultTags, []);
  assert.equal(result.maskedCount, undefined);
  assert.equal(result.residualSensitiveData, undefined);
});

test("★ 판정 무변경: 부분 정화 보고가 붙어도 판정 결과는 기존과 동일", () => {
  // index.test.ts '정화 후 통과' 시나리오 재연 — 보고 필드 추가가 판정을 안 바꾼다
  const sid = "rep-judgment";
  recordToolPayload(sid, "query_customer_db", {
    customer: "홍길동",
    email: "hong@example.com",
    phone: "010-1234-5678",
  });
  recordToolPayload(sid, "fetch_web_page", "외부 웹 문서 본문");

  assert.equal(evaluateToolCall(ctx(sid, "http_post")).allowed, false, "정화 전 차단");
  const result = attemptSanitization(sid, SanitizationMethod.TOKENIZATION);
  assert.deepEqual(result.resultTags, [ToolRiskTag.UNTRUSTED_ORIGIN]);
  assert.equal(result.residualSensitiveData, true, "홍길동 잔존 → 부분 정화 보고");
  assert.equal(
    evaluateToolCall(ctx(sid, "http_post")).allowed,
    true,
    "판정은 기존(session 모드 통과)과 동일 — 보고 필드가 판정에 개입하지 않음"
  );
});
