/**
 * 감사 로그 위변조 탐지 테스트.
 *
 * "해시 체인으로 위변조를 탐지한다"는 주장을 실제로 증명한다 —
 * 변조·삭제·재정렬 로그를 만들어 검증기가 정말 잡아내는지 확인하고,
 * 잡아내지 못하는 경우(설계 한계)까지 테스트로 못박아 둔다.
 *
 * 실행: npm run test -w @icarus-tether/dashboard-server
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditLogEntry } from "@icarus-tether/types";
import { verify, recomputeSignature } from "./verify-audit-log.js";

// proxy의 recordAudit와 같은 규칙으로 서명한다 — 키 순서까지 동일해야 해시가 맞는다.
function sign(unsigned: Omit<AuditLogEntry, "signature">): AuditLogEntry {
  const signature = createHash("sha256").update(JSON.stringify(unsigned)).digest("hex");
  return { ...unsigned, signature };
}

/** 정상적으로 이어진 체인 n줄을 만든다. */
function buildChain(n: number): AuditLogEntry[] {
  const out: AuditLogEntry[] = [];
  let prevHash: string | undefined;
  for (let i = 0; i < n; i++) {
    const entry = sign({
      id: `id-${i}`,
      sessionId: "s-1",
      toolName: `tool_${i}`,
      decision: i % 2 === 0 ? "ALLOWED" : "BLOCKED",
      matchedTags: [],
      timestamp: `2026-08-19T00:00:0${i}.000Z`,
      prevHash,
    } as Omit<AuditLogEntry, "signature">);
    out.push(entry);
    prevHash = entry.signature;
  }
  return out;
}

/** 엔트리 배열을 임시 로그 파일로 써서 경로를 돌려준다. */
function writeLog(entries: AuditLogEntry[]): string {
  const dir = mkdtempSync(join(tmpdir(), "audit-verify-"));
  const path = join(dir, "audit.log");
  writeFileSync(path, entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
  return path;
}

test("서명 재계산 규칙이 기록 규칙과 일치한다", () => {
  const [entry] = buildChain(1);
  assert.equal(recomputeSignature(entry), entry.signature);
});

test("손대지 않은 체인은 위반 0건", () => {
  const result = verify(writeLog(buildChain(5)));
  assert.equal(result.total, 5);
  assert.deepEqual(result.problems, []);
});

test("줄 내용을 고치면 SIGNATURE_MISMATCH로 잡는다", () => {
  const chain = buildChain(5);
  chain[1].decision = "ALLOWED"; // 차단됐던 걸 통과로 위조
  const result = verify(writeLog(chain));
  const kinds = result.problems.map((p) => p.kind);
  assert.ok(kinds.includes("SIGNATURE_MISMATCH"), `기대: SIGNATURE_MISMATCH, 실제: ${kinds}`);
  assert.equal(result.problems.find((p) => p.kind === "SIGNATURE_MISMATCH")?.line, 2);
});

test("줄을 지우면 CHAIN_BREAK로 잡는다", () => {
  const chain = buildChain(5);
  chain.splice(2, 1); // 3번째 줄 삭제 — 흔적을 지우려는 공격
  const result = verify(writeLog(chain));
  assert.ok(result.problems.some((p) => p.kind === "CHAIN_BREAK"));
});

test("줄 순서를 바꾸면 CHAIN_BREAK로 잡는다", () => {
  const chain = buildChain(5);
  [chain[1], chain[3]] = [chain[3], chain[1]];
  const result = verify(writeLog(chain));
  assert.ok(result.problems.some((p) => p.kind === "CHAIN_BREAK"));
});

test("깨진 JSON 줄은 PARSE_ERROR로 보고하고 계속 검사한다", () => {
  const chain = buildChain(3);
  const dir = mkdtempSync(join(tmpdir(), "audit-verify-"));
  const path = join(dir, "audit.log");
  writeFileSync(path, [JSON.stringify(chain[0]), "{깨진 줄", JSON.stringify(chain[2])].join("\n") + "\n");
  const result = verify(path);
  assert.equal(result.total, 3);
  assert.ok(result.problems.some((p) => p.kind === "PARSE_ERROR" && p.line === 2));
});

test("파일이 없으면 PARSE_ERROR로 보고한다 (조용히 통과시키지 않는다)", () => {
  const result = verify(join(tmpdir(), "존재하지-않는-audit.log"));
  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0].kind, "PARSE_ERROR");
});

test("[알려진 한계] 체인 전체를 다시 계산한 위조는 탐지하지 못한다", () => {
  // 키 없는 SHA-256의 구조적 한계. 공격자가 로그 파일 전체를 다시 서명하면
  // 사슬은 완전히 정합적이다. 진짜 방어는 비밀 키를 쓰는 HMAC — 향후 과제.
  // 이 한계를 테스트로 남겨, 나중에 HMAC을 넣으면 이 테스트가 깨지며 알려준다.
  const forged = buildChain(5);
  forged.splice(2, 1);
  let prevHash: string | undefined;
  const rechained = forged.map((e) => {
    const { signature: _drop, ...rest } = e;
    const resigned = sign({ ...rest, prevHash } as Omit<AuditLogEntry, "signature">);
    prevHash = resigned.signature;
    return resigned;
  });
  const result = verify(writeLog(rechained));
  assert.deepEqual(result.problems, [], "재계산된 위조는 통과한다 — 알려진 한계");
});