/**
 * 감사 로그 검증기 — C 담당 (책임 3: 위변조 방지).
 *
 * audit.log는 각 줄에 직전 줄의 signature(prevHash)를 심어 사슬로 엮여 있다.
 * 이 도구는 그 사슬을 처음부터 재계산해, 사후에 줄이 편집·삭제·재정렬됐는지
 * 탐지한다. "기록만 하고 아무도 검사 안 하면" 서명은 의미가 없다 — 이게 그 검사다.
 *
 * 탐지하는 것:
 *   1. 줄 내용 변조 — signature를 다시 계산해 저장값과 비교
 *   2. 줄 삭제·재정렬 — prevHash가 실제 앞 줄 signature와 일치하는지
 *
 * 탐지 못 하는 것(설계 한계): 키 없는 SHA-256이라, 공격자가 특정 줄부터
 *   끝까지 전부 다시 계산해 사슬을 새로 맞추면 탐지 불가. 진짜 방어는 HMAC
 *   서명(비밀 키) — 키 관리 설계가 필요해 향후 과제로 둔다.
 * 
 * [주의] 검증 규칙은 proxy/src/dashboard-bridge.ts의 verifyAuditChain과 동일하다.
 *    워크스페이스가 달라 의도적으로 중복 — 한쪽 규칙 변경 시 다른 쪽도 함께 고칠 것.
 * 
 *
 * 실행: npm run verify -w dashboard/server            (기본: proxy/audit.log)
 *      npm run verify -w dashboard/server -- <경로>   (다른 파일 지정)
 * 
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import type { AuditLogEntry } from "@icarus-tether/types";

const __dirname = dirname(fileURLToPath(import.meta.url));
// 로그는 proxy 워크스페이스가 쓴다. 인자로 경로를 주면 그걸 우선한다.
const DEFAULT_LOG_PATH = resolve(__dirname, "../../../proxy/audit.log");

// 기록할 때(recordAudit)와 동일한 규칙: signature 자신만 빼고 나머지 전부 해시.
// prevHash는 포함된다 — 그래야 "앞 줄이 무엇이었나"가 서명에 묶인다.
export function recomputeSignature(entry: AuditLogEntry): string {
  const { signature: _omit, ...unsigned } = entry;
  return createHash("sha256").update(JSON.stringify(unsigned)).digest("hex");
}

interface Problem {
  line: number; // 1-based
  kind: "SIGNATURE_MISMATCH" | "CHAIN_BREAK" | "PARSE_ERROR";
  detail: string;
}

export function verify(logPath: string): { total: number; problems: Problem[] } {
  let raw: string;
  try {
    raw = readFileSync(logPath, "utf8");
  } catch (err) {
    return {
      total: 0,
      problems: [{ line: 0, kind: "PARSE_ERROR", detail: `파일을 읽을 수 없음: ${(err as Error).message}` }],
    };
  }

  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const problems: Problem[] = [];
  let expectedPrevHash: string | undefined; // 앞 줄의 signature = 이 줄의 prevHash여야 함

  lines.forEach((line, i) => {
    const lineNo = i + 1;
    let entry: AuditLogEntry;
    try {
      entry = JSON.parse(line);
    } catch (err) {
      problems.push({ line: lineNo, kind: "PARSE_ERROR", detail: (err as Error).message });
      expectedPrevHash = undefined; // 깨진 줄 이후 체인은 판단 불가
      return;
    }

    // (1) 내용 변조 검사
    const recomputed = recomputeSignature(entry);
    if (recomputed !== entry.signature) {
      problems.push({
        line: lineNo,
        kind: "SIGNATURE_MISMATCH",
        detail: `서명 불일치 — 이 줄 내용이 기록 후 바뀌었을 수 있음 (id=${entry.id})`,
      });
    }

    // (2) 체인 연결 검사
    if (entry.prevHash !== expectedPrevHash) {
      problems.push({
        line: lineNo,
        kind: "CHAIN_BREAK",
        detail:
          lineNo === 1
            ? `첫 줄인데 prevHash가 있음 (앞에 줄이 삭제됐을 수 있음)`
            : `prevHash가 앞 줄 signature와 불일치 — 줄 삭제·재정렬 의심 ` +
              `(기대=${expectedPrevHash?.slice(0, 12) ?? "없음"}…, 실제=${entry.prevHash?.slice(0, 12) ?? "없음"}…)`,
      });
    }

    // 다음 줄이 검사할 기준값 — "저장된" signature를 쓴다. 재계산값을 쓰면
    // 변조된 줄 하나가 이후 모든 줄을 연쇄로 CHAIN_BREAK 처리해 원인이 묻힌다.
    expectedPrevHash = entry.signature;
  });

  return { total: lines.length, problems };
}

// ── 실행 (CLI로 직접 실행했을 때만) ──
// 가드가 없으면 테스트가 이 모듈을 import하는 순간 process.exit가 불려 테스트가 죽는다.
if (resolve(process.argv[1] ?? "") === resolve(fileURLToPath(import.meta.url))) {
  const logPath = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_LOG_PATH;
  console.error(`[verify] 검사 대상: ${logPath}\n`);

  const { total, problems } = verify(logPath);

  if (problems.length === 0) {
    console.error(`[정상] 무결 — ${total}줄 전부 서명·체인 정상.`);
    process.exit(0);
  } else {
    console.error(`[위반] 무결성 위반 ${problems.length}건 (전체 ${total}줄):\n`);
    for (const p of problems) {
      console.error(`  ${p.line}번째 줄 [${p.kind}] ${p.detail}`);
    }
    process.exit(1);
  }
}