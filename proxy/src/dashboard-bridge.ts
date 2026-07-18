/**
 * 대시보드 브리지 — C 담당.
 *
 * 왜 proxy 프로세스 안에 사는가: HITL 승인 상태(policy-engine의 hitl.ts)는
 * 프로세스 내 메모리(offers Map)에 있다. 별도 프로세스인 브라우저가
 * resolveApproval을 직접 부르면 자기 복사본만 바뀌고 엔진은 모른다.
 * 그래서 브라우저의 승인 클릭을 웹소켓으로 받아, 엔진과 같은 프로세스인
 * 여기서 대신 호출한다.
 *
 * index.ts(A 담당)가 쓰는 것은 startDashboardBridge / stopDashboardBridge /
 * broadcastDecision 셋뿐 — proxy 본체에 남기는 흔적을 최소화하기 위함이다.
 */

import { WebSocketServer, type WebSocket } from "ws";
import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { requestApproval, resolveApproval, attemptSanitization } from "@icarus-tether/policy-engine";
import { SanitizationMethod, type PolicyDecision, type AuditLogEntry, type ToolRiskTag } from "@icarus-tether/types";

const WS_PORT = 7331;


// ── 감사 로그: 해시 체인 (C 담당, 책임 3) ─────────────────────────────
// 각 줄에 직전 줄의 signature(prevHash)를 심어 사슬로 엮는다. 나중에 줄을
// 지우거나 순서를 바꾸면 체인이 끊겨 verify-audit-log가 잡아낸다.
// (키 없는 SHA-256이라 "사후 편집·삭제 탐지"까지가 목표 — HMAC 서명은 향후 과제.)
const __dirname = dirname(fileURLToPath(import.meta.url));
const AUDIT_LOG_PATH = resolve(__dirname, "../audit.log");

// 이 프로세스가 마지막으로 쓴 줄의 signature. 다음 줄의 prevHash가 된다.
// 첫 줄은 제네시스라 undefined (체인의 시작점).
let lastSignature: string | undefined;

// signature 계산 시 signature/prevHash 자신은 빼고, prevHash는 항상 포함한다 —
// 그래야 "앞 줄이 무엇이었나"까지 서명에 묶여 재정렬·삭제가 탐지된다.
function signAuditEntry(entry: Omit<AuditLogEntry, "signature">): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

/**
 * 판정 하나를 해시 체인으로 엮어 audit.log에 JSON 한 줄로 append.
 * index.ts에서 writeAuditLog를 대신해 이 함수를 부른다.
 */
export function recordAudit(input: {
  sessionId: string;
  toolName: string;
  decision: "ALLOWED" | "BLOCKED";
  matchedTags: ToolRiskTag[];
}): void {
  const unsigned: Omit<AuditLogEntry, "signature"> = {
    id: randomUUID(),
    sessionId: input.sessionId,
    toolName: input.toolName,
    decision: input.decision,
    matchedTags: input.matchedTags,
    timestamp: new Date().toISOString(),
    prevHash: lastSignature, // 첫 줄이면 undefined → JSON에서 생략됨(제네시스)
  };
  const signature = signAuditEntry(unsigned);
  const signed: AuditLogEntry = { ...unsigned, signature };
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(signed) + "\n");
  lastSignature = signature; // 다음 줄이 이 값을 prevHash로 물고 이어간다
}

// ── 감사 로그 무결성 검증 (책임 3의 "검사" 쪽) ────────────────────────
// ⚠️ 이 검증 로직은 dashboard/server/src/verify-audit-log.ts(CLI)와 같은 규칙이다.
// 워크스페이스가 달라 공유 import가 지저분해 의도적으로 중복했다 — 한쪽 규칙을
// 바꾸면 반드시 다른 쪽도 함께 고칠 것. (signAuditEntry와 동일한 해시 규칙)
export interface AuditIntegrityResult {
  ok: boolean;
  total: number;
  problems: { line: number; kind: string; detail: string }[];
}

export function verifyAuditChain(): AuditIntegrityResult {
  let raw: string;
  try {
    raw = readFileSync(AUDIT_LOG_PATH, "utf8");
  } catch {
    return { ok: true, total: 0, problems: [] }; // 로그가 아직 없으면 위반 아님
  }

  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const problems: AuditIntegrityResult["problems"] = [];
  let expectedPrevHash: string | undefined;

  lines.forEach((line, i) => {
    const lineNo = i + 1;
    let entry: AuditLogEntry;
    try {
      entry = JSON.parse(line);
    } catch {
      problems.push({ line: lineNo, kind: "PARSE_ERROR", detail: "JSON 파싱 실패" });
      expectedPrevHash = undefined;
      return;
    }
    const { signature, ...unsigned } = entry;
    if (signAuditEntry(unsigned) !== signature) {
      problems.push({ line: lineNo, kind: "SIGNATURE_MISMATCH", detail: "줄 내용 변조 의심" });
    }
    if (entry.prevHash !== expectedPrevHash) {
      problems.push({ line: lineNo, kind: "CHAIN_BREAK", detail: "줄 삭제·재정렬 의심" });
    }
    expectedPrevHash = signature; // 저장된 값 기준 (재계산값 쓰면 이후 전줄 연쇄 오탐)
  });

  return { ok: problems.length === 0, total: lines.length, problems };
}

/** 로그 전체를 검증해 무결성 결과를 대시보드에 방송한다. (세션 종료 직전 호출) */
export function broadcastAuditIntegrity(): void {
  const result = verifyAuditChain();
  broadcastToDashboard({
    type: "audit_integrity",
    ok: result.ok,
    total: result.total,
    problems: result.problems,
    timestamp: new Date().toISOString(),
  });
  console.error(
    result.ok
      ? `[bridge] 감사로그 무결성 ✅ (${result.total}줄)`
      : `[bridge] 감사로그 무결성 ⛔ 위반 ${result.problems.length}건`
  );
}

let wss: WebSocketServer | null = null;
const clients = new Set<WebSocket>();

/** 대시보드로 이벤트 한 건 방송. 브리지가 꺼져 있으면 조용히 무시한다. */
export function broadcastToDashboard(event: Record<string, unknown>): void {
  const payload = JSON.stringify(event);
  for (const client of clients) {
    if (client.readyState === client.OPEN) client.send(payload);
  }
}

/**
 * 판정 하나를 대시보드 모양으로 방송.
 * explanation·canOverride·approvalId까지 실어야 승인 모달이 뜰 수 있다.
 * canOverride는 hitlPolicy가 off면 엔진이 아예 안 채우므로 여기서 false로 고정한다 —
 * 대시보드가 "필드 없음"과 "false"를 구분하지 않아도 되게.
 */
export function broadcastDecision(
  sessionId: string,
  toolName: string,
  decision: PolicyDecision,
  timestamp: string
): void {
  broadcastToDashboard({
    type: "decision",
    sessionId,
    toolName,
    allowed: decision.allowed,
    reason: decision.reason,
    matchedTags: decision.matchedTags,
    explanation: decision.explanation,
    canOverride: decision.canOverride ?? false,
    approvalId: decision.approvalId,
    timestamp,
  });
}

function handleDashboardMessage(text: string): void {
  const msg = JSON.parse(text) as {
    type?: string;
    sessionId?: string;
    approvalId?: string;
    resolvedBy?: string;
    method?: string;
  };

  // (1) 승인/거부 — HITL 오버라이드
  if (msg.type === "approve" || msg.type === "reject") {
    if (!msg.sessionId || !msg.approvalId) return;
    const approved = msg.type === "approve";
    requestApproval(msg.sessionId, msg.approvalId); // OFFERED → PENDING
    resolveApproval(msg.approvalId, approved, msg.resolvedBy ?? "dashboard");
    console.error(`[bridge] 대시보드 ${approved ? "승인" : "거부"}  approvalId=${msg.approvalId}`);
    broadcastToDashboard({
      type: "approval_resolved",
      sessionId: msg.sessionId,
      approvalId: msg.approvalId,
      approved,
      resolvedBy: msg.resolvedBy ?? "dashboard",
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // (2) 정화 — 세션 오염 태그를 검증된 방법으로 해제한다.
  // 승인(1회 통과)과 달리 태그 자체가 사라지므로, 재시도하면 트라이펙타가 미성립해 통과된다.
  if (msg.type === "sanitize") {
    if (!msg.sessionId || !msg.method) return;
    if (msg.method !== SanitizationMethod.TOKENIZATION && msg.method !== SanitizationMethod.STRUCTURED_EXTRACTION) {
      console.error(`[bridge] 알 수 없는 정화 방법: ${msg.method}`);
      return;
    }
    const result = attemptSanitization(msg.sessionId, msg.method);
    const ok = result.originalTags.length > result.resultTags.length; // 태그가 줄었으면 정화 성공
    console.error(
      `[bridge] 대시보드 정화(${msg.method})  ${result.originalTags.join(",")} → ${result.resultTags.join(",") || "(없음)"}`
    );
    broadcastToDashboard({
      type: "sanitized",
      sessionId: msg.sessionId,
      method: msg.method,
      originalTags: result.originalTags,
      resultTags: result.resultTags,
      ok,
      timestamp: new Date().toISOString(),
    });
    return;
  }
}

/** 웹소켓 서버 기동. 포트가 물려 있으면 원인을 분명히 알리고 죽는다. */
export function startDashboardBridge(): void {
  if (wss) return;
  const server = new WebSocketServer({ port: WS_PORT });
  wss = server;

  // 핸들러가 없으면 EADDRINUSE가 unhandled error로 터져 스택만 잔뜩 나온다.
  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `[bridge] 포트 ${WS_PORT}이 이미 사용 중 — 이전 proxy가 안 죽었을 수 있습니다.\n` +
          `        확인: Get-NetTCPConnection -LocalPort ${WS_PORT}`
      );
    } else {
      console.error("[bridge] 웹소켓 서버 오류:", err);
    }
    process.exit(1);
  });

  server.on("connection", (socket) => {
    clients.add(socket);
    console.error(`[bridge] 대시보드 연결됨 (현재 ${clients.size}개)`);
    socket.on("close", () => clients.delete(socket));
    socket.on("message", (raw) => {
      try {
        handleDashboardMessage(raw.toString());
      } catch (err) {
        // 없는 id·세션 불일치·이미 처리된 제안은 엔진이 예외로 막는다 (fail-closed).
        console.error("[bridge] 대시보드 메시지 처리 실패:", err);
      }
    });
  });

  console.error(`[bridge] 대시보드 웹소켓 대기 중 (포트 ${WS_PORT})`);
}

/** 브리지를 닫는다. 안 닫으면 웹소켓 서버가 이벤트 루프를 잡아 proxy가 종료되지 않는다. */
export function stopDashboardBridge(): void {
  wss?.close();
  wss = null;
  clients.clear();
}