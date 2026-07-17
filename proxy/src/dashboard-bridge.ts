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
import { requestApproval, resolveApproval } from "@icarus-tether/policy-engine";
import type { PolicyDecision } from "@icarus-tether/types";

const WS_PORT = 7331;

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
  };
  if (msg.type !== "approve" && msg.type !== "reject") return;
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