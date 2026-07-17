/**
 * 프록시 — 에이전트와 실제 MCP 서버 사이에 끼는 투명 프록시.
 * 에이전트에겐 서버로(저수준 Server), 실제 서버에겐 클라이언트로(Client) 행세하며
 * tools/call을 가로채 정책 엔진의 판정대로 통과·차단한다.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import { WebSocketServer, type WebSocket } from "ws";
import { pipeline } from "@huggingface/transformers";
import { z } from "zod";
// 검사함수가 주고받을 표준 계약. 세 파트 공용 타입(B가 이 모양으로 판정한다).
import type { ToolCallContext, AuditLogEntry } from "@icarus-tether/types";
// ① 정책 엔진(B) — 판정과 오염 기록의 실제 구현.
import {
  evaluateToolCall,
  recordToolResult,
  requestApproval,
  resolveApproval,
} from "@icarus-tether/policy-engine";

// ★ stdout 보호: stdio에서 stdout은 JSON-RPC 전용 채널인데, 정책 엔진은 로그를
// console.log(stdout)로 찍는다. 그대로 두면 첫 로그가 프로토콜 스트림을 깨뜨리므로
// 이 프로세스의 console.log를 전부 stderr로 우회시킨다.
console.log = (...args: unknown[]) => console.error(...args);

// ESM엔 __dirname이 없어 import.meta.url로 계산 (실행 위치와 무관하게 경로 고정)
const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCK_SERVER_PATH = resolve(__dirname, "../test/mock-server.ts");
// npx 대신 로컬 tsx를 절대경로로 직접 실행한다. npx는 cwd 기준으로 tsx를 찾기 때문에,
// 에이전트가 임의의 cwd에서 프록시를 띄우면 tsx를 인터넷에서 새로 받으려 한다(느리고 오프라인 실패).
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const AUDIT_LOG_PATH = resolve(__dirname, "../audit.log");

// ── 대시보드용 웹소켓 서버 (개념 증명) ──────────────────────────────
// proxy는 판정 데이터를 이미 갖고 있으니, 별도 서버 없이 여기서 바로 방송한다.
const WS_PORT = 7331;
const wss = new WebSocketServer({ port: WS_PORT });
const dashboardClients = new Set<WebSocket>();

wss.on("connection", (socket) => {
  dashboardClients.add(socket);
  console.error(`[proxy] 대시보드 연결됨 (현재 ${dashboardClients.size}개)`);
  socket.on("close", () => dashboardClients.delete(socket));
});

function broadcastToDashboard(event: Record<string, unknown>): void {
  const payload = JSON.stringify(event);
  for (const client of dashboardClients) {
    if (client.readyState === client.OPEN) client.send(payload);
  }
}

// ── 인젝션 탐지 (개념 증명 — 원래는 dashboard/server 소유, 지금은 임시로 여기 복제) ──
// ⚠️ 비신뢰 콘텐츠(fetch_web_page 등) 전용. 사용자 명령문에는 쓰지 말 것(오탐 확인됨).
const INJECTION_THRESHOLD = 0.95;
let injectionClassifierPromise: ReturnType<typeof pipeline> | null = null;
function getInjectionClassifier() {
  if (!injectionClassifierPromise) {
    injectionClassifierPromise = pipeline(
      "text-classification",
      "protectai/deberta-v3-base-prompt-injection-v2"
    );
  }
  return injectionClassifierPromise;
}

async function detectInjection(text: string): Promise<{ isInjection: boolean; score: number }> {
  try {
    const classifier = await getInjectionClassifier();
    const result = (await classifier(text.slice(0, 2000), { top_k: null })) as Array<{
      label: string;
      score: number;
    }>;
    const score = result.find((r) => r.label === "INJECTION")?.score ?? 0;
    return { isInjection: score > INJECTION_THRESHOLD, score };
  } catch (err) {
    console.error("[proxy] 인젝션 탐지 실패 — fail-safe로 의심 처리:", err);
    return { isInjection: true, score: 1 };
  }
}

interface SessionState {
  id: string;
  createdAt: string;
  toolCalls: number;
}

// 세션 저장소. stdio에선 세션 1개지만, 다중 클라이언트(HTTP)로 확장되면 여러 개가 쌓인다.
// (오염 태그는 정책 엔진이 sessionId로 내부 추적하므로 여기서 들고 있지 않는다.)
const sessions = new Map<string, SessionState>();

// 기록 내용의 sha256 해시 = 위변조 방지 서명. 나중에 다시 계산해 비교하면 변조를 탐지.
function signEntry(entry: unknown): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

// 판정 하나를 서명 붙여 audit.log에 JSON 한 줄로 append. (C가 나중에 이 기록을 전시)
function writeAuditLog(entry: Omit<AuditLogEntry, "signature">): void {
  const signed: AuditLogEntry = { ...entry, signature: signEntry(entry) };
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(signed) + "\n");
}

// [C 자리 스텁] 대시보드에서 사람이 승인하는 것을 흉내낸다.
// 실전에선 C가 엔진의 requestApproval/resolveApproval을 호출한다.
// 승인이 등록되면 에이전트가 같은 호출을 재시도할 때 엔진이 승인을 소비해 통과시킨다.
function simulateDashboardApproval(sessionId: string, approvalId: string): void {
  if (process.env.APPROVAL_DECISION !== "approve") return;
  try {
    requestApproval(sessionId, approvalId);
    resolveApproval(approvalId, true, "stub-dashboard");
    console.error(`[proxy] (스텁) 대시보드 승인됨  approvalId=${approvalId} — 재시도하면 통과`);
  } catch (err) {
    console.error("[proxy] (스텁) 승인 실패:", err);
  }
}

async function main() {
  // stdio에선 이 프록시 프로세스 하나가 클라이언트 하나를 상대한다 = 세션 하나.
  const sessionId = randomUUID();
  sessions.set(sessionId, {
    id: sessionId,
    createdAt: new Date().toISOString(),
    toolCalls: 0,
  });
  console.error(`[proxy] 세션 시작  session=${sessionId}`);

  const downstream = new Client({
    name: "icarus-tether-proxy-client",
    version: "0.1.0",
  });
  const downstreamTransport = new StdioClientTransport({
    command: process.execPath, // 지금 프록시를 돌리는 node 실행파일 (절대경로라 cwd 무관)
    args: [TSX_CLI, MOCK_SERVER_PATH],
  });
  await downstream.connect(downstreamTransport);

  // 저수준 Server를 쓰는 이유: 프록시는 도구를 미리 모르므로 임의 요청을 그대로 중계해야 한다.
  // capabilities는 다운스트림이 노출하는 것을 그대로 신고 → 클라이언트가 그 기능들을 쓸 수 있게.
  const server = new Server(
    { name: "icarus-tether-proxy", version: "0.1.0" },
    { capabilities: downstream.getServerCapabilities() ?? { tools: {} } }
  );

  // 클라이언트가 stdin을 닫으면(EOF) 대화가 끝난 것 → 세션 정리.
  // (StdioServerTransport는 stdin EOF에 onclose를 부르지 않으므로 'end'를 직접 듣는다.)
  process.stdin.on("end", () => {
    const s = sessions.get(sessionId);
    console.error(
      `[proxy] 세션 종료  session=${sessionId}  (도구호출 ${s?.toolCalls ?? 0}건)`
    );
    sessions.delete(sessionId);
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return await downstream.listTools();
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const session = sessions.get(sessionId);
    if (session) session.toolCalls += 1;
    console.error(
      `[proxy] ⮕ ${name}  args=${JSON.stringify(args ?? {})}  session=${sessionId}`
    );

    const ctx: ToolCallContext = {
      sessionId,
      toolName: name,
      args: (args ?? {}) as Record<string, unknown>,
      argTags: [],
      timestamp: new Date().toISOString(),
    };

    // 정책 엔진의 판정. 엔진이 세션 오염을 내부 추적하므로 태그를 따로 넘기지 않는다.
    const decision = evaluateToolCall(ctx);

    writeAuditLog({
      id: randomUUID(),
      sessionId,
      toolName: name,
      decision: decision.allowed ? "ALLOWED" : "BLOCKED",
      matchedTags: decision.matchedTags,
      timestamp: new Date().toISOString(),
    });

    broadcastToDashboard({
      type: "decision",
      sessionId,
      toolName: name,
      allowed: decision.allowed,
      reason: decision.reason,
      matchedTags: decision.matchedTags,
      timestamp: ctx.timestamp,
    });

    if (!decision.allowed) {
      console.error(`[proxy] 차단  ${name}  reason=${decision.reason}`);
      // 오버라이드 가능한 차단이면 승인 id를 알려준다 — 사람이 승인 후 재시도하면 통과.
      if (decision.canOverride && decision.approvalId) {
        console.error(`[proxy] 오버라이드 가능  approvalId=${decision.approvalId}`);
        simulateDashboardApproval(sessionId, decision.approvalId); // C 자리 스텁
      }
      const text = [
        `정책 차단: ${decision.explanation?.summary ?? decision.reason ?? "정책 위반"}`,
        decision.canOverride && decision.approvalId
          ? `승인 후 같은 호출을 재시도하면 진행됩니다 (approvalId=${decision.approvalId})`
          : "",
      ]
        .filter(Boolean)
        .join("\n");
      return { isError: true, content: [{ type: "text", text }] };
    }

    const result = await downstream.callTool(request.params);

    // ★ 오염 기록 — 엔진의 세션 오염은 '기록된 결과'에서만 자란다. 빠뜨리면 fail-open.
    // 기록 실패 시엔 추적 안 된 데이터를 넘기지 않고 막는다 (fail-safe).
    try {
      recordToolResult(sessionId, name, ctx.args, result);
    } catch (err) {
      console.error(`[proxy] 오염 기록 실패 — 결과 전달 보류  ${name}`, err);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: "안전장치: 도구 결과의 오염 추적에 실패해 결과 전달을 보류합니다.",
          },
        ],
      };
    }

    console.error(`[proxy] ⬅ 통과  ${name}`);

    // 비신뢰 콘텐츠 도구 결과만 인젝션 탐지 (사용자 명령문엔 절대 적용 금지 — 오탐 확인됨)
    if (name === "fetch_web_page") {
      const textContent =
        (result as { content?: Array<{ type: string; text?: string }> }).content?.find(
          (c) => c.type === "text"
        )?.text ?? "";
      const injectionResult = await detectInjection(textContent);
      console.error(
        `[proxy] 🔍 인젝션 탐지  score=${injectionResult.score.toFixed(4)}  isInjection=${injectionResult.isInjection}`
      );
      broadcastToDashboard({
        type: "injection_check",
        sessionId,
        toolName: name,
        isInjection: injectionResult.isInjection,
        score: injectionResult.score,
        timestamp: new Date().toISOString(),
      });
    }

    return result;
  });

  // [투명성] tools 외 모든 요청·알림은 손대지 않고 그대로 중계한다.
  // 임의 메서드를 통과시키므로 타입 유니온을 우회(any)하고, 결과는 관대한 스키마로 받는다.
  server.fallbackRequestHandler = async (req) =>
    downstream.request({ method: req.method, params: req.params } as any, z.any());
  server.fallbackNotificationHandler = async (n) => downstream.notification(n as any);
  // 역방향(서버→클라, 예: sampling/roots)도 통과.
  downstream.fallbackRequestHandler = async (req) =>
    server.request({ method: req.method, params: req.params } as any, z.any());
  downstream.fallbackNotificationHandler = async (n) => server.notification(n as any);

  // stdout은 에이전트와의 JSON-RPC 전용선이므로, 로그는 반드시 stderr(console.error)로.
  const upstreamTransport = new StdioServerTransport();
  await server.connect(upstreamTransport);
  console.error(`[proxy] 기동됨. session=${sessionId}`);
}

main().catch((err) => {
  console.error("[proxy] 기동 실패:", err);
  process.exit(1);
});