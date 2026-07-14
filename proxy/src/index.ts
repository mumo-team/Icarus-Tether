/**
 * ② 프록시 — A 담당 / 0단계: 통짜 통과 프록시
 *
 * 역할: AI 에이전트와 진짜 MCP 서버 사이에 끼어, 모든 요청을 그대로 중계한다.
 *   - 에이전트한테는 "내가 서버다"  → 저수준 Server + StdioServerTransport
 *   - 진짜 서버한테는 "내가 클라이언트다" → Client + StdioClientTransport
 *
 * 0단계 목표: 검사 없이, tools/list·tools/call을 진짜 서버로 넘기고
 * 결과를 그대로 돌려줘서 "사슬이 이어지는지"만 확인한다.
 * (로깅=1단계, 스텁검사=2단계, 실제차단=3단계에서 붙인다.)
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
// 검사함수가 주고받을 표준 계약. 세 파트 공용 타입(B가 이 모양으로 판정한다).
import type { ToolCallContext, PolicyDecision } from "@icarus-tether/types";
import { WebSocketServer, type WebSocket } from "ws";
import { pipeline } from "@huggingface/transformers";

// ESM에는 __dirname이 없다. import.meta.url(이 파일의 위치)로 직접 계산한다.
// 이렇게 해두면 어디서 프록시를 실행하든 mock-server 경로가 안 깨진다.
const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCK_SERVER_PATH = resolve(__dirname, "../test/mock-server.ts");

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
/**
 * [2단계] 검사 소켓 — B의 정책 엔진이 나중에 꽂힐 자리.
 *
 * 지금은 A 혼자 차단을 시연하려는 임시 스텁이다.
 * 이 함수의 "본문"만 나중에 B의 진짜 엔진 호출(HTTP/IPC)로 통째로 바꾸면,
 * 프록시의 나머지 배선은 손대지 않아도 된다. (그게 소켓을 만드는 이유)
 *
 * [3단계] 규칙 한 개: 외부 유출 도구 send_email은 차단한다.
 */
async function requestPolicyCheck(ctx: ToolCallContext): Promise<PolicyDecision> {
  if (ctx.toolName === "send_email") {
    return {
      sessionId: ctx.sessionId,
      toolName: ctx.toolName,
      allowed: false, // <- 차단
      reason: "send_email은 외부로 데이터가 나가는 싱크라 데모 정책상 차단됨",
      matchedTags: [],
    };
  }
  // 그 외에는 통과 (2단계의 '항상 통과' 기본값)
  return {
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    allowed: true,
    matchedTags: [],
  };
}

async function main() {
  // ---------------------------------------------------------------------
  // (1) 클라이언트 얼굴: 진짜(다운스트림) 서버에 붙는다.
  //     StdioClientTransport가 진짜 서버를 "자식 프로세스로 실행(spawn)"하고
  //     그 자식의 stdin/stdout으로 대화한다.
  // ---------------------------------------------------------------------
  const downstream = new Client({
    name: "icarus-tether-proxy-client",
    version: "0.1.0",
  });
  const downstreamTransport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", MOCK_SERVER_PATH],
  });
  await downstream.connect(downstreamTransport); // 여기서 진짜 서버와 initialize 핸드셰이크가 일어난다.

  // ---------------------------------------------------------------------
  // (2) 서버 얼굴: 에이전트에게 "내가 서버다"라고 행세한다.
  //     capabilities.tools를 켜서 "나 도구 기능 있음"을 핸드셰이크 때 알린다.
  // ---------------------------------------------------------------------
  const server = new Server(
    { name: "icarus-tether-proxy", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  // tools/list 요청이 오면 → 진짜 서버에 그대로 물어서, 그 목록을 그대로 돌려준다.
  // (프록시는 도구를 미리 모른다. "뭐가 있든 그대로 비춰준다"가 투명 프록시의 핵심.)
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return await downstream.listTools();
  });

  // tools/call 요청이 오면 → 인자를 그대로 진짜 서버로 넘기고, 결과를 그대로 돌려준다.
  // request.params 안에 { name, arguments }가 들어있고, 그게 곧 callTool의 입력이다.
  // ★ 나중에 여기(넘기기 직전)에 B의 검사함수가 끼어들 자리다.
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // [1단계] 가로챈 호출을 눈으로 확인한다. (반드시 stderr로!)
    console.error(
      `[proxy] ⮕ 가로챔 tools/call  name=${name}  args=${JSON.stringify(args ?? {})}`
    );

    // [2단계] 가로챈 정보를 검사함수가 이해하는 표준 모양(ToolCallContext)으로 포장한다.
    const ctx: ToolCallContext = {
      sessionId: "demo-session-1", // 세션 관리는 나중에. 지금은 고정값.
      toolName: name,
      args: (args ?? {}) as Record<string, unknown>,
      argTags: [], // 태그 전파(propagation)는 B의 몫. 지금은 빈 값.
      timestamp: new Date().toISOString(),
    };

    // [2단계] 검사 소켓 호출. 여기 반환값(allowed)이 통과/차단을 가른다.
    const decision = await requestPolicyCheck(ctx);
    broadcastToDashboard({
      type: "decision",
      sessionId: decision.sessionId,
      toolName: decision.toolName,
      allowed: decision.allowed,
      reason: decision.reason,
      matchedTags: decision.matchedTags,
      timestamp: ctx.timestamp,
    });

    // [3단계] 차단 결정이면 다운스트림에 넘기지 않고 여기서 끊는다.
    // → send_email이면 진짜 서버는 호출조차 되지 않는다(=실제 차단).
    if (!decision.allowed) {
      console.error(`[proxy] ⛔ 차단  name=${name}  reason=${decision.reason}`);
      // 에이전트에게는 프로토콜 에러가 아니라 '도구 실행 결과가 에러'인 형태로 알린다.
      return {
        isError: true,
        content: [
          { type: "text", text: `🛑 정책 차단: ${decision.reason ?? "정책 위반"}` },
        ],
      };
    }

    // [통과] 0/1단계와 동일하게 중계한다.
    const result = await downstream.callTool(request.params);
    console.error(`[proxy] ⬅ 응답 통과  name=${name}`);

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
        sessionId: ctx.sessionId,
        toolName: name,
        isInjection: injectionResult.isInjection,
        score: injectionResult.score,
        timestamp: new Date().toISOString(),
      });
    }

    return result;
  });

  // ---------------------------------------------------------------------
  // (3) 서버 얼굴을 켠다: 에이전트가 우리를 spawn하면서 연결된 stdio에 붙는다.
  // ---------------------------------------------------------------------
  const upstreamTransport = new StdioServerTransport();
  await server.connect(upstreamTransport);

  // stdout은 에이전트와의 통신 전용이므로, 로그는 반드시 stderr로.
  console.error("[proxy] 기동됨. 에이전트 <-> 프록시 <-> 진짜 서버 사슬 준비 완료.");
}

main().catch((err) => {
  console.error("[proxy] 기동 실패:", err);
  process.exit(1);
});
