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
// ① 정책 엔진(B) — 판정과 오염 기록의 실제 구현.
import { evaluateToolCall, recordToolResult } from "@icarus-tether/policy-engine";

// ★ stdout 보호: stdio MCP에서 stdout은 JSON-RPC 전용 채널이다.
// 정책 엔진은 TrifectaEvent·[SHADOW] 로그를 console.log(stdout)로 찍으므로,
// 그대로 두면 첫 차단 로그가 프로토콜 스트림을 깨뜨린다. 이 프로세스의
// console.log를 전부 stderr로 우회시킨다 (프록시 자신도 stderr만 쓰는 규칙).
console.log = (...args: unknown[]) => console.error(...args);

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
 * [연결 완료] 검사 소켓 — B의 정책 엔진(①)이 꽂힌 자리.
 *
 * 스텁(send_email "이름" 무조건 차단)과 달리, 엔진은 "데이터 흐름"으로 판정한다:
 * 같은 send_email이라도 세션에 민감(SENSITIVE)+비신뢰(UNTRUSTED_ORIGIN) 오염이
 * 겹쳐 있을 때(lethal trifecta)만 차단된다. 판정 규칙·도구 분류는 전부
 * policy-engine/config/*.json에서 온다 (기본: tool-registry.json, session 모드).
 *
 * evaluateToolCall은 동기 함수지만 async 시그니처 안에서 그대로 반환하면 된다 —
 * 프록시 배선(핸들러 구조)은 그대로다.
 */
async function requestPolicyCheck(ctx: ToolCallContext): Promise<PolicyDecision> {
  return evaluateToolCall(ctx);
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
      // 데모용 고정 세션. 실전에서는 MCP 연결(에이전트 세션) 단위로 발급해야
      // 세션 간 오염이 섞이지 않는다. 긴 세션에서는 주기적으로
      // pruneSessionLineage(sessionId) 호출로 계보를 압축할 것 (선택 계약).
      sessionId: "demo-session-1",
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

    // ★★ 오염 기록 — 이게 없으면 엔진이 무력화된다(fail-open).
    // 엔진의 계보·세션 태그는 "기록된 도구 결과"에서만 자란다. 결과를 에이전트에
    // 돌려주기 전에 반드시 기록한다. isError 결과도 기록 — 에러 텍스트에도
    // 민감정보가 실릴 수 있다. (차단 경로는 downstream 미호출이라 기록할 결과 없음)
    try {
      recordToolResult(ctx.sessionId, name, ctx.args, result);
    } catch (err) {
      // 기록 실패 = 오염 추적이 안 된 결과. 그대로 넘기면 이후 판정이 이 데이터를
      // 못 보는 fail-open이 되므로, 결과를 보류하고 에러로 알린다 (fail-safe).
      console.error(`[proxy] ⚠ 오염 기록 실패 — 결과 전달 보류  name=${name}`, err);
      return {
        isError: true,
        content: [
          { type: "text", text: "🛑 안전장치: 도구 결과의 오염 추적에 실패해 결과 전달을 보류합니다." },
        ],
      };
    }

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
