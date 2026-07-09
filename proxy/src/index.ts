/**
 * 프록시 — 에이전트와 실제 MCP 서버 사이에 끼는 투명 프록시.
 * 에이전트에겐 서버로(저수준 Server), 실제 서버에겐 클라이언트로(Client) 행세하며
 * tools/call을 가로채 검사·차단한다.
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
import { ToolRiskTag, SinkClass } from "@icarus-tether/types";
import type {
  ToolCallContext,
  PolicyDecision,
  AuditLogEntry,
} from "@icarus-tether/types";

// ESM엔 __dirname이 없어 import.meta.url로 계산 (실행 위치와 무관하게 경로 고정)
const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCK_SERVER_PATH = resolve(__dirname, "../test/mock-server.ts");
const AUDIT_LOG_PATH = resolve(__dirname, "../audit.log");

interface SessionState {
  id: string;
  createdAt: string;
  toolCalls: number;
  tags: Set<ToolRiskTag>; // 이 세션이 지금까지 결과에서 본 오염 태그
}

// 세션 저장소. stdio에선 세션 1개지만, 다중 클라이언트(HTTP)로 확장되면 여기에 여러 개가 쌓인다.
const sessions = new Map<string, SessionState>();

// 기록 내용의 sha256 해시 = 위변조 방지 서명. 나중에 다시 계산해 비교하면 변조를 탐지.
function signEntry(entry: Omit<AuditLogEntry, "signature">): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

// 판정 하나를 서명 붙여 audit.log에 JSON 한 줄로 append. (C가 나중에 이 기록을 전시)
function writeAuditLog(entry: Omit<AuditLogEntry, "signature">): void {
  const signed: AuditLogEntry = { ...entry, signature: signEntry(entry) };
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(signed) + "\n");
}

// 도메인 파트의 정책 엔진이 꽂힐 자리. 지금은 스텁이며, 이 함수 본문만 실제 엔진 호출로 교체하면 된다.
async function requestPolicyCheck(
  ctx: ToolCallContext,
  sessionTags: Set<ToolRiskTag>
): Promise<PolicyDecision> {
  const isOutbound = getToolInfo(ctx.toolName).sinkClass === SinkClass.OUTBOUND_SINK;
  const hasSensitive = sessionTags.has(ToolRiskTag.SENSITIVE);
  const hasUntrusted = sessionTags.has(ToolRiskTag.UNTRUSTED_ORIGIN);

  // 트라이펙타: 외부 유출 싱크 + 민감데이터 + 비신뢰입력이 한 세션에 겹칠 때만 차단.
  if (isOutbound && hasSensitive && hasUntrusted) {
    return {
      sessionId: ctx.sessionId,
      toolName: ctx.toolName,
      allowed: false,
      reason: "트라이펙타: 민감데이터+비신뢰입력이 쌓인 세션에서 외부 유출 시도",
      matchedTags: [ToolRiskTag.SENSITIVE, ToolRiskTag.UNTRUSTED_ORIGIN],
    };
  }
  return {
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    allowed: true,
    matchedTags: [],
  };
}

// 도메인 파트의 ToolRegistry가 꽂힐 자리. 도구 하나의 메타데이터를 한 표에 모은다.
interface ToolInfo {
  sourceTags: ToolRiskTag[]; // 이 도구 결과에 붙는 오염 태그
  sinkClass: SinkClass; // 이 도구가 데이터를 어디로 보내는지
}

const TOOL_REGISTRY: Record<string, ToolInfo> = {
  query_customer_db: { sourceTags: [ToolRiskTag.SENSITIVE], sinkClass: SinkClass.READ },
  read_webpage: { sourceTags: [ToolRiskTag.UNTRUSTED_ORIGIN], sinkClass: SinkClass.READ },
  send_email: { sourceTags: [], sinkClass: SinkClass.OUTBOUND_SINK },
};

function getToolInfo(toolName: string): ToolInfo {
  return TOOL_REGISTRY[toolName] ?? { sourceTags: [], sinkClass: SinkClass.READ };
}

async function main() {
  // stdio에선 이 프록시 프로세스 하나가 클라이언트 하나를 상대한다 = 세션 하나.
  const sessionId = randomUUID();
  sessions.set(sessionId, {
    id: sessionId,
    createdAt: new Date().toISOString(),
    toolCalls: 0,
    tags: new Set(),
  });
  console.error(`[proxy] 세션 시작  session=${sessionId}`);

  const downstream = new Client({
    name: "icarus-tether-proxy-client",
    version: "0.1.0",
  });
  const downstreamTransport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", MOCK_SERVER_PATH],
  });
  await downstream.connect(downstreamTransport);

  // 저수준 Server를 쓰는 이유: 프록시는 도구를 미리 모르므로 임의 요청을 그대로 중계해야 한다.
  const server = new Server(
    { name: "icarus-tether-proxy", version: "0.1.0" },
    { capabilities: { tools: {} } }
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

    const decision = await requestPolicyCheck(ctx, session?.tags ?? new Set());

    writeAuditLog({
      id: randomUUID(),
      sessionId,
      toolName: name,
      decision: decision.allowed ? "ALLOWED" : "BLOCKED",
      matchedTags: decision.matchedTags,
      timestamp: new Date().toISOString(),
    });
    if (!decision.allowed) {
      console.error(`[proxy] 차단  ${name}  reason=${decision.reason}`);
      return {
        isError: true,
        content: [
          { type: "text", text: `정책 차단: ${decision.reason ?? "정책 위반"}` },
        ],
      };
    }

    const result = await downstream.callTool(request.params);

    // 결과에 실린 태그를 분류(스텁)해 세션에 누적한다.
    for (const tag of getToolInfo(name).sourceTags) session?.tags.add(tag);
    console.error(
      `[proxy] ⬅ 통과  ${name}  세션태그=[${[...(session?.tags ?? [])].join(", ")}]`
    );
    return result;
  });

  // stdout은 에이전트와의 JSON-RPC 전용선이므로, 로그는 반드시 stderr(console.error)로.
  const upstreamTransport = new StdioServerTransport();
  await server.connect(upstreamTransport);
  console.error(`[proxy] 기동됨. session=${sessionId}`);
}

main().catch((err) => {
  console.error("[proxy] 기동 실패:", err);
  process.exit(1);
});
