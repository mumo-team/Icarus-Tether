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
import { z } from "zod";
import { ToolRiskTag, SinkClass } from "@icarus-tether/types";
import type {
  ToolCallContext,
  PolicyDecision,
  AuditLogEntry,
  ApprovalRequest,
  ApprovalStatus,
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
function signEntry(entry: unknown): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

// 판정 하나를 서명 붙여 audit.log에 JSON 한 줄로 append. (C가 나중에 이 기록을 전시)
function writeAuditLog(entry: Omit<AuditLogEntry, "signature">): void {
  const signed: AuditLogEntry = { ...entry, signature: signEntry(entry) };
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(signed) + "\n");
}

// 승인 요청의 최종 결과(누가·언제·승인/거부)를 서명 붙여 audit.log에 남긴다.
function writeApprovalLog(req: ApprovalRequest): void {
  appendFileSync(
    AUDIT_LOG_PATH,
    JSON.stringify({ ...req, signature: signEntry(req) }) + "\n"
  );
}

// 승인 대기 중인 요청들: id → "그 요청을 깨울 resolve 함수"를 보관.
const pendingApprovals = new Map<string, (status: ApprovalStatus) => void>();

// 승인을 요청하고, 사람이 결정할 때까지 기다리는 Promise를 돌려준다. (deferred 패턴)
function requestApproval(req: ApprovalRequest): Promise<ApprovalStatus> {
  return new Promise((resolve) => {
    pendingApprovals.set(req.id, resolve); // resolve를 보관만 하고 Promise는 아직 안 끝남
    console.error(`[proxy] 승인 대기  id=${req.id}  tool=${req.toolName}`);
  });
}

// 사람(또는 C)이 결정을 내리면 호출된다. 보관된 resolve를 불러 대기 중인 요청을 깨운다.
function resolveApproval(id: string, status: ApprovalStatus): void {
  const resolve = pendingApprovals.get(id);
  if (!resolve) return; // 이미 처리됐거나 없는 id
  pendingApprovals.delete(id);
  resolve(status);
}

// [C 자리 스텁] 사람 심사 시뮬레이션. 실제로는 C의 승인 큐에서 사람이 누른다.
// env APPROVAL_DECISION="approve"일 때만 승인, 아니면 거부(안전 기본값).
function simulateHumanReview(req: ApprovalRequest): void {
  const status: ApprovalStatus =
    process.env.APPROVAL_DECISION === "approve" ? "APPROVED" : "REJECTED";
  setTimeout(() => {
    console.error(`[proxy] (스텁) 사람 결정: ${status}  id=${req.id}`);
    resolveApproval(req.id, status);
  }, 500); // 사람이 잠깐 고민하는 시간을 흉내
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

    const decision = await requestPolicyCheck(ctx, session?.tags ?? new Set());

    // 정책상 막힐 케이스(트라이펙타)면 즉시 차단하지 않고 사람 승인을 받는다.
    let allowed = decision.allowed;
    let resolvedBy: string | undefined;
    if (!decision.allowed) {
      const req: ApprovalRequest = {
        id: randomUUID(),
        sessionId,
        toolName: name,
        args: ctx.args,
        status: "PENDING",
        requestedAt: new Date().toISOString(),
      };
      const pending = requestApproval(req); // 대기 등록
      simulateHumanReview(req); // C 자리: 심사 시작
      const status = await pending; // 사람 결정 대기

      req.status = status;
      req.resolvedAt = new Date().toISOString();
      req.resolvedBy = "stub-reviewer"; // 실제로는 승인한 사람 ID
      writeApprovalLog(req); // 누가 승인/거부했는지 영구 기록

      allowed = status === "APPROVED";
      resolvedBy = req.resolvedBy;
    }

    writeAuditLog({
      id: randomUUID(),
      sessionId,
      toolName: name,
      decision: allowed ? "ALLOWED" : "BLOCKED",
      matchedTags: decision.matchedTags,
      timestamp: new Date().toISOString(),
    });

    if (!allowed) {
      console.error(`[proxy] 차단  ${name}  (by=${resolvedBy ?? "정책"})`);
      return {
        isError: true,
        content: [
          { type: "text", text: `정책 차단: ${decision.reason ?? "정책 위반"}` },
        ],
      };
    }
    if (resolvedBy) console.error(`[proxy] 승인됨 → 진행  ${name}  (by=${resolvedBy})`);

    const result = await downstream.callTool(request.params);

    // 결과에 실린 태그를 분류(스텁)해 세션에 누적한다.
    for (const tag of getToolInfo(name).sourceTags) session?.tags.add(tag);
    console.error(
      `[proxy] ⬅ 통과  ${name}  세션태그=[${[...(session?.tags ?? [])].join(", ")}]`
    );
    return result;
  });

  // stdout은 에이전트와의 JSON-RPC 전용선이므로, 로그는 반드시 stderr(console.error)로.
  // [투명성] tools 외 모든 요청·알림은 손대지 않고 그대로 중계한다.
  // 임의 메서드를 통과시키므로 타입 유니온을 우회(any)하고, 결과는 관대한 스키마로 받는다.
  server.fallbackRequestHandler = async (req) =>
    downstream.request({ method: req.method, params: req.params } as any, z.any());
  server.fallbackNotificationHandler = async (n) =>
    downstream.notification(n as any);
  // 역방향(서버→클라, 예: sampling/roots)도 통과.
  downstream.fallbackRequestHandler = async (req) =>
    server.request({ method: req.method, params: req.params } as any, z.any());
  downstream.fallbackNotificationHandler = async (n) => server.notification(n as any);

  const upstreamTransport = new StdioServerTransport();
  await server.connect(upstreamTransport);
  console.error(`[proxy] 기동됨. session=${sessionId}`);
}

main().catch((err) => {
  console.error("[proxy] 기동 실패:", err);
  process.exit(1);
});
