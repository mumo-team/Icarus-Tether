/**
 * 프록시 — 에이전트와 실제 MCP 서버 사이에 끼는 투명 프록시.
 * 에이전트에겐 서버로(저수준 Server), 실제 서버에겐 클라이언트로(Client) 행세하며
 * tools/call을 가로채 정책 엔진의 판정대로 통과·차단한다.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { readFileSync, watch } from "node:fs";
import { startDashboardBridge, stopDashboardBridge, broadcastDecision, recordAudit, broadcastAuditIntegrity, broadcastLineage } from "./dashboard-bridge.js";
import { checkInjection } from "./injection.js";
// 순수 라우팅·분류 헬퍼 (Phase 4에서 퍼징 가능하도록 분리).
// (URI 신뢰 판정은 C-7로 엔진에 이관 — isResourceTrusted 임시 휴리스틱 제거)
import { classifyMethod, splitAgentToolName, type MethodRisk } from "./routing.js";
import { z } from "zod";
// 검사함수가 주고받을 표준 계약. 세 파트 공용 타입(B가 이 모양으로 판정한다).
import type { ToolCallContext } from "@icarus-tether/types";
// ① 정책 엔진(B) — 판정과 오염 기록의 실제 구현.
import {
  evaluateToolCall,
  evaluateOutboundContent,
  evaluateResourceRequest,
  recordToolResult,
  recordExternalContent,
  reloadPolicyConfig,
  requestApproval,
  resolveApproval,
} from "@icarus-tether/policy-engine";

// ★ stdout 보호: stdio에서 stdout은 JSON-RPC 전용 채널인데, 정책 엔진은 로그를
// console.log(stdout)로 찍는다. 그대로 두면 첫 로그가 프로토콜 스트림을 깨뜨리므로
// 이 프로세스의 console.log를 전부 stderr로 우회시킨다.
console.log = (...args: unknown[]) => console.error(...args);

// ESM엔 __dirname이 없어 import.meta.url로 계산 (실행 위치와 무관하게 경로 고정)
const __dirname = dirname(fileURLToPath(import.meta.url));
// 다운스트림 서버 경로. 기본은 데모용 mock-server. 테스트에서 PROXY_DOWNSTREAM으로 교체 가능.
const MOCK_SERVER_PATH = process.env.PROXY_DOWNSTREAM
  ? resolve(process.env.PROXY_DOWNSTREAM)
  : resolve(__dirname, "../test/mock-server.ts");
// npx 대신 로컬 tsx를 절대경로로 직접 실행한다. npx는 cwd 기준으로 tsx를 찾기 때문에,
// 에이전트가 임의의 cwd에서 프록시를 띄우면 tsx를 인터넷에서 새로 받으려 한다(느리고 오프라인 실패).
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");


interface SessionState {
  id: string;
  createdAt: string;
  toolCalls: number;
}

// 세션 저장소. stdio에선 세션 1개지만, 다중 클라이언트(HTTP)로 확장되면 여러 개가 쌓인다.
// (오염 태그는 정책 엔진이 sessionId로 내부 추적하므로 여기서 들고 있지 않는다.)
const sessions = new Map<string, SessionState>();


// ── Phase 2: 멀티서버 페더레이션 ──────────────────────────────────────────
// PROXY_SERVERS_CONFIG(설정 파일 경로)가 있으면 페더레이션 모드: 여러 다운스트림 서버에
// 붙어 도구를 '서버명.도구명'으로 합쳐 노출하고, 호출을 접두사로 라우팅한다.
// 없으면 기존 단일 다운스트림 모드(모든 기존 테스트·데모 그대로).
// (순수 분류·라우팅 헬퍼 classifyMethod/splitAgentToolName은
//  퍼징 가능하도록 ./routing.ts로 분리했다 — Phase 4.)
interface ServerEntry {
  name: string;
  module?: string; // stdio: proxy 기준 상대경로 tsx 모듈
  url?: string; // http: Streamable HTTP 다운스트림
}

function loadServerConfig(): ServerEntry[] | null {
  const path = process.env.PROXY_SERVERS_CONFIG;
  if (!path) return null;
  const raw = JSON.parse(readFileSync(resolve(path), "utf8")) as {
    servers: Record<string, { module?: string; url?: string }>;
  };
  return Object.entries(raw.servers).map(([name, v]) => ({ name, ...v }));
}

// tools 외 메서드를 무검사로 중계할 때, 최소한 그 사실을 눈에 보이게 남긴다(S5 대응 1단계).
// audit.log는 dashboard-bridge가 해시 체인(ALLOWED/BLOCKED 판정)으로 관리하므로,
// 여기서 파일에 직접 append하면 체인이 깨진다 → stderr 로그로만 남긴다.
// (정식 해결: 메서드 위험도 분류로 이 경로도 판정·기록 — 별도 작업 (사))
function logForwarded(sessionId: string, method: string, risk: MethodRisk = "UNCLASSIFIED"): void {
  // SINK는 눈에 띄게, 미분류(?)는 주의 표시, 무해는 표식 없음.
  const mark = risk === "SINK" ? "⚠SINK " : risk === "UNCLASSIFIED" ? "? " : "";
  console.error(`[proxy] ↪ 무검사 중계 ${mark} method=${method}  session=${sessionId}`);
}

// fallback로 빠지는 메서드를 분류해 audit.log에 정식 기록하고 stderr에도 남긴다.
// '무검사 통과'는 진짜 검사 통과(ALLOWED)와 구분되도록 FORWARDED로 기록한다(e-2).
function auditForward(sessionId: string, method: string, reverse = false): void {
  const risk = classifyMethod(method); // 분류는 항상 순수 메서드명으로 (↩ 방향표시 제거된 값)
  const label = reverse ? `↩${method}` : method; // 로그·기록엔 방향을 남긴다
  logForwarded(sessionId, label, risk);
  recordAudit({
    sessionId,
    toolName: label, // 'resources/read'처럼 '/'가 있어 실제 도구명과 구분된다
    decision: "FORWARDED", // 검사 없이 중계됨 — 통과(ALLOWED)와 구분
    matchedTags: [],
  });
}

// 로그용 안전 직렬화. JSON.stringify는 순환참조(TypeError)·과대 깊이(RangeError)에서
// 던지는데, 이 로그가 recordAudit보다 먼저라 그대로 두면 '감사 기록 전에 죽어' 감사 공백이
// 생긴다(e-1). 절대 던지지 않게 감싸고 길이도 제한한다.
function safeArgs(args: unknown): string {
  try {
    const s = JSON.stringify(args ?? {});
    return s.length > 500 ? `${s.slice(0, 500)}…(생략)` : s;
  } catch {
    return "[직렬화 불가 — 순환참조/과대 인자]";
  }
}

// Phase 3: 정책 핫리로드. 설정 파일이 바뀌면 재시작 없이 다음 요청부터 새 정책을 적용한다.
// reloadPolicyConfig()는 '검증-후-교체'라 새 설정이 유효할 때만 캐시를 바꾸고, 실패하면
// throw하되 기존 정책이 그대로 살아있다 → try/catch로 감싸 로그만 남기면 안전하다.
function watchPolicyConfig(): void {
  const path = process.env.TAINTGUARD_TOOL_REGISTRY;
  if (!path) return; // 명시 경로 없음(기본 레지스트리) → 감시 생략
  const resolved = resolve(path);
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    watch(resolved, () => {
      // 에디터 저장이 write 이벤트를 여러 번 쏘므로 디바운스한다.
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        try {
          reloadPolicyConfig(); // 유효할 때만 원자적 교체. 실패해도 기존 정책 유지.
          console.error(`[proxy] 🔄 정책 핫리로드 적용됨 ← ${resolved}`);
        } catch (err) {
          console.error(`[proxy] ⚠ 정책 리로드 실패 — 기존 정책 유지: ${(err as Error).message}`);
        }
      }, 200);
    });
    console.error(`[proxy] 정책 파일 감시 시작: ${resolved}`);
  } catch (err) {
    console.error(`[proxy] 정책 파일 감시 실패: ${(err as Error).message}`);
  }
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
  startDashboardBridge();
  watchPolicyConfig(); // Phase 3: 설정 파일 변경 시 재시작 없이 정책 핫리로드

  // 다운스트림 서버 하나에 연결하는 헬퍼. HTTP(url) 또는 stdio(module 상대경로) 전송.
  // sampling capability를 신고해야 서버가 역방향 sampling을 쓸 수 있다(Phase 1에서 추가).
  async function connectServer(entry: ServerEntry): Promise<Client> {
    const client = new Client(
      { name: `icarus-tether-proxy→${entry.name || "downstream"}`, version: "0.1.0" },
      { capabilities: { sampling: {} } }
    );
    const transport = entry.url
      ? new StreamableHTTPClientTransport(new URL(entry.url))
      : new StdioClientTransport({
          command: process.execPath, // cwd 무관 절대경로 node
          args: [TSX_CLI, entry.module ? resolve(__dirname, "..", entry.module) : MOCK_SERVER_PATH],
        });
    await client.connect(transport);
    return client;
  }

  // 페더레이션 모드면 설정의 여러 서버에, 아니면 단일 다운스트림에 연결한다.
  const federationConfig = loadServerConfig();
  const federated = federationConfig !== null;
  const servers: { name: string; client: Client }[] = [];
  if (federated) {
    for (const entry of federationConfig!) {
      servers.push({ name: entry.name, client: await connectServer(entry) });
      console.error(
        `[proxy] 다운스트림 연결: ${entry.name} (${entry.url ? `HTTP ${entry.url}` : `stdio ${entry.module}`})`
      );
    }
  } else {
    // 단일 모드: PROXY_DOWNSTREAM_URL(HTTP) 또는 MOCK_SERVER_PATH(stdio).
    const entry: ServerEntry = { name: "", url: process.env.PROXY_DOWNSTREAM_URL };
    servers.push({ name: "", client: await connectServer(entry) });
    console.error(`[proxy] 다운스트림 전송: ${process.env.PROXY_DOWNSTREAM_URL ? `HTTP` : "stdio"}`);
  }
  // 프라이머리 = 첫 서버. tools 외 요청(resources/sampling 등)의 기본 중계 대상.
  const primary = servers[0].client;

  // 저수준 Server를 쓰는 이유: 프록시는 도구를 미리 모르므로 임의 요청을 그대로 중계해야 한다.
  // capabilities는 프라이머리가 노출하는 것을 신고(페더레이션에선 모든 서버가 tools 제공).
  const server = new Server(
    { name: "icarus-tether-proxy", version: "0.1.0" },
    { capabilities: primary.getServerCapabilities() ?? { tools: {} } }
  );

  // 클라이언트가 stdin을 닫으면(EOF) 대화가 끝난 것 → 세션 정리.
  // (StdioServerTransport는 stdin EOF에 onclose를 부르지 않으므로 'end'를 직접 듣는다.)
  process.stdin.on("end", () => {
    const s = sessions.get(sessionId);
    console.error(
      `[proxy] 세션 종료  session=${sessionId}  (도구호출 ${s?.toolCalls ?? 0}건)`
    );
    sessions.delete(sessionId);
    // 세션 로그 전체를 검증해 무결성 결과를 대시보드에 방송한다.
    broadcastAuditIntegrity();
    // 방송이 소켓에 실제로 나갈 시간을 준 뒤 종료한다 — 즉시 exit하면 flush 전에 죽는다.
    setTimeout(() => {
      stopDashboardBridge();
      process.exit(0);
    }, 300);
  })

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    // 단일 모드: 그대로. 페더레이션: 모든 서버의 도구를 '서버명.도구명'으로 합쳐 노출.
    if (!federated) return await primary.listTools();
    const all: Awaited<ReturnType<Client["listTools"]>>["tools"] = [];
    for (const { name, client } of servers) {
      const { tools } = await client.listTools();
      for (const t of tools) all.push({ ...t, name: `${name}.${t.name}` });
    }
    return { tools: all };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: agentName, arguments: args } = request.params;
    // 페더레이션: 'db.query_customer_db' → 서버 'db' + 속이름 'query_customer_db'.
    // 단일 모드: 접두사 없이 그대로.
    const [prefix, bareName] = federated ? splitAgentToolName(agentName) : ["", agentName];
    const target = federated ? servers.find((s) => s.name === prefix)?.client : primary;
    if (!target) {
      return {
        isError: true,
        content: [{ type: "text", text: `알 수 없는 서버 접두사: '${prefix}' (${agentName})` }],
      };
    }

    const session = sessions.get(sessionId);
    if (session) session.toolCalls += 1;
    console.error(`[proxy] ⮕ ${agentName}  args=${safeArgs(args)}  session=${sessionId}`);

    // ★ 엔진 판정·오염기록은 '속이름'으로 한다 — 레지스트리는 접두사 붙은 이름을 모른다.
    const ctx: ToolCallContext = {
      sessionId,
      toolName: bareName,
      args: (args ?? {}) as Record<string, unknown>,
      argTags: [],
      timestamp: new Date().toISOString(),
    };

    // 정책 엔진의 판정. 엔진이 세션 오염을 내부 추적하므로 태그를 따로 넘기지 않는다.
    const decision = evaluateToolCall(ctx);

    recordAudit({
      sessionId,
      toolName: agentName, // 감사엔 겉이름(어느 서버로 라우팅됐는지 보이게)
      decision: decision.allowed ? "ALLOWED" : "BLOCKED",
      matchedTags: decision.matchedTags,
    });

    broadcastDecision(sessionId, agentName, decision, ctx.timestamp);
    broadcastLineage(sessionId); // 판정 직후 현재 계보 스냅샷 방송 → TaintGraph 실시간 갱신

    if (!decision.allowed) {
      console.error(`[proxy] 차단  ${agentName}  reason=${decision.reason}`);
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

    // 라우팅: 대상 서버에 '속이름'으로 실제 호출한다.
    const result = await target.callTool({ name: bareName, arguments: args });

    // ★ 오염 기록 — 엔진의 세션 오염은 '기록된 결과'에서만 자란다. 빠뜨리면 fail-open.
    // 기록 실패 시엔 추적 안 된 데이터를 넘기지 않고 막는다 (fail-safe).
    try {
      recordToolResult(sessionId, bareName, ctx.args, result);
    } catch (err) {
      console.error(`[proxy] 오염 기록 실패 — 결과 전달 보류  ${agentName}`, err);
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

    console.error(`[proxy] ⬅ 통과  ${agentName}`);

   // 비신뢰 출처 콘텐츠 인젝션 검사 (대상 판단·점수 산출·방송은 injection.ts가 한다).
    await checkInjection(sessionId, bareName, result);

    return result;
  });

  // [투명성] tools 외 모든 요청·알림은 그대로 중계한다.
  // ⚠️ 알려진 한계(S5 fail-open): 이 경로는 정책 검사·오염 추적을 거치지 않는다.
  // 그 전까지의 완화책(작업 사-A): 요청은 메서드 위험도로 분류해 audit.log에 정식
  // 기록하고, SINK(sampling 등)는 stderr에 ⚠로 드러낸다. 근본 해결(resources/read
  // 결과의 SOURCE 오염 태깅)은 엔진(B) 몫 → 사-B 이슈. 알림은 데이터를 안 나르고
  // 양이 많아 stderr 로그만 남긴다(audit 기록은 요청만).
  server.fallbackRequestHandler = async (req) => {
    const method = req.method;
    // SOURCE 채널: 외부 콘텐츠가 세션으로 유입되는 경로. 결과를 받아 recordExternalContent로
    // 오염 태깅해야 이후 이 콘텐츠가 send_email 등으로 나갈 때 차단된다 (S5 근본 차단).
    if (method === "resources/read" || method === "prompts/get") {
      const uri = String(
        (req.params as { uri?: unknown; name?: unknown })?.uri ??
          (req.params as { name?: unknown })?.name ??
          method
      );
      // ★ C-7+③: 중계 전에 엔진이 요청 자체를 판정한다. 비신뢰 URI로 나가는 요청은
      // "읽기"라도 경계 밖 통신(URI에 데이터를 실으면 유출구) — sink 강도로 검사된다.
      let requestDecision;
      try {
        requestDecision = evaluateResourceRequest(sessionId, method, uri, req.params);
      } catch (err) {
        // fail-safe: 판정 실패 시 중계하지 않는다.
        console.error(`[proxy] 리소스 요청 판정 실패 — 차단  ${method}:${uri}`, err);
        throw new Error("안전장치: 리소스 요청 판정 실패로 차단합니다.");
      }
      if (!requestDecision.allowed) {
        console.error(`[proxy] 차단(리소스 요청)  ${method}:${uri}  reason=${requestDecision.reason}`);
        recordAudit({
          sessionId,
          toolName: `${method}:${uri}`,
          decision: "BLOCKED",
          matchedTags: requestDecision.matchedTags,
        });
        broadcastDecision(sessionId, `${method}:${uri}`, requestDecision, new Date().toISOString());
        throw new Error(
          `정책 차단: ${requestDecision.explanation?.summary ?? requestDecision.reason ?? "리소스 요청 유출 차단"}`
        );
      }

      const result = await primary.request({ method, params: req.params } as any, z.any());
      try {
        // URI 신뢰 판정은 엔진 소유(C-7) — trusted를 넘기지 않으면 registry
        // (trustedResourceUris)의 접두사 규칙으로 엔진이 판정한다.
        recordExternalContent(sessionId, method, uri, result);
      } catch (err) {
        // fail-safe: 오염 추적 실패 시 추적 안 된 콘텐츠를 넘기지 않는다(tools/call과 동일).
        console.error(`[proxy] 외부 콘텐츠 오염 기록 실패 — 전달 보류  ${method}:${uri}`, err);
        throw new Error("안전장치: 외부 콘텐츠 오염 추적 실패로 전달을 보류합니다.");
      }
      console.error(`[proxy] ✅ 외부 콘텐츠 오염 기록  ${method}:${uri}  session=${sessionId}`);
      recordAudit({ sessionId, toolName: `${method}:${uri}`, decision: "ALLOWED", matchedTags: [] });
      return result;
    }
    auditForward(sessionId, method);
    // tools 외 요청(resources 등)은 프라이머리 서버로 중계 (페더레이션에선 미접두).
    return primary.request({ method, params: req.params } as any, z.any());
  };
  server.fallbackNotificationHandler = async (n) => {
    const m = (n as { method?: string }).method ?? "notification";
    logForwarded(sessionId, m, classifyMethod(m));
    return primary.notification(n as any);
  };
  // 역방향(서버→클라). sampling/createMessage는 서버가 클라 LLM에 컨텍스트를 보내는
  // 실제 유출구(SINK)라, 나가는 콘텐츠에 민감 오염이 실렸는지 판정해 하드 블록한다.
  // 역방향 요청은 어느 다운스트림에서든 올 수 있어, 모든 클라이언트에 같은 핸들러를 건다.
  for (const { client: dc } of servers) {
    dc.fallbackRequestHandler = async (req) => {
    const method = req.method;
    if (method === "sampling/createMessage") {
      let decision;
      try {
        decision = evaluateOutboundContent(sessionId, "sampling/createMessage", req.params);
      } catch (err) {
        // fail-safe: 판정 자체가 실패하면 통과시키지 않는다.
        console.error(`[proxy] 역방향 판정 실패 — 차단  ${method}`, err);
        throw new Error("안전장치: 역방향 콘텐츠 판정 실패로 차단합니다.");
      }
      recordAudit({
        sessionId,
        toolName: `↩${method}`,
        decision: decision.allowed ? "ALLOWED" : "BLOCKED",
        matchedTags: decision.matchedTags,
      });
      broadcastDecision(sessionId, `↩${method}`, decision, new Date().toISOString());
      if (!decision.allowed) {
        console.error(`[proxy] 차단(역방향)  ${method}  reason=${decision.reason}`);
        throw new Error(
          `정책 차단: ${decision.explanation?.summary ?? decision.reason ?? "역방향 유출 차단"}`
        );
      }
      console.error(`[proxy] ⬅ 검사 통과(역방향 SINK)  ${method}  session=${sessionId}`);
      return server.request({ method, params: req.params } as any, z.any());
    }
    auditForward(sessionId, method, true);
    return server.request({ method, params: req.params } as any, z.any());
    };
    dc.fallbackNotificationHandler = async (n) => {
      const m = (n as { method?: string }).method ?? "notification";
      logForwarded(sessionId, `↩${m}`, classifyMethod(m));
      return server.notification(n as any);
    };
  }

  // stdout은 에이전트와의 JSON-RPC 전용선이므로, 로그는 반드시 stderr(console.error)로.
  const upstreamTransport = new StdioServerTransport();
  await server.connect(upstreamTransport);
  console.error(`[proxy] 기동됨. session=${sessionId}`);
}

main().catch((err) => {
  console.error("[proxy] 기동 실패:", err);
  process.exit(1);
});