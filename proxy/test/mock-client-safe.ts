/**
 * 정상 케이스 테스트 — 비신뢰 소스(read_webpage) 없이 조회 후 메일 전송.
 * 트라이펙타 조건(SENSITIVE+UNTRUSTED)이 미충족이므로 send_email이 통과해야 한다.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");

async function main() {
  const client = new Client({ name: "mock-agent-safe", version: "0.0.1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, PROXY_PATH],
    env: process.env as Record<string, string>, // 엔진 config 경로(TAINTGUARD_*)를 프록시로 전달
  });
  await client.connect(transport);

  await client.callTool({
    name: "query_customer_db",
    arguments: { customerId: "12345" },
  });

  const emailResult = await client.callTool({
    name: "send_email",
    arguments: { to: "boss@company.com", subject: "업무 보고", body: "정상 메일" },
  });
  console.error("[safe] send_email 결과:", JSON.stringify(emailResult.content));

  await client.close();
}

main().catch((err) => {
  console.error("[safe] 실패:", err);
  process.exit(1);
});
