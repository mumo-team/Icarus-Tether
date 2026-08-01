/**
 * Phase 2 페더레이션 데모 — 'mail' 서버.
 * 외부 유출 싱크(send_email)만 노출한다. 민감/비신뢰 소스는 'db' 서버에 있다.
 * → 프록시가 두 서버에 걸친 세션 오염을 추적해, 여기서 유출을 차단하는지 보인다.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "mail-server", version: "0.0.1" });

server.registerTool(
  "send_email",
  {
    description: "외부로 이메일을 전송한다 (외부 유출 싱크)",
    inputSchema: { to: z.string(), subject: z.string(), body: z.string() },
  },
  async ({ to, subject }) => ({
    content: [{ type: "text", text: `이메일 전송 완료 -> ${to} / 제목: ${subject}` }],
  })
);

async function main() {
  await server.connect(new StdioServerTransport());
  console.error("[mail-server] 기동됨.");
}

main().catch((err) => {
  console.error("[mail-server] 기동 실패:", err);
  process.exit(1);
});
