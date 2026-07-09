/**
 * 테스트용 실제 서버 대역 — 도구 2개짜리 미니 MCP 서버.
 * 실제 배포에선 진짜 DB·메일 서버로 교체된다.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "mock-tool-server",
  version: "0.0.1",
});

// 읽기 전용 조회 (트라이펙타에서 SENSITIVE 소스가 될 도구)
server.registerTool(
  "query_customer_db",
  {
    description: "고객 ID로 고객 정보를 조회한다 (읽기 전용)",
    inputSchema: { customerId: z.string() },
  },
  async ({ customerId }) => {
    return {
      content: [
        {
          type: "text",
          text: `고객 ${customerId}: 이름=홍길동, 이메일=hong@example.com, 등급=VIP`,
        },
      ],
    };
  }
);

// 외부로 나가는 싱크 (차단 대상)
server.registerTool(
  "send_email",
  {
    description: "외부로 이메일을 전송한다 (외부 유출 싱크)",
    inputSchema: {
      to: z.string(),
      subject: z.string(),
      body: z.string(),
    },
  },
  async ({ to, subject }) => {
    return {
      content: [
        { type: "text", text: `이메일 전송 완료 -> ${to} / 제목: ${subject}` },
      ],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout은 JSON-RPC 전용선이므로 로그는 반드시 stderr로.
  console.error("[mock-server] 기동됨.");
}

main().catch((err) => {
  console.error("[mock-server] 기동 실패:", err);
  process.exit(1);
});
