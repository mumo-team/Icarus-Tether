/**
 * [테스트 하네스] 진짜 MCP 서버 역할 — "장난감 목적지"
 *
 * 프록시를 시험하려면 프록시가 요청을 넘길 "진짜 서버"가 있어야 한다.
 * 실제 배포에서는 진짜 DB 서버·Gmail 서버 등으로 교체될, 일회용 대역이다.
 *
 * 도구 2개:
 *   - query_customer_db : 읽기 전용 조회 (나중에 SENSITIVE 소스가 됨)
 *   - send_email        : 외부 유출 싱크 (3단계에서 차단 대상이 됨)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// 고수준 헬퍼. name/version은 initialize 핸드셰이크 때 상대방에게 자기소개로 보낸다.
const server = new McpServer({
  name: "mock-tool-server",
  version: "0.0.1",
});

// --- 도구 1: 고객 DB 조회 (읽기 전용) ---
server.registerTool(
  "query_customer_db",
  {
    description: "고객 ID로 고객 정보를 조회한다 (읽기 전용)",
    // inputSchema는 zod로 쓴 인자 규격. SDK가 이걸 JSON Schema로 변환해
    // tools/list 응답에 실어주고, 들어온 인자를 자동 검증해준다.
    inputSchema: { customerId: z.string() },
  },
  // 실제로 도구가 하는 일. 지금은 위험한 짓 없이 가짜 문자열만 돌려준다.
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

// --- 도구 2: 이메일 전송 (외부로 나가는 싱크) ---
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
  // stdio 전송: 이 프로세스의 stdin으로 요청을 받고, stdout으로 응답을 보낸다.
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // 주의: stdout은 JSON-RPC 통신 전용 채널이다. 여기에 console.log를 찍으면
  // 프로토콜 스트림이 깨진다. 그래서 사람이 볼 로그는 반드시 stderr로 보낸다.
  console.error("[mock-server] 기동됨. 도구 2개 제공 대기 중...");
}

main().catch((err) => {
  console.error("[mock-server] 기동 실패:", err);
  process.exit(1);
});
