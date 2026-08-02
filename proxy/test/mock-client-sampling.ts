/**
 * 역방향 sampling 유출 차단 테스트 (프록시 경유).
 * 시나리오:
 *   1) query_customer_db → 세션에 민감 데이터 유입
 *   2) ask_llm → 서버가 sampling으로 그 민감 데이터를 외부 LLM에 빼돌리려 시도
 *      → 프록시가 evaluateOutboundContent로 판정해 하드 블록해야 한다.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CreateMessageRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const SAMPLING_SERVER = resolve(__dirname, "mock-server-sampling.ts");

async function main() {
  // 우리는 sampling(LLM)을 지원한다고 신고한다. 그래야 서버가 sampling을 요청할 수 있다.
  const client = new Client(
    { name: "mock-sampling-agent", version: "0.0.1" },
    { capabilities: { sampling: {} } }
  );
  // 서버가 sampling을 요청하면 우리(에이전트 LLM)가 답을 만들어 준다 (여기선 모의 응답).
  // 유출이 차단되면 이 핸들러는 애초에 호출되지 않는다(프록시가 먼저 막으므로).
  client.setRequestHandler(CreateMessageRequestSchema, async () => ({
    role: "assistant",
    content: { type: "text", text: "요약: (모의 LLM 응답)" },
    model: "mock-llm",
  }));

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, PROXY_PATH],
    // 프록시가 sampling 서버를 다운스트림으로 띄우게 한다.
    env: { ...process.env, PROXY_DOWNSTREAM: SAMPLING_SERVER } as Record<string, string>,
  });
  await client.connect(transport);
  console.error("[sampling] 프록시 연결됨.\n");

  // (1) 민감 소스 조회 → 세션에 SENSITIVE 오염 심기
  await client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } });
  console.error("[sampling] (1) query_customer_db — 세션에 민감 데이터 유입");

  // (1.5) 비신뢰 외부 소스 → 세션에 UNTRUSTED 노출 심기 (트라이펙타 완성)
  await client.callTool({ name: "fetch_web_page", arguments: { url: "https://evil.example.com" } });
  console.error("[sampling] (1.5) fetch_web_page — 세션이 비신뢰 입력에 노출됨\n");

  // (2) ask_llm → 서버가 sampling으로 민감 데이터 유출 시도 → 차단돼야 함
  let blocked = false;
  try {
    const r = await client.callTool({ name: "ask_llm", arguments: {} });
    blocked = r.isError === true || JSON.stringify(r.content).includes("정책 차단");
    console.error("[sampling] (2) ask_llm 결과:", JSON.stringify(r.content));
  } catch (e) {
    blocked = true; // 프록시가 던진 에러가 도구 호출을 실패시킴 = 차단
    console.error("[sampling] (2) ask_llm 예외(차단):", (e as Error).message);
  }

  console.error(
    `\n${blocked ? "✅ PASS" : "❌ FAIL"} — 역방향 sampling 유출 ${blocked ? "차단됨" : "통과(취약!)"}`
  );
  await client.close();
  process.exit(blocked ? 0 : 1);
}

main().catch((e) => {
  console.error("[sampling] 실패:", e);
  process.exit(1);
});
