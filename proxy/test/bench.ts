/**
 * Phase 6: 성능 벤치마크.
 * 같은 도구 호출을 (1) 서버에 직접 연결 (2) 프록시 경유 로 각각 측정해,
 * 프록시가 붙이는 왕복 오버헤드를 perf_hooks(마이크로초 해상도)로 숫자화한다.
 * 프록시 경유엔 정책 판정·해시체인 감사·오염 기록·계보 방송 비용이 포함된다.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCK_SERVER = resolve(__dirname, "mock-server.ts");
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const TSX_CLI = resolve(__dirname, "../../node_modules/tsx/dist/cli.mjs");
const REGISTRY = resolve(__dirname, "../config/demo-registry.json");

const WARMUP = 15;
const ITER = 100;

interface Stats {
  min: number;
  median: number;
  mean: number;
  p95: number;
  max: number;
}

function stats(xs: number[]): Stats {
  const s = [...xs].sort((a, b) => a - b);
  const pct = (q: number) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return {
    min: s[0],
    median: pct(0.5),
    mean: xs.reduce((a, b) => a + b, 0) / xs.length,
    p95: pct(0.95),
    max: s[s.length - 1],
  };
}

async function connect(args: string[], env?: Record<string, string>): Promise<Client> {
  const client = new Client({ name: "bench-agent", version: "0.0.1" });
  await client.connect(
    new StdioClientTransport({ command: process.execPath, args, env: env as Record<string, string> })
  );
  return client;
}

// query_customer_db는 읽기(READ)라 반복 호출해도 항상 통과 — 보안 경로 전체를 거치되 차단되지 않음.
async function measure(client: Client): Promise<number[]> {
  const call = () =>
    client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } });
  for (let i = 0; i < WARMUP; i++) await call();
  const samples: number[] = [];
  for (let i = 0; i < ITER; i++) {
    const t0 = performance.now();
    await call();
    samples.push(performance.now() - t0);
  }
  return samples;
}

function fmt(x: number): string {
  return x.toFixed(3).padStart(8);
}

async function main() {
  console.error(`[bench] 워밍업 ${WARMUP} + 측정 ${ITER}회, 도구=query_customer_db (단위: ms)\n`);

  // (1) 직접 연결 (기준선)
  const direct = await connect([TSX_CLI, MOCK_SERVER]);
  const dt = await measure(direct);
  await direct.close();

  // (2) 프록시 경유
  const proxied = await connect([TSX_CLI, PROXY_PATH], {
    ...process.env,
    TAINTGUARD_TOOL_REGISTRY: REGISTRY,
  });
  const pt = await measure(proxied);
  await proxied.close();

  const d = stats(dt);
  const p = stats(pt);
  console.error("경로          min    median     mean      p95      max");
  console.error(`직접 연결  ${fmt(d.min)} ${fmt(d.median)} ${fmt(d.mean)} ${fmt(d.p95)} ${fmt(d.max)}`);
  console.error(`프록시 경유${fmt(p.min)} ${fmt(p.median)} ${fmt(p.mean)} ${fmt(p.p95)} ${fmt(p.max)}`);
  console.error(
    `\n[bench] 프록시 오버헤드(median): ${(p.median - d.median).toFixed(3)} ms/call ` +
      `(직접 ${d.median.toFixed(3)} → 프록시 ${p.median.toFixed(3)})`
  );
  process.exit(0);
}

main().catch((e) => {
  console.error("[bench] 실패:", e);
  process.exit(1);
});
