/**
 * ② 프록시 — A 담당
 *
 * 역할: AI 에이전트와 실제 MCP 서버 사이에 끼어, 모든 tool call을 가로챈다.
 * 에이전트한테는 "내가 서버다"라고, 실제 서버한테는 "내가 클라이언트다"라고
 * 행동하는 투명 프록시 패턴이다 (자세한 설명은 docs/architecture.md 참고).
 *
 * TODO(A): @modelcontextprotocol/sdk로 실제 initialize 핸드셰이크 구현
 * TODO(A): tools/call 수신 시 policy-engine(B)에 검사 요청하는 부분 연동
 */

import type { ToolCallContext, PolicyDecision, ToolRiskTag } from "@taintguard/types";

/**
 * 임시 스텁: 실제로는 policy-engine 워크스페이스를 HTTP/IPC로 호출해야 한다.
 * B가 policy-engine을 완성하기 전까지, A는 이 함수만 교체하면
 * 나머지 프록시 로직을 독립적으로 개발/테스트할 수 있다.
 */
async function requestPolicyCheck(ctx: ToolCallContext): Promise<PolicyDecision> {
  // 1주차 스텁: 항상 통과시킴. B의 실제 판정 로직으로 교체 예정.
  return {
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    allowed: true,
    matchedTags: [] as ToolRiskTag[],
  };
}

async function handleToolCall(ctx: ToolCallContext) {
  const decision = await requestPolicyCheck(ctx);

  if (!decision.allowed) {
    console.log(`[proxy] 차단됨: ${ctx.toolName} (session=${ctx.sessionId})`, decision.reason);
    return { blocked: true, reason: decision.reason };
  }

  console.log(`[proxy] 통과: ${ctx.toolName} (session=${ctx.sessionId}) -> 다운스트림 서버로 전달`);
  // TODO(A): 실제 다운스트림 MCP 서버로 전달하고 결과 수신
  return { blocked: false };
}

async function main() {
  console.log("TaintGuard proxy 기동 (1주차 스텁 버전)");

  // 데모용 임시 호출 예시 — 실제 MCP 연결 붙기 전까지 로직 확인용
  const sample: ToolCallContext = {
    sessionId: "demo-session-1",
    toolName: "query_customer_db",
    args: { customerId: "12345" },
    argTags: [],
    timestamp: new Date().toISOString(),
  };
  await handleToolCall(sample);
}

main().catch((err) => {
  console.error("proxy 기동 실패:", err);
  process.exit(1);
});
