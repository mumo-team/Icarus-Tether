/**
 * 섀도 모드 — 계보(real) 기반 판정을 "계산·비교·로그만" 하는 모듈.
 *
 * 실제 차단 결정은 100% toy(sessionStore boolean)가 한다. real이 판정에 절대
 * 영향을 주지 못하는 3중 보장:
 *   1. runShadowEvaluation은 void — 반환값이 없어 판정 경로에 낄 방법이 타입 차원에서 없다.
 *   2. 함수 본문 전체가 try/catch — 어떤 예외도 호출부(evaluateToolCall)로 새지 않는다.
 *   3. 읽기 전용 — previewParentLinks(그래프 미변형)만 쓰므로 sessionStore·계보·
 *      payloadStore 어디에도 흔적을 남기지 않아 미래의 판정에도 영향이 없다.
 *
 * 수집한 일치/불일치 데이터는 toy → real 판정 전환 여부를 결정할 근거가 된다.
 */

import { SinkClass, ToolRiskTag, type ToolCallContext } from "@icarus-tether/types";
import { getTaintNode, previewParentLinks, sessionHasLiveTag, type LinkMethod } from "./lineage.js";
import { containsVaultOriginal } from "./sanitization.js";

// ---------------------------------------------------------------------------
// 로그 구조 (나중에 대시보드 C 파트로 그대로 내보낼 수 있는 형태)
// ---------------------------------------------------------------------------

export interface ShadowEvidence {
  /** real이 부모를 어떻게 찾았나 (MCP_REF / VALUE_MATCH / TEMPORAL_FALLBACK / NONE) */
  linkMethod: LinkMethod;
  /** real이 본 노드들과 그 계보 태그 — 판정 근거 */
  nodes: Array<{ nodeId: string; toolName: string; tags: ToolRiskTag[]; weak: boolean }>;
  /** 부모 노드 태그의 합집합 (트라이펙타 판정 입력) */
  unionTags: ToolRiskTag[];
  sinkClass: SinkClass;
}

export interface ShadowLogEntry {
  sessionId: string;
  toolName: string;
  timestamp: string;
  /** 실제 차단을 결정한 toy(sessionStore) 판정 */
  toyAllowed: boolean;
  /** real(계보) 판정. null = real 계산 실패 (판정 영향 없음, 기록만) */
  realAllowed: boolean | null;
  /** toy === real 여부. null = 비교 불가(계산 실패) */
  match: boolean | null;
  /** 불일치 방향 (일치·실패 시 없음) */
  divergence?: "TOY_ALLOW_REAL_BLOCK" | "TOY_BLOCK_REAL_ALLOW";
  evidence: ShadowEvidence | null;
  /** real 계산이 던진 예외 메시지 (있을 때만) */
  error?: string;
}

// 인메모리 순환 버퍼 — 최근 판정만 유지 (무한 성장 방지)
const MAX_SHADOW_LOG = 1000;
const shadowLog: ShadowLogEntry[] = [];

/** 섀도 로그 조회 (테스트·대시보드용). sessionId를 주면 그 세션 것만. */
export function getShadowLog(sessionId?: string): ReadonlyArray<ShadowLogEntry> {
  if (sessionId === undefined) return shadowLog;
  return shadowLog.filter((e) => e.sessionId === sessionId);
}

// ---------------------------------------------------------------------------
// 계보 근거 수집 — 섀도 로그와 실전 lineage 판정(index.ts)이 공유
// ---------------------------------------------------------------------------

export interface LineageEvidence {
  linkMethod: LinkMethod;
  nodes: Array<{ nodeId: string; toolName: string; tags: ToolRiskTag[]; weak: boolean }>;
  /** 부모 노드 태그의 합집합 (argTags는 포함하지 않음 — 호출부가 필요 시 합친다) */
  unionTags: Set<ToolRiskTag>;
}

/**
 * "이 호출의 인자가 어느 계보 노드에서 왔고, 그 계보에 어떤 태그가 살아있나"를
 * 읽기 전용으로 수집한다. 실패 시 예외를 던진다 — 처리 방향은 호출부 책임:
 * 섀도(로그 전용)는 삼키고 기록만, 실전 lineage 판정은 fail-safe 차단.
 */
export function collectLineageEvidence(ctx: ToolCallContext): LineageEvidence {
  const { linkMethod, parentLinks } = previewParentLinks(ctx.sessionId, ctx.args);
  const nodes = parentLinks.flatMap((link) => {
    const node = getTaintNode(ctx.sessionId, link.nodeId);
    return node
      ? [{ nodeId: node.id, toolName: node.toolName, tags: [...node.tags], weak: link.weak }]
      : [];
  });
  const unionTags = new Set(nodes.flatMap((n) => n.tags));
  return { linkMethod, nodes, unionTags };
}

// ---------------------------------------------------------------------------
// real 판정 계산 + 비교 로그
// ---------------------------------------------------------------------------

/**
 * toy 판정이 끝난 뒤 호출된다. real(계보) 판정을 계산해 비교 로그만 남긴다.
 * 어떤 경우에도 예외를 던지지 않으며(전체 try/catch), 아무 상태도 변형하지 않는다.
 */
export function runShadowEvaluation(
  ctx: ToolCallContext,
  sinkClass: SinkClass,
  toyAllowed: boolean
): void {
  try {
    let entry: ShadowLogEntry;
    try {
      // real 규칙: 인자가 어느 계보 노드에서 왔는지 3층 로직으로 찾고(읽기 전용),
      // 그 부모들의 태그 합집합이 트라이펙타를 이루며 OUTBOUND_SINK로 나가면 차단.
      const { linkMethod, nodes, unionTags } = collectLineageEvidence(ctx);

      // ★ 실제 판정부(computeLineageDecision)와 동일한 비대칭 규칙으로 예측:
      //   민감(S)은 값-계보(또는 정화 전 원본 재전송)로, 비신뢰(U)는 세션-존재로.
      //   (argTags는 여기서 unionTags에 포함되지 않으므로 값-축 U는 unionTags만으로 본다.)
      const valueSensitive =
        unionTags.has(ToolRiskTag.SENSITIVE) || containsVaultOriginal(ctx.args);
      const realBlocked =
        sinkClass === SinkClass.OUTBOUND_SINK &&
        valueSensitive &&
        (unionTags.has(ToolRiskTag.UNTRUSTED_ORIGIN) ||
          sessionHasLiveTag(ctx.sessionId, ToolRiskTag.UNTRUSTED_ORIGIN));
      const realAllowed = !realBlocked;
      const match = realAllowed === toyAllowed;

      entry = {
        sessionId: ctx.sessionId,
        toolName: ctx.toolName,
        timestamp: new Date().toISOString(),
        toyAllowed,
        realAllowed,
        match,
        divergence: match
          ? undefined
          : toyAllowed
            ? "TOY_ALLOW_REAL_BLOCK" // toy가 놓친 잠재 유출 — real 전환의 핵심 근거
            : "TOY_BLOCK_REAL_ALLOW", // toy의 과차단 — real의 정밀함이 세션을 살리는 케이스
        evidence: { linkMethod, nodes, unionTags: [...unionTags], sinkClass },
      };
    } catch (err) {
      // real 계산 실패 — 조용히 기록만. 실제 판정(toy)에는 영향 0.
      entry = {
        sessionId: ctx.sessionId,
        toolName: ctx.toolName,
        timestamp: new Date().toISOString(),
        toyAllowed,
        realAllowed: null,
        match: null,
        evidence: null,
        error: err instanceof Error ? err.message : String(err),
      };
    }

    shadowLog.push(entry);
    if (shadowLog.length > MAX_SHADOW_LOG) shadowLog.shift();
    console.log("[SHADOW]", entry);
  } catch {
    // 최후 방어: 섀도는 어떤 경우에도 판정 흐름을 깨뜨리지 않는다
  }
}
