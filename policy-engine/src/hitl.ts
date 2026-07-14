/**
 * HITL(Human-In-The-Loop) 오버라이드 — 전부 결정론 코드. AI/휴리스틱 판단 0.
 *
 * 철학: "언제 사람에게 물을지"를 AI가 판단하면 공격자가 그 판단을 조작(환각 유도)해
 * HITL을 우회할 수 있다. 그래서 승인 가능 여부(evaluateOverridability)조차
 * 계보의 weak 플래그(결정론적으로 계산된 연결 신뢰도)만으로 판정한다.
 *
 * 수명주기 (전이 조건 전부 명시적 — "응답 없음 → 통과" 경로가 존재하지 않는다):
 *   차단 + canOverride  →  OFFERED   (엔진이 제안 등록, approvalId 발급)
 *   requestApproval     →  PENDING   (사람/대시보드가 승인 대기 등록)
 *   resolveApproval     →  APPROVED | REJECTED
 *   APPROVED + 같은 호출(지문 일치) + 미사용  →  1회 소비(OVERRIDE_USED) → 통과
 *   그 외 전부(OFFERED/PENDING/REJECTED/지문 불일치/이미 사용)  →  차단 유지
 *
 * fail-safe: 여기서 던진 예외는 computeLineageDecision의 try/catch가 흡수해
 * 차단으로 귀결된다. 잘못된 id·세션 불일치는 예외(fail-closed).
 */

import { createHash, randomUUID } from "node:crypto";
import {
  ToolRiskTag,
  type ApprovalRequest,
  type ToolCallContext,
} from "@icarus-tether/types";
import type { LineageEvidence } from "./shadow.js";

// ---------------------------------------------------------------------------
// 승인 가능 여부 — 결정론 규칙 (이 함수가 HITL의 문지기)
// ---------------------------------------------------------------------------

/**
 * canOverride ⇔ 트라이펙타를 이룬 오염이 "전부 약한(weak) 연결"로만 유입됐다.
 *
 * - weak는 lineage.ts가 연결 시점에 결정론적으로 계산한 신뢰도다:
 *   MCP_REF(명시 참조)=항상 strong, TEMPORAL_FALLBACK(시간 근사)=항상 weak,
 *   VALUE_MATCH=근거 토큰 강도로 결정.
 * - strong 연결이 오염(S/U)을 하나라도 실었으면 → 확실히 엮인 트라이펙타 →
 *   사람도 못 여는 확정 차단.
 * - argTags는 프록시가 확정 전파한 증거이므로 오염이 실려 있으면 무조건 불가.
 */
export function evaluateOverridability(
  evidence: LineageEvidence,
  argTags: ToolRiskTag[]
): boolean {
  if (argTags.includes(ToolRiskTag.SENSITIVE) || argTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN)) {
    return false;
  }
  // 모든 근거 노드가 "weak 연결이거나, 오염을 안 실었거나" 여야 승인 후보
  return evidence.nodes.every((n) => n.weak || n.tags.length === 0);
}

// ---------------------------------------------------------------------------
// 승인 저장소 (인메모리 — 기존 sessionStore 패턴)
// ---------------------------------------------------------------------------

type OfferStatus = "OFFERED" | "PENDING" | "APPROVED" | "REJECTED";

interface OverrideOffer {
  approvalId: string;
  sessionId: string;
  toolName: string;
  args: Record<string, unknown>;
  /** 승인은 "그 호출"에만 유효 — sessionId|toolName|args의 결정론적 지문 */
  fingerprint: string;
  status: OfferStatus;
  requestedAt?: string;
  resolvedAt?: string;
  resolvedBy?: string;
  /** single-use: 승인 1회 = 통과 1회 (승인 재사용에 의한 반복 유출 방지) */
  used: boolean;
}

const offers = new Map<string, OverrideOffer>();

function fingerprintOf(sessionId: string, toolName: string, args: Record<string, unknown>): string {
  return createHash("sha256")
    .update(`${sessionId}|${toolName}|${JSON.stringify(args)}`)
    .digest("hex")
    .slice(0, 32);
}

// ---------------------------------------------------------------------------
// 감사 로그 — "누가 언제 뭘 승인했나" (대시보드 C 파트 연동 대비, 섀도 로그 패턴)
// ---------------------------------------------------------------------------

export interface OverrideAuditEntry {
  approvalId: string;
  sessionId: string;
  toolName: string;
  action: "OFFERED" | "REQUESTED" | "APPROVED" | "REJECTED" | "OVERRIDE_USED";
  /** 승인/거부한 사람 (resolveApproval의 resolvedBy) */
  actor?: string;
  timestamp: string;
}

const auditLog: OverrideAuditEntry[] = [];

function audit(offer: OverrideOffer, action: OverrideAuditEntry["action"], actor?: string): void {
  auditLog.push({
    approvalId: offer.approvalId,
    sessionId: offer.sessionId,
    toolName: offer.toolName,
    action,
    actor,
    timestamp: new Date().toISOString(),
  });
}

export function getOverrideAuditLog(sessionId?: string): ReadonlyArray<OverrideAuditEntry> {
  if (sessionId === undefined) return auditLog;
  return auditLog.filter((e) => e.sessionId === sessionId);
}

// ---------------------------------------------------------------------------
// 수명주기 API
// ---------------------------------------------------------------------------

/**
 * 차단 시점에 엔진(computeLineageDecision)이 호출 — 오버라이드 제안을 등록하고
 * approvalId를 돌려준다. 같은 호출(지문 동일)의 미해결 제안이 있으면 그 id를
 * 재사용한다 — 재평가 때마다 id가 바뀌면 사람이 승인 중인 id가 무효화되므로.
 */
export function offerOverride(ctx: ToolCallContext): string {
  const fingerprint = fingerprintOf(ctx.sessionId, ctx.toolName, ctx.args);
  for (const offer of offers.values()) {
    if (offer.fingerprint === fingerprint && (offer.status === "OFFERED" || offer.status === "PENDING")) {
      return offer.approvalId; // 진행 중인 제안 재사용 (id 안정성)
    }
  }
  const offer: OverrideOffer = {
    approvalId: `ap_${randomUUID()}`,
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    args: ctx.args,
    fingerprint,
    status: "OFFERED",
    used: false,
  };
  offers.set(offer.approvalId, offer);
  audit(offer, "OFFERED");
  return offer.approvalId;
}

/** 승인 대기 등록: OFFERED → PENDING. 없는 id·세션 불일치는 예외 (fail-closed). */
export function requestApproval(sessionId: string, approvalId: string): ApprovalRequest {
  const offer = offers.get(approvalId);
  if (!offer || offer.sessionId !== sessionId) {
    throw new Error(`[hitl] 세션 "${sessionId}"에 승인 가능한 제안 "${approvalId}"이 없습니다`);
  }
  if (offer.status === "OFFERED") {
    offer.status = "PENDING";
    offer.requestedAt = new Date().toISOString();
    audit(offer, "REQUESTED");
  } else if (offer.status !== "PENDING") {
    throw new Error(`[hitl] 제안 "${approvalId}"은 이미 ${offer.status} 상태입니다`);
  }
  return toApprovalRequest(offer);
}

/** 승인/거부 확정: PENDING → APPROVED | REJECTED. 등록(request) 없이 해결은 예외. */
export function resolveApproval(
  approvalId: string,
  approved: boolean,
  resolvedBy?: string
): ApprovalRequest {
  const offer = offers.get(approvalId);
  if (!offer || offer.status !== "PENDING") {
    throw new Error(
      `[hitl] "${approvalId}"은 PENDING 상태의 승인 요청이 아닙니다 (현재: ${offer?.status ?? "없음"})`
    );
  }
  offer.status = approved ? "APPROVED" : "REJECTED";
  offer.resolvedAt = new Date().toISOString();
  offer.resolvedBy = resolvedBy;
  audit(offer, approved ? "APPROVED" : "REJECTED", resolvedBy);
  return toApprovalRequest(offer);
}

/**
 * 판정 시 엔진이 호출 — "이 호출"과 지문이 일치하는 APPROVED·미사용 승인이 있으면
 * 1회 소비하고 승인 정보를 돌려준다. 그 외 전부 null (= 차단 유지, fail-safe).
 * index.ts 밖으로 re-export하지 않는다 — 소비 경로는 판정 하나뿐.
 */
export function consumeApprovalIfMatching(
  ctx: ToolCallContext
): { approvalId: string; resolvedBy?: string } | null {
  const fingerprint = fingerprintOf(ctx.sessionId, ctx.toolName, ctx.args);
  for (const offer of offers.values()) {
    if (offer.fingerprint === fingerprint && offer.status === "APPROVED" && !offer.used) {
      offer.used = true; // single-use
      audit(offer, "OVERRIDE_USED", offer.resolvedBy);
      return { approvalId: offer.approvalId, resolvedBy: offer.resolvedBy };
    }
  }
  return null;
}

function toApprovalRequest(offer: OverrideOffer): ApprovalRequest {
  return {
    id: offer.approvalId,
    sessionId: offer.sessionId,
    toolName: offer.toolName,
    args: offer.args,
    status: offer.status === "OFFERED" ? "PENDING" : (offer.status as ApprovalRequest["status"]),
    requestedAt: offer.requestedAt ?? new Date().toISOString(),
    resolvedAt: offer.resolvedAt,
    resolvedBy: offer.resolvedBy,
  };
}
