/**
 * HITL(Human-In-The-Loop) 오버라이드 — 전부 결정론 코드. AI/휴리스틱 판단 0.
 *
 * 철학: "언제 사람에게 물을지"를 AI가 판단하면 공격자가 그 판단을 조작(환각 유도)해
 * HITL을 우회할 수 있다. 그래서 승인 가능 여부(evaluateOverridability)조차
 * 계보의 weak 플래그(결정론적으로 계산된 연결 신뢰도)만으로 판정한다.
 *
 * 수명주기 (전이 조건 전부 명시적 — "응답 없음 → 통과" 경로가 존재하지 않는다):
 *   차단 + canOverride  →  OFFERED   (엔진이 제안 등록, approvalId 발급,
 *                                     ★승인 시점 계보 지문 저장)
 *   requestApproval     →  PENDING   (사람/대시보드가 승인 대기 등록)
 *   resolveApproval     →  APPROVED | REJECTED
 *   APPROVED + 같은 호출(지문 일치) + 미사용 + ★계보 지문 일치(제안 시점과
 *   계보 상태가 그대로)  →  1회 소비(OVERRIDE_USED) → 통과
 *   그 외 전부(OFFERED/PENDING/REJECTED/SUPERSEDED/지문 불일치/이미 사용/
 *   계보 지문 불일치)  →  차단 유지
 *
 * ★ TOCTOU 방어 (TaintHITL.tla가 반례로 확인한 구멍의 수정): 승인은 "그
 * 호출"뿐 아니라 "그 계보 상태"에도 묶인다. 승인~소비 사이에 recordToolResult
 * 등으로 evidence가 조금이라도 달라지면(노드 교체·추가, weak→strong 재분류,
 * 태그 변화, argTags 변화) 낡은 승인은 영구 무효(OVERRIDE_STALE)가 되고 차단이
 * 유지된다. 여전히 승인 가능한 상태면 재평가에서 새 제안이 자동 발급된다.
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

/** SUPERSEDED: 제안 후 계보가 달라져 새 제안으로 대체됨 — 낡은 그림의 승인 차단 */
type OfferStatus = "OFFERED" | "PENDING" | "APPROVED" | "REJECTED" | "SUPERSEDED";

/**
 * ★ 게이트 판별자 — 승인이 "어느 게이트의 차단"에 대한 것인지.
 * 지문(fingerprintOf)에 포함되어 두 게이트의 offer 공간이 서로소가 된다:
 * 같은 호출(sessionId|toolName|args)에 유출·파괴 offer가 공존해도 서로의
 * 제안을 SUPERSEDED로 봉인하거나 승인을 지문 불일치로 소각(OVERRIDE_STALE)
 * 하는 교차 간섭이 구조적으로 불가능하다
 * (TaintDestructiveHITL.tla GateIsolation — 공유 키 변형은 4스텝 반례).
 */
export type OverrideGate = "exfil" | "destructive";

interface OverrideOffer {
  approvalId: string;
  sessionId: string;
  toolName: string;
  args: Record<string, unknown>;
  /** 이 제안을 발급한 게이트 (지문에도 포함 — 감사·디버깅용 중복 보관) */
  gate: OverrideGate;
  /** 승인은 "그 게이트의 그 호출"에만 유효 — gate|sessionId|toolName|args의 결정론적 지문 */
  fingerprint: string;
  /**
   * ★ 승인은 "그 계보 상태"에만 유효 — 제안 시점 evidence의 결정론적 지문
   * (노드 id·weak·tags 정렬 + argTags + linkMethod). 소비 시점에 현재 계보로
   * 재계산한 지문과 일치해야만 통과 — 승인~소비 사이의 어떤 계보 변화도
   * (weak→strong 승격, 승인 이식용 노드 끼워넣기 포함) 낡은 승인을 무효화한다.
   */
  lineageFingerprint: string;
  status: OfferStatus;
  requestedAt?: string;
  resolvedAt?: string;
  resolvedBy?: string;
  /** single-use: 승인 1회 = 통과 1회 (승인 재사용에 의한 반복 유출 방지) */
  used: boolean;
}

const offers = new Map<string, OverrideOffer>();

function fingerprintOf(
  gate: OverrideGate,
  sessionId: string,
  toolName: string,
  args: Record<string, unknown>
): string {
  // gate가 지문의 첫 성분 — 두 게이트의 offer 공간을 서로소로 만드는 바로 그 지점.
  return createHash("sha256")
    .update(`${gate}|${sessionId}|${toolName}|${JSON.stringify(args)}`)
    .digest("hex")
    .slice(0, 32);
}

/**
 * 계보 지문 — "소비 시점 판정이 쓰는 입력 전부"를 canonical 형태로 해시한다:
 * evidence.nodes 각각의 {nodeId, weak, tags(정렬)} (nodeId로 정렬해 순회 순서
 * 비결정 제거) + linkMethod + argTags(정렬). unionTags는 nodes에서 파생되므로
 * 별도 포함 불필요. 여기 안 들어간 결정 요인이 생기면 지문도 함께 확장할 것 —
 * 지문의 완전성이 곧 TOCTOU 방어의 완전성이다.
 */
function lineageFingerprintOf(evidence: LineageEvidence, argTags: ToolRiskTag[]): string {
  const nodes = evidence.nodes
    .map((n) => ({ nodeId: n.nodeId, weak: n.weak, tags: [...n.tags].sort() }))
    .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
  return createHash("sha256")
    .update(JSON.stringify({ linkMethod: evidence.linkMethod, nodes, argTags: [...argTags].sort() }))
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
  action:
    | "OFFERED"
    | "REQUESTED"
    | "APPROVED"
    | "REJECTED"
    | "OVERRIDE_USED"
    /** 제안 후 계보가 달라져 새 제안으로 대체 (offer 시점 감지) */
    | "SUPERSEDED"
    /** 승인 소비 시도 시 계보 지문 불일치 → 낡은 승인 영구 무효 (소비 시점 감지) */
    | "OVERRIDE_STALE";
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
 * approvalId를 돌려준다. 같은 호출(지문 동일)이고 ★계보 지문도 같은 미해결
 * 제안이 있으면 그 id를 재사용한다 — 재평가 때마다 id가 바뀌면 사람이 승인
 * 중인 id가 무효화되므로. 계보 지문이 달라졌으면 낡은 제안을 SUPERSEDED로
 * 마킹하고 새 제안을 발급한다 — 사람이 이미 낡아버린 위험 그림을 승인하는 것
 * 자체를 차단 (superseded id의 requestApproval/resolveApproval은 상태 검사에서
 * 예외 = fail-closed).
 *
 * ★팀 공지(시그니처 변경 2회차): evidence 인자(제안 시점 계보 지문 저장용)에 이어
 * gate 인자 추가(기본 "exfil" — 기존 호출부 무변경). 호출처는 게이트별 한 곳:
 * 유출은 index.ts computeLineageDecision, 파괴는 index.ts computeDestructiveDecision.
 * 파괴 게이트의 evidence는 값-계보가 아니라 "살아있는 U-보유자 스냅샷"
 * (collectLiveTagHolders)을 LineageEvidence 모양으로 접은 것 — 같은
 * lineageFingerprintOf에 태워 같은 TOCTOU 수명주기를 얻는다.
 */
export function offerOverride(
  ctx: ToolCallContext,
  evidence: LineageEvidence,
  gate: OverrideGate = "exfil"
): string {
  const fingerprint = fingerprintOf(gate, ctx.sessionId, ctx.toolName, ctx.args);
  const lineageFingerprint = lineageFingerprintOf(evidence, ctx.argTags);
  for (const offer of offers.values()) {
    if (offer.fingerprint === fingerprint && (offer.status === "OFFERED" || offer.status === "PENDING")) {
      if (offer.lineageFingerprint === lineageFingerprint) {
        return offer.approvalId; // 진행 중인 제안 재사용 (id 안정성)
      }
      offer.status = "SUPERSEDED"; // 계보가 달라짐 — 낡은 그림은 승인 불가로 봉인
      audit(offer, "SUPERSEDED");
    }
  }
  const offer: OverrideOffer = {
    approvalId: `ap_${randomUUID()}`,
    sessionId: ctx.sessionId,
    toolName: ctx.toolName,
    args: ctx.args,
    gate,
    fingerprint,
    lineageFingerprint,
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
 * 판정 시 엔진이 호출 — "이 호출"과 지문이 일치하는 APPROVED·미사용 승인이
 * 있고, ★제안 시점 계보 지문이 현재 계보와 여전히 일치하면 1회 소비하고 승인
 * 정보를 돌려준다. 그 외 전부 null (= 차단 유지, fail-safe).
 *
 * ★ TOCTOU 재검증 (소비 시점): 계보 지문이 불일치하면 — 승인~소비 사이에
 * evidence가 달라졌으면(weak→strong 승격, 노드 끼워넣기, 태그 변화 전부) —
 * 그 승인을 영구 무효화(used=true, OVERRIDE_STALE)하고 null을 돌려준다.
 * "한 번이라도 다른 상태를 거친" 승인은 상태가 되돌아와도 재사용 불가.
 * 여전히 승인 가능(weak)한 상황이면 이어지는 차단 분기에서 새 제안이 자동
 * 발급되므로 정상 HITL 흐름은 죽지 않는다.
 *
 * fail-safe: 지문 재계산이 예외를 던지면 그대로 전파 —
 * computeLineageDecision의 try/catch가 차단으로 흡수한다 (조용한 통과 없음).
 *
 * ★팀 공지(시그니처 변경 2회차): evidence 인자(소비 시점 계보 지문 재계산용)에 이어
 * gate 인자 추가(기본 "exfil" — 기존 호출부 무변경). 지문에 gate가 포함되므로
 * 이 스캔은 자기 게이트의 offer만 본다 — 상대 게이트의 정당한 승인을 지문
 * 불일치로 소각하는 교차 간섭이 구조적으로 불가능 (GateIsolation).
 * 호출처는 게이트별 판정 한 곳씩. index.ts 밖으로 re-export하지 않는다.
 */
export function consumeApprovalIfMatching(
  ctx: ToolCallContext,
  evidence: LineageEvidence,
  gate: OverrideGate = "exfil"
): { approvalId: string; resolvedBy?: string } | null {
  const fingerprint = fingerprintOf(gate, ctx.sessionId, ctx.toolName, ctx.args);
  const lineageFingerprint = lineageFingerprintOf(evidence, ctx.argTags);
  for (const offer of offers.values()) {
    if (offer.fingerprint === fingerprint && offer.status === "APPROVED" && !offer.used) {
      if (offer.lineageFingerprint !== lineageFingerprint) {
        offer.used = true; // 낡은 승인 영구 무효 — 상태가 되돌아와도 재사용 불가
        audit(offer, "OVERRIDE_STALE", offer.resolvedBy);
        continue; // 통과 아님 — 차단 유지
      }
      offer.used = true; // single-use
      audit(offer, "OVERRIDE_USED", offer.resolvedBy);
      return { approvalId: offer.approvalId, resolvedBy: offer.resolvedBy };
    }
  }
  return null;
}

/**
 * 무변형 조회 — "지금 소비하면 성공할 승인이 있는가"만 답한다. 상태를 절대 바꾸지
 * 않는다(stale 마킹·감사 기록 없음).
 *
 * 용도(승인 소각 방지 프로토콜, index.ts evaluateToolCall lineage 분기): 파괴
 * 게이트가 차단 예정일 때 소비 가능한 파괴 승인이 없으면 유출 판정(승인 소비 포함)을
 * 아예 돌리지 않는다 — 유출 승인이 "통과했는데 파괴에 막혀 실행 없이 소각"되는
 * 것을 막는다. 동기 단일 스레드라 peek↔consume 사이에 상태가 변하지 않으므로
 * peek=true면 이어지는 consume은 반드시 같은 offer를 소비한다.
 */
export function peekApprovalMatches(
  ctx: ToolCallContext,
  evidence: LineageEvidence,
  gate: OverrideGate
): boolean {
  const fingerprint = fingerprintOf(gate, ctx.sessionId, ctx.toolName, ctx.args);
  const lineageFingerprint = lineageFingerprintOf(evidence, ctx.argTags);
  for (const offer of offers.values()) {
    if (
      offer.fingerprint === fingerprint &&
      offer.status === "APPROVED" &&
      !offer.used &&
      offer.lineageFingerprint === lineageFingerprint
    ) {
      return true;
    }
  }
  return false;
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
