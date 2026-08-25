/**
 * 대시보드 브리지 — C 담당.
 *
 * 왜 proxy 프로세스 안에 사는가: HITL 승인 상태(policy-engine의 hitl.ts)는
 * 프로세스 내 메모리(offers Map)에 있다. 별도 프로세스인 브라우저가
 * resolveApproval을 직접 부르면 자기 복사본만 바뀌고 엔진은 모른다.
 * 그래서 브라우저의 승인 클릭을 웹소켓으로 받아, 엔진과 같은 프로세스인
 * 여기서 대신 호출한다.
 *
 * index.ts(A 담당)가 쓰는 것은 startDashboardBridge / stopDashboardBridge /
 * broadcastDecision 셋뿐 — proxy 본체에 남기는 흔적을 최소화하기 위함이다.
 */

import { WebSocketServer, type WebSocket } from "ws";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { requestApproval, resolveApproval, attemptSanitization, getSessionLineage, getOverrideAuditLog } from "@icarus-tether/policy-engine";
import { SanitizationMethod, type PolicyDecision, type AuditLogEntry, type ToolRiskTag } from "@icarus-tether/types";

const WS_PORT = 7331;
const WS_HOST = "127.0.0.1";
const ALLOWED_ORIGINS = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173",
]);


// ── 감사 로그: 해시 체인 (C 담당, 책임 3) ─────────────────────────────
// 각 줄에 직전 줄의 signature(prevHash)를 심어 사슬로 엮는다. 나중에 줄을
// 지우거나 순서를 바꾸면 체인이 끊겨 verify-audit-log가 잡아낸다.
// (키 없는 SHA-256이라 "사후 편집·삭제 탐지"까지가 목표 — HMAC 서명은 향후 과제.)
const __dirname = dirname(fileURLToPath(import.meta.url));
const AUDIT_LOG_PATH = resolve(__dirname, "../audit.log");


// ── 제어 채널 인증 ────────────────────────────────────────────────
// Origin 헤더는 non-브라우저 클라이언트가 마음대로 붙일 수 있어 인증이 못 된다.
// 관측(broadcast) 수신은 그대로 열어두되, 상태를 바꾸는 명령만 토큰을 요구한다.
// 이렇게 나눠야 데모 흐름을 안 깨면서, 인젝션당한 에이전트가 자기 승인을 눌러
// HITL을 통과하는 경로를 막을 수 있다.
// 프로젝트 폴더 밖에 둔다 — 파일 읽기 도구는 대개 프로젝트를 루트로 잡으므로,
// 밖에 있으면 인젝션당한 에이전트가 토큰을 읽어 자기 승인하는 경로가 막힌다.
// (경로 제한 없는 도구에는 여전히 뚫린다 — 차단이 아니라 문턱 높이기다.)
const CONTROL_TOKEN_PATH = resolve(tmpdir(), "icarus-tether-control.token");
const CONTROL_TYPES = new Set(["approve", "reject", "sanitize"]);
let controlToken = "";

/** 길이가 다르면 즉시 false. 같으면 타이밍 차이가 안 나게 비교한다. */
function tokenMatches(given: unknown): boolean {
  if (typeof given !== "string" || controlToken === "") return false;
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(controlToken, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// 이 프로세스가 마지막으로 쓴 줄의 signature. 다음 줄의 prevHash가 된다.
// 프로세스 시작 시 기존 audit.log 마지막 줄에서 seed한다(seedLastSignatureFromLog) —
// "데모 1회 = 1프로세스"라 리셋하면 세션 경계마다 제네시스 줄이 생겨 검증기가
// CHAIN_BREAK 오탐을 낸다. 이어받으면 파일 전체가 연속 체인이 되어 오탐이 사라지고,
// 세션 경계까지 서명으로 묶여 재정렬 탐지가 오히려 강해진다. 로그가 없으면 undefined
// (진짜 제네시스).
let lastSignature: string | undefined;

// signature 계산 시 signature/prevHash 자신은 빼고, prevHash는 항상 포함한다 —
// 그래야 "앞 줄이 무엇이었나"까지 서명에 묶여 재정렬·삭제가 탐지된다.
function signAuditEntry(entry: Omit<AuditLogEntry, "signature">): string {
  return createHash("sha256").update(JSON.stringify(entry)).digest("hex");
}

/**
 * 판정 하나를 해시 체인으로 엮어 audit.log에 JSON 한 줄로 append.
 * index.ts에서 writeAuditLog를 대신해 이 함수를 부른다.
 */
export function recordAudit(input: {
  sessionId: string;
  toolName: string;
  decision: "ALLOWED" | "BLOCKED" | "FORWARDED";
  matchedTags: ToolRiskTag[];
}): void {
  const unsigned: Omit<AuditLogEntry, "signature"> = {
    id: randomUUID(),
    sessionId: input.sessionId,
    toolName: input.toolName,
    decision: input.decision,
    matchedTags: input.matchedTags,
    timestamp: new Date().toISOString(),
    prevHash: lastSignature, // 첫 줄이면 undefined → JSON에서 생략됨(제네시스)
  };
  const signature = signAuditEntry(unsigned);
  const signed: AuditLogEntry = { ...unsigned, signature };
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(signed) + "\n");
  lastSignature = signature; // 다음 줄이 이 값을 prevHash로 물고 이어간다
  broadcastAuditIntegrity();
}

/**
 * 프로세스 시작 시 기존 audit.log의 마지막 줄 signature를 lastSignature에 seed한다.
 * 이렇게 하면 새 세션의 첫 줄이 이전 세션 마지막 줄을 prevHash로 물어 파일 전체가
 * 하나의 연속 체인이 된다 — 세션 경계 CHAIN_BREAK 오탐이 사라지고(검증기 무수정),
 * 세션 경계 재정렬까지 탐지된다. 파일이 없거나(첫 실행) 파싱 실패면 undefined 유지
 * = 진짜 제네시스로 시작.
 *
 * 주의: "데모 1회 = 1프로세스" 순차 실행 전제. 여러 proxy가 같은 파일에 동시 append
 * 하면 seed 레이스가 생길 수 있으나, 현재 실행 모델(stdio 단일 클라이언트)에선 없다.
 */
function seedLastSignatureFromLog(): void {
  try {
    const raw = readFileSync(AUDIT_LOG_PATH, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    if (lines.length === 0) return;
    const last = JSON.parse(lines[lines.length - 1]) as AuditLogEntry;
    lastSignature = last.signature; // 새 세션 첫 줄이 이 값을 prevHash로 물고 이어간다
  } catch {
    // 파일 없음/파싱 실패 → lastSignature undefined 유지 (진짜 제네시스로 시작)
  }
}
seedLastSignatureFromLog();

// ── 감사 로그 무결성 검증 (책임 3의 "검사" 쪽) ────────────────────────
// 이 검증 로직은 dashboard/server/src/verify-audit-log.ts(CLI)와 같은 규칙이다.
// 워크스페이스가 달라 공유 import가 지저분해 의도적으로 중복했다 — 한쪽 규칙을
// 바꾸면 반드시 다른 쪽도 함께 고칠 것. (signAuditEntry와 동일한 해시 규칙)
export interface AuditIntegrityResult {
  ok: boolean;
  total: number;
  problems: { line: number; kind: string; detail: string }[];
}

export function verifyAuditChain(): AuditIntegrityResult {
  let raw: string;
  try {
    raw = readFileSync(AUDIT_LOG_PATH, "utf8");
  } catch {
    return { ok: true, total: 0, problems: [] }; // 로그가 아직 없으면 위반 아님
  }

  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const problems: AuditIntegrityResult["problems"] = [];
  let expectedPrevHash: string | undefined;

  lines.forEach((line, i) => {
    const lineNo = i + 1;
    let entry: AuditLogEntry;
    try {
      entry = JSON.parse(line);
    } catch {
      problems.push({ line: lineNo, kind: "PARSE_ERROR", detail: "JSON 파싱 실패" });
      expectedPrevHash = undefined;
      return;
    }
    const { signature, ...unsigned } = entry;
    if (signAuditEntry(unsigned) !== signature) {
      problems.push({ line: lineNo, kind: "SIGNATURE_MISMATCH", detail: "줄 내용 변조 의심" });
    }
    if (entry.prevHash !== expectedPrevHash) {
      problems.push({ line: lineNo, kind: "CHAIN_BREAK", detail: "줄 삭제·재정렬 의심" });
    }
    expectedPrevHash = signature; // 저장된 값 기준 (재계산값 쓰면 이후 전줄 연쇄 오탐)
  });

  return { ok: problems.length === 0, total: lines.length, problems };
}

/** 로그 전체를 검증해 무결성 결과를 대시보드에 방송한다. (세션 종료 직전 호출) */
export function broadcastAuditIntegrity(): void {
  const result = verifyAuditChain();
  broadcastToDashboard({
    type: "audit_integrity",
    ok: result.ok,
    total: result.total,
    problems: result.problems,
    timestamp: new Date().toISOString(),
  });
  console.error(
    result.ok
      ? `[bridge] 감사로그 무결성 [정상] (${result.total}줄)`
      : `[bridge] 감사로그 무결성 [위반] ${result.problems.length}건`
  );
}

let wss: WebSocketServer | null = null;
const clients = new Set<WebSocket>();

const ALLOWED_FIELDS: Record<string, readonly string[]> = {
  decision: ["type", "sessionId", "toolName", "allowed", "decision", "reason", "matchedTags", "explanation", "canOverride", "approvalId", "outputScan", "blockedArgs", "timestamp"],
  lineage: ["type", "sessionId", "nodes", "timestamp"],
  hitl_audit: ["type", "sessionId", "entries", "timestamp"],
  audit_integrity: ["type", "ok", "total", "problems", "timestamp"],
  approval_resolved: ["type", "sessionId", "approvalId", "approved", "resolvedBy", "timestamp"],
  sanitized: ["type", "sessionId", "method", "originalTags", "resultTags", "ok", "maskedCount", "residualSensitiveData", "timestamp"],
  injection_check: ["type", "sessionId", "toolName", "isInjection", "score", "evaluated", "timestamp"],
};

// 중첩 객체/배열의 필드별 허용 키 — 필드명으로 스키마를 찾아 재귀 적용한다.
const NESTED_ALLOWED: Record<string, readonly string[]> = {
  explanation: ["summary", "reason", "risks", "actions"],
  actions: ["kind", "label", "description", "available", "detail"],
  outputScan: ["id", "sessionId", "toolName", "sinkClass", "timestamp", "kind", "sourceTool", "matchLen", "valueHash"],
  nodes: ["id", "toolName", "tags", "parents"],
  parents: ["nodeId", "method", "weak"],
  entries: ["approvalId", "sessionId", "toolName", "action", "actor", "timestamp"],
  problems: ["line", "kind", "detail"],
};

// key에 해당하는 중첩 스키마가 있으면 value(객체/배열)를 재귀로 걸러 반환한다.
// 스키마가 없으면(원시값·문자열 태그 배열 등) 그대로 통과. dropped엔 "key.subkey" 경로를 쌓는다.
function filterNested(key: string, value: unknown, dropped: string[]): unknown {
  const schema = NESTED_ALLOWED[key];
  if (!schema) return value;
  const one = (obj: Record<string, unknown>): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(obj)) {
      if (!schema.includes(k)) { dropped.push(`${key}.${k}`); continue; }
      out[k] = filterNested(k, obj[k], dropped);
    }
    return out;
  };
  if (Array.isArray(value)) {
    return value.map((el) => (el && typeof el === "object" ? one(el as Record<string, unknown>) : el));
  }
  if (value && typeof value === "object") return one(value as Record<string, unknown>);
  return value;
} 

/**
 * 대시보드로 이벤트 한 건 방송 — 전송 경계 화이트리스트.
 * 이벤트 타입별 허용 필드만 통과시키고, 그 외 키는 drop + 경고.
 * 미등록 타입은 통째로 차단(fail-closed) — "깜빡하면 새어나간다"보다
 * "깜빡하면 안 나간다"가 낫다는 의도된 비용.
 */
export function broadcastToDashboard(event: Record<string, unknown>): void {
  const type = typeof event.type === "string" ? event.type : undefined;
  const allowed = type ? ALLOWED_FIELDS[type] : undefined;
  if (!allowed) {
    console.error(`[bridge] [경고] 미등록 이벤트 타입 방송 차단: ${String(event.type)}`);
    return;
  }
  const safe: Record<string, unknown> = {};
  const dropped: string[] = [];
  for (const key of Object.keys(event)) {
    if (!allowed.includes(key)) { dropped.push(key); continue; }
    safe[key] = filterNested(key, event[key], dropped);
  }
  if (dropped.length > 0) {
    console.error(`[bridge] [경고] 화이트리스트 밖 필드 drop (${type}): ${dropped.join(", ")}`);
  }
  const payload = JSON.stringify(safe);
  for (const client of clients) {
    if (client.readyState === client.OPEN) client.send(payload);
  }
}

/**
 * 판정 하나를 대시보드 모양으로 방송.
 * explanation·canOverride·approvalId까지 실어야 승인 모달이 뜰 수 있다.
 * canOverride는 hitlPolicy가 off면 엔진이 아예 안 채우므로 여기서 false로 고정한다 —
 * 대시보드가 "필드 없음"과 "false"를 구분하지 않아도 되게.
 */
// 차단된 호출이 '무엇을 내보내려 했는지'를 대시보드가 실제 값으로 보여주기 위한 것.
// 통과한 호출은 싣지 않는다 — 운영자가 확인해야 하는 건 막힌 쪽이고, 그만큼 노출면이 좁아진다.
// 길이 상한을 두는 이유: 도구 인자에 문서 전문이 통째로 들어올 수 있어, 그대로 실으면
// 프레임이 비대해지고 화면에서도 못 읽는다.
const MAX_BLOCKED_ARGS_CHARS = 1200;

function summarizeBlockedArgs(args: unknown): string | undefined {
  if (args === undefined || args === null) return undefined;
  let text: string;
  try {
    text = JSON.stringify(args);
  } catch {
    return undefined; // 순환참조 등 — 조용히 생략한다(방송 자체를 막지는 않는다)
  }
  if (!text || text === "{}") return undefined;
  return text.length > MAX_BLOCKED_ARGS_CHARS
    ? `${text.slice(0, MAX_BLOCKED_ARGS_CHARS)}…(생략)`
    : text;
}

export function broadcastDecision(
  sessionId: string,
  toolName: string,
  decision: PolicyDecision,
  timestamp: string,
  args?: unknown
): void {
  broadcastToDashboard({
    type: "decision",
    sessionId,
    toolName,
    allowed: decision.allowed,
    reason: decision.reason,
    matchedTags: decision.matchedTags,
    explanation: decision.explanation,
    canOverride: decision.canOverride ?? false,
    approvalId: decision.approvalId,
    outputScan: decision.outputScan,
    // 차단된 경우에만 실제 인자를 싣는다 — 통과 건의 인자는 대시보드로 나가지 않는다.
    blockedArgs: decision.allowed ? undefined : summarizeBlockedArgs(args),
    timestamp,
  });
  // 이 판정 과정에서 생긴 HITL 전이(OFFERED 등)를 함께 방송 — index.ts 무수정.
  broadcastHitlAudit(sessionId);
}

export function broadcastForwarded(
  sessionId: string,
  toolName: string,
  timestamp: string
): void {
  // 무검사 중계는 판정 객체가 없다 — decision 필드를 명시적으로 실어
  // App.tsx가 불리언이 아니라 FORWARDED 3-상태로 기록하게 한다.
  broadcastToDashboard({
    type: "decision",
    sessionId,
    toolName,
    decision: "FORWARDED",
    matchedTags: [],
    timestamp,
  });
}

/**
 * 현재 세션의 오염 계보 전체를 대시보드에 방송한다 — TaintGraph 실데이터 소스.
 * TaintNode의 Set/Map은 JSON 직렬화가 안 되므로 그래프에 필요한 것만 배열로 편다:
 * 노드 id·도구·유효태그, 그리고 부모 연결(어느 노드에서·어떤 방법으로·신뢰도).
 * 판정 직후 호출하면 노드가 하나씩 자라는 게 화면에 실시간으로 보인다.
 */
export function broadcastLineage(sessionId: string): void {
  const lineage = getSessionLineage(sessionId);
  const nodes = [...lineage.values()].map((n) => ({
    id: n.id,
    toolName: n.toolName,
    tags: [...n.tags],
    parents: n.parentLinks.map((p) => ({
      nodeId: p.nodeId,
      method: p.method,
      weak: p.weak,
    })),
  }));
  broadcastToDashboard({
    type: "lineage",
    sessionId,
    nodes,
    timestamp: new Date().toISOString(),
  });
  console.error(`[bridge] 계보 방송  노드 ${nodes.length}개`);
}


/**
 * 세션의 HITL 오버라이드 감사로그 전체를 대시보드에 방송한다 — AuditTimeline의
 * hitlLog 소스. 엔진 hitl.ts의 getOverrideAuditLog가 프로세스 내 누적 로그를 주므로,
 * 매번 세션 전체를 보내고 대시보드는 교체(append 아님)한다. broadcastDecision(매 판정)
 * 과 approve/reject 처리 직후에 호출해 OFFERED~OVERRIDE_USED 전이가 실시간 반영된다.
 */
export function broadcastHitlAudit(sessionId: string): void {
  const entries = getOverrideAuditLog(sessionId);
  broadcastToDashboard({
    type: "hitl_audit",
    sessionId,
    entries,
    timestamp: new Date().toISOString(),
  });
}

function handleDashboardMessage(text: string, socket: WebSocket): void {
  const msg = JSON.parse(text) as {
    type?: string;
    sessionId?: string;
    approvalId?: string;
    resolvedBy?: string;
    method?: string;
    token?: string;
  };

  // 상태를 바꾸는 명령만 막는다. 관측용 수신은 이 함수를 타지 않으므로
  // 연결·실시간 표시는 토큰 없이도 그대로다.
  if (msg.type && CONTROL_TYPES.has(msg.type) && !tokenMatches(msg.token)) {
    console.error(`[bridge] [경고] 제어 명령 거부 — 토큰 불일치 (type=${msg.type})`);
    socket.send(
      JSON.stringify({
        type: "control_rejected",
        reason: "제어 토큰이 필요합니다. proxy 콘솔의 토큰을 대시보드에 입력하세요.",
        timestamp: new Date().toISOString(),
      })
    );
    return;
  }

  // (1) 승인/거부 — HITL 오버라이드
  if (msg.type === "approve" || msg.type === "reject") {
    if (!msg.sessionId || !msg.approvalId) return;
    const approved = msg.type === "approve";
    requestApproval(msg.sessionId, msg.approvalId); // OFFERED → PENDING
    resolveApproval(msg.approvalId, approved, msg.resolvedBy ?? "dashboard");
    console.error(`[bridge] 대시보드 ${approved ? "승인" : "거부"}  approvalId=${msg.approvalId}`);
    broadcastToDashboard({
      type: "approval_resolved",
      sessionId: msg.sessionId,
      approvalId: msg.approvalId,
      approved,
      resolvedBy: msg.resolvedBy ?? "dashboard",
      timestamp: new Date().toISOString(),
    });
    broadcastHitlAudit(msg.sessionId); // REQUESTED/APPROVED/REJECTED 전이 반영
    return;
  }

  // (2) 정화 — 세션 오염 태그를 검증된 방법으로 해제한다.
  // 승인(1회 통과)과 달리 태그 자체가 사라지므로, 재시도하면 트라이펙타가 미성립해 통과된다.
  if (msg.type === "sanitize") {
    if (!msg.sessionId || !msg.method) return;
    if (msg.method !== SanitizationMethod.TOKENIZATION && msg.method !== SanitizationMethod.STRUCTURED_EXTRACTION) {
      console.error(`[bridge] 알 수 없는 정화 방법: ${msg.method}`);
      return;
    }
    const result = attemptSanitization(msg.sessionId, msg.method);
    const ok = result.originalTags.length > result.resultTags.length; // 태그가 줄었으면 정화 성공
    console.error(
      `[bridge] 대시보드 정화(${msg.method})  ${result.originalTags.join(",")} → ${result.resultTags.join(",") || "(없음)"}`
    );
    broadcastToDashboard({
      type: "sanitized",
      sessionId: msg.sessionId,
      method: msg.method,
      originalTags: result.originalTags,
      resultTags: result.resultTags,
      ok,
      // 부분 정화 UX용 보고 필드(엔진이 반환) — 대시보드에 전달
      maskedCount: result.maskedCount,
      residualSensitiveData: result.residualSensitiveData,
      timestamp: new Date().toISOString(),
    });
    return;
  }
}

/**
 * 웹소켓 서버 기동. 루프백에만 리슨하고 브라우저 Origin을 화이트리스트로 제한한다.
 * 포트가 물려 있으면 원인을 알리되 프로세스는 죽이지 않는다 — 대시보드 없이도
 * 판정·차단·감사로그는 계속 동작해야 한다.
 */
export function startDashboardBridge(): void {
  if (wss) return;
  
  // 프로세스마다 새 토큰. 사람은 콘솔에서 보고 대시보드에 붙여넣고,
  // 같은 머신의 Node 클라이언트(demo:hitl)는 파일에서 읽는다.
  controlToken = randomUUID();
  try {
    writeFileSync(CONTROL_TOKEN_PATH, controlToken, { encoding: "utf8", mode: 0o600 });
  } catch (err) {
    console.error("[bridge] 제어 토큰 파일 기록 실패 — 콘솔 값으로 진행하세요:", err);
  }
  console.error(
    `\n[bridge] ── 제어 토큰 ─────────────────────────────────\n` +
      `[bridge]   ${controlToken}\n` +
      `[bridge]   대시보드 상단 '제어 토큰' 칸에 넣어야 승인·정화가 동작합니다.\n` +
      `[bridge] ──────────────────────────────────────────────\n`
  );
  const server = new WebSocketServer({
    port: WS_PORT,
    host: WS_HOST,
    // @types/ws의 verifyClient는 sync|async 유니온이라 문맥 추론이 안 된다(TS7031) →
    // 파라미터를 명시한다. 선언은 origin: string이지만 Origin 헤더가 없는 클라이언트에선
    // 런타임에 undefined가 들어오므로 !origin으로 함께 받는다.
    verifyClient: ({ origin }: { origin: string }) => {
      if (!origin) return true;            // Node 클라이언트(demo:hitl)는 Origin 없음
      if (ALLOWED_ORIGINS.has(origin)) return true;
      console.error(`[bridge] [경고] 허용되지 않은 Origin 연결 거부: ${origin}`);
      return false;
    },
  });
  wss = server;

  // 핸들러가 없으면 EADDRINUSE가 unhandled error로 터져 스택만 잔뜩 나온다.
  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `[bridge] 포트 ${WS_PORT}이 이미 사용 중 — 이전 proxy가 안 죽었을 수 있습니다.\n` +
          `        확인: Get-NetTCPConnection -LocalPort ${WS_PORT}`
      );
    } else {
      console.error("[bridge] 웹소켓 서버 오류:", err);
    }
    // 대시보드는 관측 계층이다. 여기서 프로세스를 죽이면 집행 계층(판정·차단·감사로그)까지
    // 같이 죽어, 사용자가 프록시를 설정에서 빼고 실제 서버에 직접 붙는 진짜 우회를 유발한다.
    // clients가 빈 채로 남으므로 broadcastToDashboard는 무해한 no-op이 된다.
    wss = null;
  });

  server.on("connection", (socket) => {
    clients.add(socket);
    console.error(`[bridge] 대시보드 연결됨 (현재 ${clients.size}개)`);
    socket.on("close", () => clients.delete(socket));
    socket.on("message", (raw) => {
      try {
        handleDashboardMessage(raw.toString(), socket);
      } catch (err) {
        // 없는 id·세션 불일치·이미 처리된 제안은 엔진이 예외로 막는다 (fail-closed).
        console.error("[bridge] 대시보드 메시지 처리 실패:", err);
      }
    });
  });

  console.error(`[bridge] 대시보드 웹소켓 대기 중 (포트 ${WS_PORT})`);
}

/** 브리지를 닫는다. 안 닫으면 웹소켓 서버가 이벤트 루프를 잡아 proxy가 종료되지 않는다. */
export function stopDashboardBridge(): void {
  wss?.close();
  wss = null;
  clients.clear();
}