import { useState,useEffect, useRef } from "react";
import type { AuditLogEntry, ApprovalRequest, PolicyDecision, UserAction } from "@icarus-tether/types";
import MetricCards from "./components/MetricCards";
import TrifectaWarningBanner from "./components/TrifectaWarningBanner";
import EventLogTimeline from "./components/EventLogTimeline";
import ApprovalQueue from "./components/ApprovalQueue";
import SanitizationCompareView from "./components/SanitizationCompareView";
import { maskPii } from "./lib/pii/mask";
import TaintGraph from "./components/TaintGraph";
import TrifectaApprovalModal from "./components/TrifectaApprovalModal";
import AuditTimeline, { type HitlAuditEntry } from "./components/AuditTimeline";

interface InjectionCheckEntry {
  id: string;
  sessionId: string;
  toolName: string;
  isInjection: boolean;
  score: number;
  timestamp: string;
}

console.log(maskPii("고객 이메일은 hansol@example.com 이고 연락처는 010-1234-5678 입니다"));
// 기대값: "고객 이메일은 [EMAIL_REDACTED] 이고 연락처는 [PHONE_REDACTED] 입니다"

const SAMPLE_LOGS: AuditLogEntry[] = [
  {
    id: "1",
    sessionId: "demo-session-1",
    toolName: "query_customer_db",
    decision: "ALLOWED",
    matchedTags: [],
    timestamp: new Date().toISOString(),
  },
];

const SAMPLE_APPROVALS: ApprovalRequest[] = [
  {
    id: "ap-1",
    sessionId: "demo-session-1",
    toolName: "send_email",
    args: { to: "external@example.com" },
    status: "PENDING",
    requestedAt: new Date().toISOString(),
  },
];

const SAMPLE_HITL_LOG: HitlAuditEntry[] = [
  {
    approvalId: "ap-1",
    sessionId: "demo-session-1",
    toolName: "send_email",
    action: "OFFERED",
    timestamp: new Date(Date.now() - 60_000).toISOString(),
  },
  {
    approvalId: "ap-1",
    sessionId: "demo-session-1",
    toolName: "send_email",
    action: "REQUESTED",
    timestamp: new Date(Date.now() - 30_000).toISOString(),
  },
];

const SAMPLE_BLOCKED_DECISION: PolicyDecision = {
  sessionId: "demo-session-1",
  toolName: "send_email",
  allowed: false,
  matchedTags: [],
  canOverride: true,
  approvalId: "ap-1",
  explanation: {
    summary: "민감한 정보가 외부로 나가려는 흐름이 감지되어 전송을 막았어요.",
    reason: "고객 문의(query_customer_db)에서 나온 정보와 외부 웹 페이지 내용이 함께 섞여 있어요.",
    risks: [
      "외부에서 온 내용에 숨은 지시가 있으면, 민감한 정보가 의도치 않게 밖으로 새어 나갈 수 있어요.",
    ],
    actions: [
      {
        kind: "REQUEST_APPROVAL",
        label: "관리자 승인 받고 보내기",
        description: "담당자가 확인 후 승인하면 한 번만 전송이 허용돼요.",
        available: true,
        detail: "ap-1",
      },
    ],
  },
};

export default function App() {
  const [logs, setLogs] = useState<AuditLogEntry[]>(SAMPLE_LOGS);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>(SAMPLE_APPROVALS);
  const [modalDecision, setModalDecision] = useState<PolicyDecision | null>(null);
  const [injectionChecks, setInjectionChecks] = useState<InjectionCheckEntry[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const [auditIntegrity, setAuditIntegrity] = useState<{
    ok: boolean;
    total: number;
    problems: { line: number; kind: string; detail: string }[];
  } | null>(null);

    useEffect(() => {
    let disposed = false; // 언마운트 후 재연결 타이머가 되살아나는 것 방지
    let retryTimer: number | undefined;
    let ws: WebSocket | null = null;

    function connect() {
      ws = new WebSocket("ws://localhost:7331");
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        console.log("[대시보드] proxy 연결됨");
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === "decision") {
          const entry: AuditLogEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            decision: data.allowed ? "ALLOWED" : "BLOCKED",
            matchedTags: data.matchedTags ?? [],
            timestamp: data.timestamp,
          };
          setLogs((prev) => [...prev, entry]);
          // 승인 가능한 차단이 오면 모달을 자동으로 띄운다 — 발표 3단계 "와우 포인트".
          if (data.allowed === false && data.canOverride && data.approvalId) {
            setModalDecision({
              sessionId: data.sessionId,
              toolName: data.toolName,
              allowed: false,
              matchedTags: data.matchedTags ?? [],
              reason: data.reason,
              explanation: data.explanation,
              canOverride: data.canOverride,
              approvalId: data.approvalId,
            });
          }
        }
        if (data.type === "approval_resolved") {
          console.log(
            `[대시보드] 승인 처리됨: ${data.approvalId} → ${data.approved ? "승인" : "거부"}`
          );
        }

        if (data.type === "injection_check") {
          const entry: InjectionCheckEntry = {
            id: `${data.sessionId}-${data.toolName}-${data.timestamp}`,
            sessionId: data.sessionId,
            toolName: data.toolName,
            isInjection: data.isInjection,
            score: data.score,
            timestamp: data.timestamp,
          };
          setInjectionChecks((prev) => [...prev, entry]);
        }
        if (data.type === "audit_integrity") {
          setAuditIntegrity({ ok: data.ok, total: data.total, problems: data.problems ?? [] });
        }
      };

      // onerror 뒤에는 항상 onclose가 따라오므로, 재연결은 onclose 한 곳에서만 건다.
      ws.onerror = () => {};

      ws.onclose = () => {
        setWsConnected(false);
        wsRef.current = null;
        if (disposed) return;
        // proxy는 "데모 1회 = 1프로세스"라 실행할 때마다 죽고 새로 뜬다.
        // 계속 재시도해 두면 다음 데모 실행에 자동으로 다시 붙는다.
        retryTimer = window.setTimeout(connect, 1000);
      };
    }

    connect();

    return () => {
      disposed = true;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      wsRef.current = null;
      ws?.close();
    };
  }, []);

    function handleDecide(id: string, status: "APPROVED" | "REJECTED", resolvedBy: string) {
    setApprovals((prev) =>
      prev.map((a) =>
        a.id === id
          ? { ...a, status, resolvedAt: new Date().toISOString(), resolvedBy }
          : a
      )
    );
  }

  function handleActionClick(action: UserAction) {
    // 지금 실제로 배선된 건 승인 요청뿐. 정화(SANITIZE)는 아직 미구현.
    if (action.kind === "REQUEST_APPROVAL" && modalDecision?.approvalId) {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        // 승인 상태는 proxy 프로세스의 엔진 메모리에 있어 브라우저가 직접 못 부른다.
        // 웹소켓으로 보내면 proxy가 같은 프로세스에서 resolveApproval을 대신 호출한다.
        ws.send(
          JSON.stringify({
            type: "approve",
            sessionId: modalDecision.sessionId,
            approvalId: modalDecision.approvalId,
            resolvedBy: "dashboard-reviewer",
          })
        );
        console.log("[대시보드] 승인 전송:", modalDecision.approvalId);
      } else {
        console.error("[대시보드] proxy 연결이 없어 승인을 보낼 수 없습니다");
      }
    } else {
      console.log("[대시보드] 아직 미배선 액션:", action.kind, action.label);
    }
    setModalDecision(null);
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <h1>Icarus-Tether 대시보드</h1>
       <button onClick={() => setModalDecision(SAMPLE_BLOCKED_DECISION)}>
        ⚠️ 트라이펙타 경고 데모 보기 (샘플)
      </button>
      <p style={{ color: wsConnected ? "#2e7d32" : "#d32f2f", fontWeight: "bold" }}>
        {wsConnected ? "🟢 proxy 연결됨" : "🔴 proxy 대기 중 — 데모를 실행하면 자동 연결됩니다"}
      </p>
      <TrifectaWarningBanner logs={logs} />
      <MetricCards logs={logs} approvals={approvals} />
      <EventLogTimeline logs={logs} />
      <AuditTimeline logs={logs} hitlLog={SAMPLE_HITL_LOG} />
      <section
        style={{
          margin: "12px 0",
          padding: "12px 16px",
          borderRadius: "8px",
          border: "2px solid",
          borderColor: !auditIntegrity ? "#9e9e9e" : auditIntegrity.ok ? "#2e7d32" : "#d32f2f",
          background: !auditIntegrity ? "#f5f5f5" : auditIntegrity.ok ? "#e8f5e9" : "#ffebee",
        }}
      >
        <strong>🛡️ 감사 로그 무결성</strong>{" "}
        {!auditIntegrity ? (
          <span style={{ color: "#616161" }}>세션 종료 시 검증됩니다</span>
        ) : auditIntegrity.ok ? (
          <span style={{ color: "#2e7d32" }}>
            ✅ 무결 — {auditIntegrity.total}줄 전부 서명·체인 정상
          </span>
        ) : (
          <span style={{ color: "#d32f2f" }}>
            ⛔ 위변조 감지 — {auditIntegrity.problems.length}건 (전체 {auditIntegrity.total}줄)
            <ul style={{ margin: "6px 0 0" }}>
              {auditIntegrity.problems.map((p, i) => (
                <li key={i}>
                  {p.line}번째 줄 [{p.kind}] {p.detail}
                </li>
              ))}
            </ul>
          </span>
        )}
      </section>
      <section>
        <h2>인젝션 탐지 결과</h2>
        {injectionChecks.length === 0 ? (
          <p>아직 없음</p>
        ) : (
          <ul>
            {injectionChecks.map((c) => (
              <li key={c.id} style={{ color: c.isInjection ? "#d32f2f" : "#2e7d32" }}>
                {c.isInjection ? "🚨 위험" : "✅ 안전"} — {c.toolName} (score={c.score.toFixed(4)})
              </li>
            ))}
          </ul>
        )}
      </section>
      <ApprovalQueue approvals={approvals} onDecide={handleDecide} />
      <SanitizationCompareView />
      <TaintGraph />
      {modalDecision && (
        <TrifectaApprovalModal
          decision={modalDecision}
          onActionClick={handleActionClick}
          onClose={() => setModalDecision(null)}
        />
      )}
    </div>
  );
}