import { useState,useEffect } from "react";
import type { AuditLogEntry, ApprovalRequest, PolicyDecision } from "@icarus-tether/types";
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
  const [showModal, setShowModal] = useState(false);
  const [injectionChecks, setInjectionChecks] = useState<InjectionCheckEntry[]>([]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:7331");

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
    };

    ws.onerror = () => {
      console.error("[대시보드] proxy 웹소켓 연결 실패 — proxy가 켜져 있는지 확인하세요");
    };

    return () => ws.close();
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

  function handleActionClick(action: { label: string }) {
    // TODO: 실제 requestApproval/resolveApproval 연결은 프로세스 분리 문제(회의 안건) 해결 후
    console.log("[demo] 액션 클릭:", action);
    setShowModal(false);
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <h1>Icarus-Tether 대시보드</h1>
      <button onClick={() => setShowModal(true)}>⚠️ 트라이펙타 경고 데모 보기</button>
      <TrifectaWarningBanner logs={logs} />
      <MetricCards logs={logs} approvals={approvals} />
      <EventLogTimeline logs={logs} />
      <AuditTimeline logs={logs} hitlLog={SAMPLE_HITL_LOG} />
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
      {showModal && (
        <TrifectaApprovalModal
          decision={SAMPLE_BLOCKED_DECISION}
          onActionClick={handleActionClick}
          onClose={() => setShowModal(false)}
        />
      )}
    </div>
  );
}