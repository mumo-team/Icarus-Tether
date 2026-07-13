import { useState } from "react";
import type { AuditLogEntry, ApprovalRequest } from "@icarus-tether/types";
import MetricCards from "./components/MetricCards";
import TrifectaWarningBanner from "./components/TrifectaWarningBanner";
import EventLogTimeline from "./components/EventLogTimeline";
import ApprovalQueue from "./components/ApprovalQueue";
import SanitizationCompareView from "./components/SanitizationCompareView";
import { maskPii } from "./lib/pii/mask";
import TaintGraph from "./components/TaintGraph";

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

export default function App() {
  const [logs] = useState<AuditLogEntry[]>(SAMPLE_LOGS);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>(SAMPLE_APPROVALS);

  function handleDecide(id: string, status: "APPROVED" | "REJECTED") {
    setApprovals((prev) =>
      prev.map((a) =>
        a.id === id
          ? { ...a, status, resolvedAt: new Date().toISOString(), resolvedBy: "demo-user" }
          : a
      )
    );
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <h1>Icarus-Tether 대시보드</h1>
      <TrifectaWarningBanner logs={logs} />
      <MetricCards logs={logs} approvals={approvals} />
      <EventLogTimeline logs={logs} />
      <ApprovalQueue approvals={approvals} onDecide={handleDecide} />
      <SanitizationCompareView />
      <TaintGraph />
    </div>
  );
}