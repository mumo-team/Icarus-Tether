/**
 * ③ 검사·화면 — C 담당
 *
 * 역할: 승인 대기 큐, 감사로그 타임라인, (나중에) 오염 그래프 시각화.
 *
 * TODO(C): AuditLogEntry[] 를 백엔드(policy-engine)에서 실시간으로 받아와 표시
 * TODO(C): ApprovalRequest 목록에 승인/거부 버튼 붙이기
 * TODO(C): 오염 그래프 시각화 (W5~W6 예정)
 */

import { useState } from "react";
import type { AuditLogEntry, ApprovalRequest } from "@icarus-tether/types";

// 1주차 스텁 데이터 — 실제로는 API에서 받아온다
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

const SAMPLE_APPROVALS: ApprovalRequest[] = [];

export default function App() {
  const [logs] = useState<AuditLogEntry[]>(SAMPLE_LOGS);
  const [approvals] = useState<ApprovalRequest[]>(SAMPLE_APPROVALS);

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px" }}>
      <h1>TaintGuard 대시보드 (1주차 스텁)</h1>

      <h2>감사 로그</h2>
      <ul>
        {logs.map((log) => (
          <li key={log.id}>
            [{log.timestamp}] {log.toolName} → {log.decision}
          </li>
        ))}
      </ul>

      <h2>승인 대기 큐</h2>
      {approvals.length === 0 ? (
        <p>대기 중인 항목 없음</p>
      ) : (
        <ul>
          {approvals.map((a) => (
            <li key={a.id}>
              {a.toolName} ({a.status})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
