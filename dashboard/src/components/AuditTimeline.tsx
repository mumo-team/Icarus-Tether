import type { AuditLogEntry, OverrideAuditEntry } from "@icarus-tether/types";

interface TimelineEntry {
  key: string;
  timestamp: string;
  sessionId: string;
  toolName: string;
  label: string;
  source: "감사로그" | "HITL";
}

const HITL_ACTION_LABEL: Record<OverrideAuditEntry["action"], string> = {
  OFFERED: "오버라이드 제안됨",
  REQUESTED: "승인 대기 등록",
  APPROVED: "승인됨",
  REJECTED: "거부됨",
  OVERRIDE_USED: "승인으로 1회 통과",
  SUPERSEDED: "제안 대체됨",
  OVERRIDE_STALE: "낡은 승인 무효화",
};

interface AuditTimelineProps {
  logs: AuditLogEntry[];
  hitlLog: OverrideAuditEntry[];
}

export default function AuditTimeline({ logs, hitlLog }: AuditTimelineProps) {
  const auditEntries: TimelineEntry[] = logs.map((l) => ({
    key: `audit-${l.id}`,
    timestamp: l.timestamp,
    sessionId: l.sessionId,
    toolName: l.toolName,
    label: l.decision === "ALLOWED" ? "통과" : l.decision === "FORWARDED" ? "중계" : "차단",
    source: "감사로그",
  }));

  const hitlEntries: TimelineEntry[] = hitlLog.map((h, i) => ({
    key: `hitl-${h.approvalId}-${h.action}-${i}`,
    timestamp: h.timestamp,
    sessionId: h.sessionId,
    toolName: h.toolName,
    label: `${HITL_ACTION_LABEL[h.action] ?? h.action}${h.actor ? ` (${h.actor})` : ""}`,
    source: "HITL",
  }));

  const combined = [...auditEntries, ...hitlEntries].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <section>
      <h2>감사로그 통합 타임라인</h2>
      {combined.length === 0 ? (
        <p>기록 없음</p>
      ) : (
        <ul>
          {combined.map((e) => (
            <li key={e.key}>
              <span style={{ fontFamily: "monospace", color: "#888" }}>[{e.source}]</span>{" "}
              {new Date(e.timestamp).toLocaleTimeString()} — {e.toolName}: {e.label}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}