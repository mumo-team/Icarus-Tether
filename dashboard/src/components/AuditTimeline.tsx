import type { AuditLogEntry, OverrideAuditEntry } from "@icarus-tether/types";
type TimelineTone = "allowed" | "blocked" | "forwarded" | "hitl";

interface TimelineEntry {
  key: string;
  timestamp: string;
  sessionId: string;
  toolName: string;
  label: string;
  tone: TimelineTone;
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
// 스토리보드 2단계 "로그 배지 변경" — 판정 종류를 색으로 즉시 구분한다.
// HITL 전이는 판정이 아니라 사람의 개입이라 별도 색(주황)으로 분리한다.
const TONE_STYLE: Record<TimelineTone, { bg: string; fg: string; border: string }> = {
  allowed: { bg: "#e8f5e9", fg: "#1b5e20", border: "#a5d6a7" },
  blocked: { bg: "#fdecea", fg: "#b71c1c", border: "#ef9a9a" },
  forwarded: { bg: "#eceff1", fg: "#455a64", border: "#b0bec5" },
  hitl: { bg: "#fff3e0", fg: "#e65100", border: "#ffb74d" },
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
    tone: l.decision === "ALLOWED" ? "allowed" : l.decision === "FORWARDED" ? "forwarded" : "blocked",
  }));

  const hitlEntries: TimelineEntry[] = hitlLog.map((h, i) => ({
    key: `hitl-${h.approvalId}-${h.action}-${i}`,
    timestamp: h.timestamp,
    sessionId: h.sessionId,
    toolName: h.toolName,
    label: `${HITL_ACTION_LABEL[h.action] ?? h.action}${h.actor ? ` (${h.actor})` : ""}`,
    source: "HITL",
    tone: "hitl",
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
          {combined.map((e) => {
            const s = TONE_STYLE[e.tone];
            return (
              <li key={e.key} style={{ marginBottom: "4px" }}>
                <span style={{ fontFamily: "monospace", color: "#888" }}>[{e.source}]</span>{" "}
                {new Date(e.timestamp).toLocaleTimeString()} —{" "}
                <span style={{ fontFamily: "monospace" }}>{e.toolName}</span>{" "}
                <span
                  style={{
                    display: "inline-block",
                    padding: "1px 8px",
                    borderRadius: "10px",
                    fontSize: "12px",
                    fontWeight: 600,
                    background: s.bg,
                    color: s.fg,
                    border: `1px solid ${s.border}`,
                  }}
                >
                  {e.label}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}