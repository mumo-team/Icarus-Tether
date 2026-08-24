import type { AuditLogEntry, OverrideAuditEntry } from "@icarus-tether/types";
import { inset, mono } from "../theme";

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

// 판정 종류를 색으로 즉시 구분한다.
// 화면 전체가 청색 한 색상각이라, 결과를 나타내는 통과/차단만 상태색을 쓴다.
// HITL 전이는 판정이 아니라 사람의 개입이라 액센트(비신뢰 청색)로 따로 뗀다.
const TONE_STYLE: Record<TimelineTone, { bg: string; fg: string; border: string }> = {
  allowed: { bg: "var(--ok-bg)", fg: "var(--ok)", border: "var(--ok-line)" },
  blocked: { bg: "var(--danger-bg)", fg: "var(--danger-hi)", border: "var(--danger-line)" },
  forwarded: { bg: "rgba(255,255,255,.05)", fg: "var(--ink-3)", border: "var(--line-2)" },
  hitl: { bg: "rgba(155,208,235,.10)", fg: "var(--untrusted)", border: "var(--accent-line)" },
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

  if (combined.length === 0) {
    return (
      <div
        style={{
          padding: 20,
          textAlign: "center",
          borderRadius: "var(--r)",
          border: "1px dashed var(--line-2)",
          color: "var(--ink-3)",
          fontSize: 12,
        }}
      >
        기록 없음
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 8 }}>
      {combined.map((e) => {
        const s = TONE_STYLE[e.tone];
        return (
          <div
            key={e.key}
            style={{ ...inset, padding: "11px 14px", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}
          >
            <span style={{ ...mono, fontSize: 10.5, color: "var(--ink-3)", minWidth: 62 }}>
              {new Date(e.timestamp).toLocaleTimeString()}
            </span>
            <span style={{ ...mono, fontSize: 11.5, flex: 1, minWidth: 0 }}>{e.toolName}</span>
            <span style={{ fontSize: 10, color: "var(--ink-3)" }}>{e.source}</span>
            <span
              style={{
                display: "inline-block",
                padding: "3px 10px",
                borderRadius: 999,
                fontSize: 10.5,
                fontWeight: 500,
                background: s.bg,
                color: s.fg,
                border: `1px solid ${s.border}`,
              }}
            >
              {e.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}
