import type { AuditLogEntry, ApprovalRequest } from "@icarus-tether/types";

interface MetricCardsProps {
  logs: AuditLogEntry[];
  approvals: ApprovalRequest[];
}

export default function MetricCards({ logs, approvals }: MetricCardsProps) {
  const blocked = logs.filter((l) => l.decision === "BLOCKED").length;
  const pending = approvals.filter((a) => a.status === "PENDING").length;

  const cards = [
    { label: "전체 호출", value: logs.length },
    { label: "차단됨", value: blocked },
    { label: "승인 대기", value: pending },
  ];

  return (
    <div style={{ display: "flex", gap: "16px", marginBottom: "24px" }}>
      {cards.map((c) => (
        <div key={c.label} style={{ flex: 1, padding: "16px", border: "1px solid #ddd", borderRadius: "8px" }}>
          <div style={{ fontSize: "13px", color: "#666" }}>{c.label}</div>
          <div style={{ fontSize: "28px", fontWeight: 700 }}>{c.value}</div>
        </div>
      ))}
    </div>
  );
}