import type { AuditLogEntry, ApprovalRequest } from "@icarus-tether/types";
import { card, mono, GAP } from "../theme";

interface MetricCardsProps {
  logs: AuditLogEntry[];
  approvals: ApprovalRequest[];
}

export default function MetricCards({ logs, approvals }: MetricCardsProps) {
  const blocked = logs.filter((l) => l.decision === "BLOCKED").length;
  const forwarded = logs.filter((l) => l.decision === "FORWARDED").length;
  const pending = approvals.filter((a) => a.status === "PENDING").length;

  // hero: 화면에서 가장 먼저 봐야 하는 칸. 색이 아니라 표면 밝기로 올린다
  // — 붉은 채움을 쓰면 그래프의 차단 노드와 시선이 갈린다.
  const cards = [
    { label: "전체 호출", value: logs.length, hero: false },
    { label: "차단됨", value: blocked, hero: true },
    { label: "무검사 중계", value: forwarded, hero: false },
    { label: "승인 대기", value: pending, hero: false },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: GAP, marginBottom: GAP }}>
      {cards.map((c) => (
        <div
          key={c.label}
          style={{
            ...card,
            padding: "18px 19px",
            ...(c.hero ? { background: "var(--raise)", borderColor: "var(--line-2)" } : null),
          }}
        >
          <div style={{ fontSize: 12, color: c.hero ? "var(--ink)" : "var(--ink-2)", marginBottom: 11 }}>
            {c.label}
          </div>
          <div
            style={{
              ...mono,
              fontSize: 38,
              fontWeight: 500,
              lineHeight: 1,
              letterSpacing: "-0.03em",
              color: c.hero ? "var(--ink)" : "var(--ink-2)",
            }}
          >
            {c.value}
          </div>
        </div>
      ))}
    </div>
  );
}
