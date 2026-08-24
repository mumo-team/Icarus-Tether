import type { ApprovalRequest } from "@icarus-tether/types";
import { inset, mono, pill } from "../theme";

interface ApprovalQueueProps {
  approvals: ApprovalRequest[];
  onDecide: (id: string, status: "APPROVED" | "REJECTED", resolvedBy: string) => void;
  awaiting: Record<string, "awaiting" | "timeout">;
}

/** 승인 상태 → 알약 색. PENDING은 아직 결과가 아니라 무채색으로 둔다 */
function stateOf(status: ApprovalRequest["status"]) {
  if (status === "APPROVED") return "ok" as const;
  if (status === "REJECTED") return "danger" as const;
  return "muted" as const;
}

export default function ApprovalQueue({ approvals, onDecide, awaiting }: ApprovalQueueProps) {
  return (
    <section>
      <h3 style={{ marginBottom: 13, fontSize: 12.5, color: "var(--ink-2)" }}>승인 대기</h3>

      {approvals.length === 0 ? (
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
          대기 중인 항목 없음
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {approvals.map((a) => (
            <div
              key={a.id}
              style={{
                ...inset,
                padding: "12px 13px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              <span style={{ ...mono, fontSize: 11.5 }}>{a.toolName}</span>

              {a.status !== "PENDING" ? (
                <span style={pill(stateOf(a.status))}>{a.status === "APPROVED" ? "승인됨" : "거부됨"}</span>
              ) : awaiting[a.id] === "awaiting" ? (
                <span style={pill("muted")}>응답 대기</span>
              ) : (
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  {awaiting[a.id] === "timeout" && (
                    <span style={{ ...pill("danger"), marginRight: 2 }}>응답 없음</span>
                  )}
                  <button style={{ fontSize: 11.5, padding: "5px 11px" }} onClick={() => onDecide(a.id, "APPROVED", "demo-reviewer")}>
                    승인
                  </button>
                  <button style={{ fontSize: 11.5, padding: "5px 11px" }} onClick={() => onDecide(a.id, "REJECTED", "demo-reviewer")}>
                    거부
                  </button>
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
