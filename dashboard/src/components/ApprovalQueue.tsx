import type { ApprovalRequest } from "@icarus-tether/types";

interface ApprovalQueueProps {
  approvals: ApprovalRequest[];
  onDecide: (id: string, status: "APPROVED" | "REJECTED", resolvedBy: string) => void;
  awaiting: Record<string, "awaiting" | "timeout">;
}

export default function ApprovalQueue({ approvals, onDecide, awaiting }: ApprovalQueueProps) {
  return (
    <section>
      <h2>승인 대기 큐</h2>
      {approvals.length === 0 ? (
        <p>대기 중인 항목 없음</p>
      ) : (
        <ul>
          {approvals.map((a) => (
            <li key={a.id} style={{ marginBottom: "8px" }}>
              {a.toolName} ({a.status})
              {a.status === "PENDING" && (
                awaiting[a.id] === "awaiting" ? (
                  <span style={{ marginLeft: "8px", color: "#888" }}>전송됨 · 응답 대기</span>
                ) : (
                  <span style={{ marginLeft: "8px" }}>
                    {awaiting[a.id] === "timeout" && (
                      <span style={{ color: "#d32f2f", marginRight: "8px" }}>응답 없음</span>
                    )}
                    <button onClick={() => onDecide(a.id, "APPROVED", "demo-reviewer")}>승인</button>{" "}
                    <button onClick={() => onDecide(a.id, "REJECTED", "demo-reviewer")}>거부</button>
                  </span>
                )
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}