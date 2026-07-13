import type { ApprovalRequest } from "@icarus-tether/types";

interface ApprovalQueueProps {
  approvals: ApprovalRequest[];
  onDecide: (id: string, status: "APPROVED" | "REJECTED") => void;
}

export default function ApprovalQueue({ approvals, onDecide }: ApprovalQueueProps) {
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
                <span style={{ marginLeft: "8px" }}>
                  <button onClick={() => onDecide(a.id, "APPROVED")}>승인</button>{" "}
                  <button onClick={() => onDecide(a.id, "REJECTED")}>거부</button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}