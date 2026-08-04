import type { PolicyDecision, UserAction } from "@icarus-tether/types";

interface TrifectaApprovalModalProps {
  decision: PolicyDecision;
  onActionClick: (action: UserAction) => void;
  onClose: () => void;
  queuedCount?: number;
}

export default function TrifectaApprovalModal({
  decision,
  onActionClick,
  onClose,
  queuedCount,

}: TrifectaApprovalModalProps) {
  const { explanation } = decision;
  if (!explanation) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <div style={{ background: "white", borderRadius: "8px", padding: "24px", maxWidth: "480px", width: "90%" }}>
        <h2>[차단] {explanation.summary}</h2>
        {queuedCount ? (
          <p style={{ margin: "0 0 8px", color: "#e65100", fontWeight: "bold" }}>
            대기 중 {queuedCount}건 — 이 항목 처리 후 아래 승인 대기 큐에서 이어서 확인하세요
          </p>
        ) : null}
        <p>{explanation.reason}</p>

        {explanation.risks.length > 0 && (
          <ul>
            {explanation.risks.map((risk, i) => (
              <li key={i}>{risk}</li>
            ))}
          </ul>
        )}

        <div style={{ display: "flex", gap: "8px", marginTop: "16px" }}>
          {explanation.actions.map((action, i) => (
            <button
              key={i}
              disabled={!action.available}
              title={!action.available ? action.description : undefined}
              onClick={() => onActionClick(action)}
            >
              {action.label}
            </button>
          ))}
        </div>

        <button onClick={onClose} style={{ marginTop: "16px" }}>
          닫기
        </button>
      </div>
    </div>
  );
}