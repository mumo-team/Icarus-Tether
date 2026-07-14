import type { PolicyDecision, UserAction } from "@icarus-tether/types";

interface TrifectaApprovalModalProps {
  decision: PolicyDecision;
  onActionClick: (action: UserAction) => void;
  onClose: () => void;
}

export default function TrifectaApprovalModal({
  decision,
  onActionClick,
  onClose,
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
        <h2>🛑 {explanation.summary}</h2>
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