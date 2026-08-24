import type { PolicyDecision, UserAction } from "@icarus-tether/types";
import { inset, pill } from "../theme";

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
      role="dialog"
      aria-modal="true"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        background: "rgba(0,0,0,0.72)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
      }}
    >
      <div
        style={{
          background: "var(--panel)",
          border: "1px solid var(--line-2)",
          borderRadius: "var(--R)",
          padding: 26,
          maxWidth: 520,
          width: "100%",
          maxHeight: "86vh",
          overflowY: "auto",
          boxShadow: "0 30px 80px -20px rgba(0,0,0,.9)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
          <span style={pill("danger")}>차단</span>
          <h2 style={{ flex: 1, minWidth: 0 }}>{explanation.summary}</h2>
        </div>

        {queuedCount ? (
          <div style={{ ...inset, padding: "11px 13px", marginBottom: 13, fontSize: 12, color: "var(--untrusted)" }}>
            대기 중 {queuedCount}건 — 이 항목을 처리한 뒤 승인 대기 목록에서 이어서 확인하세요
          </div>
        ) : null}

        <p style={{ fontSize: 13, color: "var(--ink-2)", lineHeight: 1.78 }}>{explanation.reason}</p>

        {explanation.risks.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 14 }}>
            {explanation.risks.map((risk, i) => (
              <div key={i} style={{ ...inset, padding: "10px 13px", fontSize: 12, color: "var(--ink-2)" }}>
                {risk}
              </div>
            ))}
          </div>
        )}

        <div style={{ display: "flex", gap: 8, marginTop: 20, flexWrap: "wrap" }}>
          {explanation.actions.map((action, i) => (
            <button
              key={i}
              disabled={!action.available}
              title={!action.available ? action.description : undefined}
              onClick={() => onActionClick(action)}
              style={
                // 첫 액션이 권장 경로(정화 후 전송)다 — 하나만 액센트를 준다.
                i === 0 && action.available
                  ? { background: "rgba(155,208,235,.10)", borderColor: "var(--accent-line)", color: "var(--untrusted)" }
                  : { opacity: action.available ? 1 : 0.45 }
              }
            >
              {action.label}
            </button>
          ))}
          <button onClick={onClose} style={{ marginLeft: "auto" }}>
            닫기
          </button>
        </div>
      </div>
    </div>
  );
}
