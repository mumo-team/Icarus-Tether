import type { AuditLogEntry } from "@icarus-tether/types";

interface TrifectaWarningBannerProps {
  logs: AuditLogEntry[];
}

export default function TrifectaWarningBanner({ logs }: TrifectaWarningBannerProps) {
  const latestTrifecta = logs.find((l) => l.decision === "BLOCKED" && l.matchedTags.length > 0);
  if (!latestTrifecta) return null;

  return (
    <div style={{ padding: "12px 16px", marginBottom: "16px", background: "#fdecea", border: "1px solid #f5c2c0", borderRadius: "8px", color: "#611a15" }}>
      ⚠ 트라이펙타 감지: <strong>{latestTrifecta.toolName}</strong> 호출이 차단되었습니다 ({latestTrifecta.matchedTags.join(", ")})
    </div>
  );
}