import { ToolRiskTag, type AuditLogEntry } from "@icarus-tether/types";

interface TrifectaWarningBannerProps {
  logs: AuditLogEntry[];
}

export default function TrifectaWarningBanner({ logs }: TrifectaWarningBannerProps) {
  // 트라이펙타 = 두 태그가 "모두" 겹친 차단. 태그 1개짜리 차단(예: 파괴 게이트의
  // UNTRUSTED_ORIGIN 단독)은 트라이펙타가 아니므로 이 배너로 오표시하지 않는다.
  const latestTrifecta = logs.find(
    (l) =>
      l.decision === "BLOCKED" &&
      l.matchedTags.includes(ToolRiskTag.SENSITIVE) &&
      l.matchedTags.includes(ToolRiskTag.UNTRUSTED_ORIGIN)
  );
  if (!latestTrifecta) return null;

  return (
    <div style={{ padding: "12px 16px", marginBottom: "16px", background: "#fdecea", border: "1px solid #f5c2c0", borderRadius: "8px", color: "#611a15" }}>
      [경고] 트라이펙타 감지: <strong>{latestTrifecta.toolName}</strong> 호출이 차단되었습니다 ({latestTrifecta.matchedTags.join(", ")})
    </div>
  );
}