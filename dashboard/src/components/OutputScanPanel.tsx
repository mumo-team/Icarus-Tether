import type { OutputScanEvent } from "@icarus-tether/types";
import { inset, mono, pill } from "../theme";

export default function OutputScanPanel({ scans }: { scans: OutputScanEvent[] }) {
  if (scans.length === 0) {
    return (
      <div style={{ ...inset, padding: "13px 16px", display: "flex", alignItems: "center", gap: 12, fontSize: 12.5 }}>
        <span style={pill("muted")}>출력 스캔</span>
        <span style={{ color: "var(--ink-2)" }}>
          인코딩·분할 우회 시도 <b className="mono">0</b>건
        </span>
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 10 }}>
      {scans.map((s) => (
        <div
          key={s.id}
          style={{
            ...inset,
            padding: "13px 16px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            fontSize: 12.5,
            borderColor: "var(--danger-line)",
          }}
        >
          <span style={pill("danger")}>{s.kind === "containment" ? "원본 세탁" : "키 패턴"}</span>
          <span style={{ ...mono, color: "var(--ink-2)" }}>
            {s.toolName}
            {s.sourceTool ? ` ← ${s.sourceTool}` : ""} · {s.matchLen}바이트 · {s.valueHash.slice(0, 8)}…
          </span>
        </div>
      ))}
    </div>
  );
}
