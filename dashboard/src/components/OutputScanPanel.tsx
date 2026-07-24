import type { OutputScanEvent } from "@icarus-tether/types";

export default function OutputScanPanel({ scans }: { scans: OutputScanEvent[] }) {
  return (
    <section>
      <h2>출력 스캔 — 세탁 유출 차단</h2>
      {scans.length === 0 ? (
        <p style={{ color: "#888", fontSize: "13px" }}>아직 탐지된 세탁 유출이 없습니다.</p>
      ) : (
        <ul>
          {scans.map((s) => (
            <li key={s.id} style={{ color: "#d32f2f", fontSize: "13px" }}>
              [{s.kind === "containment" ? "원본 세탁" : "키 패턴"}] {s.toolName}
              {s.sourceTool ? ` (출처: ${s.sourceTool})` : ""} — 길이 {s.matchLen}, 해시 {s.valueHash.slice(0, 8)}…
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}