import type { AuditLogEntry } from "@icarus-tether/types";
import type { LineageNode } from "./TaintGraph";
import { inset, mono } from "../theme";

/**
 * 차단이 성립한 세 축을, 그 축을 만든 도구와 짝지어 보여준다.
 *
 * 문장으로 쓰지 않는 이유: 문장은 "어느 도구가 어느 축인지"를 못 밝히고,
 * 도구가 늘어날 때마다 다시 써야 한다. 항목이면 줄만 늘면 된다.
 */
export default function BlockReason({ logs, lineage }: { logs: AuditLogEntry[]; lineage: LineageNode[] }) {
  const lastBlocked = [...logs].reverse().find((l) => l.decision === "BLOCKED");

  if (!lastBlocked) {
    return (
      <section>
        <h2 style={{ marginBottom: 14 }}>차단 근거</h2>
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
          아직 차단된 흐름이 없습니다
        </div>
      </section>
    );
  }

  // 축을 만든 도구를 계보에서 찾는다. 같은 축을 여러 도구가 만들었으면 전부 적는다 —
  // 하나만 보여주면 "왜 이것만?"이 되고, 실제로 결합 노드가 여럿인 경우가 있다.
  const toolsWith = (tag: string) =>
    [...new Set(lineage.filter((n) => n.tags.includes(tag) && n.toolName !== lastBlocked.toolName).map((n) => n.toolName))];

  const rows = [
    { axis: "민감 데이터", tools: toolsWith("SENSITIVE") },
    { axis: "비신뢰 노출", tools: toolsWith("UNTRUSTED_ORIGIN") },
    { axis: "외부 유출구", tools: [lastBlocked.toolName] },
  ].filter((r) => r.tools.length > 0);

  return (
    <section>
      <h2 style={{ marginBottom: 14 }}>차단 근거</h2>

      <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
        {rows.map((r) => (
          <div
            key={r.axis}
            style={{
              ...inset,
              padding: "11px 13px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
            }}
          >
            <span style={{ fontSize: 12, color: "var(--ink-2)" }}>{r.axis}</span>
            <span style={{ ...mono, fontSize: 11.5, color: "var(--untrusted)", textAlign: "right" }}>
              {r.tools.join(", ")}
            </span>
          </div>
        ))}
      </div>

      {/* 이 한 줄이 제품의 논지다 — 개별 호출은 전부 인가돼 있었고, 위험은 그 조합에서 나왔다 */}
      <p style={{ margin: "13px 0 0", fontSize: 12.5, color: "var(--ink-3)", lineHeight: 1.7 }}>
        호출 하나하나는 모두 허용된 동작입니다.
      </p>
    </section>
  );
}
