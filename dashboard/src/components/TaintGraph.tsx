import { useMemo } from "react";
import type { Node, Edge } from "@xyflow/react";
import TaintFlowDiagram from "./TaintFlowDiagram";

// proxy의 broadcastLineage가 보내는 노드 한 개의 모양.
export interface LineageNode {
  id: string;
  toolName: string;
  tags: string[];
  parents: { nodeId: string; method: string; weak: boolean }[];
}

// 태그에 따라 노드 색을 정한다 — 오염 종류를 한눈에.
function nodeColor(tags: string[]): { bg: string; border: string } {
  const s = tags.includes("SENSITIVE");
  const u = tags.includes("UNTRUSTED_ORIGIN");
  if (s && u) return { bg: "#f5c2c0", border: "#d32f2f" }; // 둘 다 = 진한 빨강
  if (s) return { bg: "#fdecea", border: "#e57373" }; // 민감
  if (u) return { bg: "#fff3e0", border: "#f0b429" }; // 비신뢰
  return { bg: "#eceff1", border: "#b0bec5" }; // 태그 없음(정화됨/중립)
}

// 계보엔 화면 좌표가 없다. 부모 깊이로 x를, 같은 깊이 내 순번으로 y를 계산한다.
function computeDepths(nodes: LineageNode[]): Map<string, number> {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const depth = new Map<string, number>();
  const visit = (id: string, seen: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (seen.has(id)) return 0; // 순환 방지(계보는 원래 비순환이지만 안전장치)
    seen.add(id);
    const node = byId.get(id);
    const parents = node?.parents ?? [];
    const d = parents.length === 0 ? 0 : 1 + Math.max(...parents.map((p) => visit(p.nodeId, seen)));
    depth.set(id, d);
    return d;
  };
  nodes.forEach((n) => visit(n.id, new Set()));
  return depth;
}

export default function TaintGraph({ lineage }: { lineage: LineageNode[] }) {
  const { nodes, edges } = useMemo(() => {
    if (lineage.length === 0) return { nodes: [] as Node[], edges: [] as Edge[] };

    const depth = computeDepths(lineage);
    const rowCount = new Map<number, number>(); // 깊이별로 몇 개 쌓였는지

    const nodes: Node[] = lineage.map((n) => {
      const d = depth.get(n.id) ?? 0;
      const row = rowCount.get(d) ?? 0;
      rowCount.set(d, row + 1);
      const c = nodeColor(n.tags);
      return {
        id: n.id,
        position: { x: d * 240, y: row * 90 },
        data: { label: `${n.toolName}\n${n.tags.join("+") || "(정화됨)"}` },
        style: {
          background: c.bg,
          border: `2px solid ${c.border}`,
          borderRadius: "8px",
          fontSize: "12px",
          width: 180,
        },
      };
    });

    const edges: Edge[] = lineage.flatMap((n) =>
      n.parents.map((p) => ({
        id: `${p.nodeId}->${n.id}`,
        source: p.nodeId,
        target: n.id,
        animated: !p.weak, // 강한 연결만 애니메이션, weak는 정적
        style: p.weak ? { strokeDasharray: "4 4", stroke: "#aaa" } : { stroke: "#555" },
        label: p.method,
        labelStyle: { fontSize: "10px", fill: "#666" },
      }))
    );

    return { nodes, edges };
  }, [lineage]);

  if (lineage.length === 0) {
    return (
      <p style={{ color: "#888", fontSize: "13px", margin: "8px 0" }}>
        아직 추적된 오염이 없습니다.
      </p>
    );
  }
  return <TaintFlowDiagram nodes={nodes} edges={edges} height={280} />;
}