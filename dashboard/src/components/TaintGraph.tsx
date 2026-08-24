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

// 오염 종류에 따라 노드 표면을 정한다.
// 축마다 다른 '색상'을 주지 않는 게 핵심이다 — 민감에 빨강을 쓰면 DB 조회처럼
// 정당한 동작이 나쁜 일로 읽힌다. 색상각은 청색 하나로 두고 채도로만 나눈다.
// 두 축이 겹친 노드만 표면을 한 단계 올려(raise) 시선을 준다.
function nodeSkin(tags: string[]): { bg: string; border: string } {
  const s = tags.includes("SENSITIVE");
  const u = tags.includes("UNTRUSTED_ORIGIN");
  if (s && u) return { bg: "var(--raise)", border: "var(--untrusted)" };
  if (s) return { bg: "var(--panel)", border: "var(--sensitive)" };
  if (u) return { bg: "var(--panel)", border: "var(--untrusted)" };
  return { bg: "var(--panel-2)", border: "var(--line-2)" }; // 정화됨/중립
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
      const skin = nodeSkin(n.tags);
      return {
        id: n.id,
        position: { x: d * 250, y: row * 96 },
        data: { label: `${n.toolName}\n${n.tags.join(" + ") || "(정화됨)"}` },
        style: {
          background: skin.bg,
          border: `1px solid ${skin.border}`,
          borderRadius: 9,
          color: "var(--ink)",
          fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
          fontSize: 12,
          lineHeight: 1.55,
          padding: "10px 12px",
          width: 200,
          whiteSpace: "pre-line",
          textAlign: "left",
        },
      };
    });

    const edges: Edge[] = lineage.flatMap((n) =>
      n.parents.map((p) => ({
        id: `${p.nodeId}->${n.id}`,
        source: p.nodeId,
        target: n.id,
        animated: !p.weak, // 강한 연결만 애니메이션, weak는 정적
        // 약한 연결(안전 바닥)은 점선으로 둔다. 근거의 세기가 선 모양으로 보여야
        // "시간 근접으로 추정한 것"과 "값이 실제로 일치한 것"이 구분된다.
        style: p.weak
          ? { strokeDasharray: "5 6", stroke: "var(--ink-3)", strokeWidth: 1.6 }
          : { stroke: "var(--untrusted)", strokeWidth: 2 },
        label: p.method,
        labelStyle: {
          fontSize: 10,
          fill: "var(--ink-3)",
          fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
        },
        labelBgStyle: { fill: "var(--panel-2)" },
        labelBgPadding: [5, 3] as [number, number],
        labelBgBorderRadius: 4,
      }))
    );

    return { nodes, edges };
  }, [lineage]);

  if (lineage.length === 0) {
    return (
      <div
        style={{
          padding: 22,
          textAlign: "center",
          borderRadius: "var(--r)",
          border: "1px dashed var(--line-2)",
          color: "var(--ink-3)",
          fontSize: 12,
        }}
      >
        아직 추적된 오염이 없습니다
      </div>
    );
  }
  return <TaintFlowDiagram nodes={nodes} edges={edges} height={320} />;
}
