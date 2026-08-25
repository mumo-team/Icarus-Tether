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

// 계보 스냅샷 한 장 = 노드 배열 + 방송 시각.
// 시각을 같이 들고 있어야 재생 중인 단계가 어느 판정의 순간인지 감사 로그와 맞출 수 있다.
export interface LineageSnapshot {
  nodes: LineageNode[];
  timestamp?: string;
}

// 계보엔 없지만 그 순간 막힌 호출. 실행되지 않았으므로 오염 노드가 아니다 —
// 계보 노드와 같은 모양으로 그리면 "저것도 오염됐다"로 잘못 읽힌다.
export interface BlockedSink {
  toolName: string;
  timestamp?: string;
}

export const BLOCKED_SINK_ID = "__blocked_sink__";

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

export default function TaintGraph({
  lineage,
  blocked,
}: {
  lineage: LineageNode[];
  blocked?: BlockedSink | null;
}) {
  const { nodes, edges } = useMemo(() => {
    if (lineage.length === 0 && !blocked) return { nodes: [] as Node[], edges: [] as Edge[] };

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

    // ── 막힌 호출을 계보 오른쪽 끝에 종단으로 얹는다 ─────────────
    // 이 노드는 계보에서 온 게 아니라 감사 로그에서 합성한 것이다. 실행된 적이
    // 없으므로 테두리를 점선으로 두고 '실행 안 됨'을 라벨에 박는다.
    if (blocked) {
      const maxDepth = depth.size === 0 ? -1 : Math.max(...depth.values());
      nodes.push({
        id: BLOCKED_SINK_ID,
        position: { x: (maxDepth + 1) * 250, y: 0 },
        data: { label: `${blocked.toolName}\n차단됨 · 실행 안 됨` },
        style: {
          background: "var(--danger-bg)",
          border: "1.5px dashed var(--danger-line)",
          borderRadius: 9,
          color: "var(--danger-hi)",
          fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
          fontSize: 12,
          lineHeight: 1.55,
          padding: "10px 12px",
          width: 200,
          whiteSpace: "pre-line",
          textAlign: "left",
        },
      });

      // 오염을 나르던 도구에서 종단으로 선을 긋는다. 같은 도구가 여러 노드로
      // 갈라져 있으면 가장 깊은 노드 하나만 잇는다 — 선이 다발이면 못 읽는다.
      const deepestByTool = new Map<string, LineageNode>();
      for (const n of lineage) {
        if (n.tags.length === 0) continue; // 정화·중립 노드는 이 이야기에 필요 없다
        if (n.toolName === blocked.toolName) continue; // 종단 자신은 위에 그렸다
        const cur = deepestByTool.get(n.toolName);
        if (!cur || (depth.get(n.id) ?? 0) > (depth.get(cur.id) ?? 0)) {
          deepestByTool.set(n.toolName, n);
        }
      }
      for (const n of deepestByTool.values()) {
        edges.push({
          id: `${n.id}->${BLOCKED_SINK_ID}`,
          source: n.id,
          target: BLOCKED_SINK_ID,
          animated: false, // 흐르지 않았다. 애니메이션은 실제 전파에만 쓴다
          style: { strokeDasharray: "4 5", stroke: "var(--danger-line)", strokeWidth: 2 },
          label: "차단",
          labelStyle: {
            fontSize: 10,
            fill: "var(--danger-hi)",
            fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
          },
          labelBgStyle: { fill: "var(--panel-2)" },
          labelBgPadding: [5, 3] as [number, number],
          labelBgBorderRadius: 4,
        });
      }
    }

    return { nodes, edges };
  }, [lineage, blocked]);

  if (lineage.length === 0 && !blocked) {
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
