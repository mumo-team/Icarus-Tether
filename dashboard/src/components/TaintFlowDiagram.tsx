import { ReactFlow, Background, Controls, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface TaintFlowDiagramProps {
  nodes: Node[];
  edges: Edge[];
  height?: number;
}

export default function TaintFlowDiagram({ nodes, edges, height = 300 }: TaintFlowDiagramProps) {
  return (
    <div
      style={{
        height,
        borderRadius: "var(--r)",
        border: "1px solid var(--line)",
        background: "var(--panel-2)",
        overflow: "hidden",
      }}
    >
      <ReactFlow nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.18 }} proOptions={{ hideAttribution: true }}>
        {/* 플롯 영역이라는 걸 드러내는 격자. 페이지 배경엔 깔지 않는다 —
            거기선 아무 정보도 나르지 않고 색만 탁해진다. */}
        <Background color="#26262b" gap={14} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
