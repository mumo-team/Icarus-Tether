import { ReactFlow, Background, Controls, type Node, type Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface TaintFlowDiagramProps {
  nodes: Node[];
  edges: Edge[];
  height?: number;
}

export default function TaintFlowDiagram({ nodes, edges, height = 240 }: TaintFlowDiagramProps) {
  return (
    <div style={{ height, border: "1px solid #ddd", borderRadius: "8px" }}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}