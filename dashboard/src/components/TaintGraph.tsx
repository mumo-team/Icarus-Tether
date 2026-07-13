import { useMemo } from "react";
import type { Node, Edge } from "@xyflow/react";
import TaintFlowDiagram from "./TaintFlowDiagram";

// TODO: 실제 TaintGraphEvent 스키마 확정(7/15 회의) 후 실데이터로 교체
const DUMMY_NODES: Node[] = [
  { id: "1", position: { x: 0, y: 80 }, data: { label: "read_email\n(UNTRUSTED_ORIGIN)" }, style: { background: "#fff3e0", border: "1px solid #f0b429" } },
  { id: "2", position: { x: 220, y: 0 }, data: { label: "query_customer_db\n(SENSITIVE)" }, style: { background: "#fdecea", border: "1px solid #f5c2c0" } },
  { id: "3", position: { x: 440, y: 40 }, data: { label: "send_email\n(OUTBOUND_SINK)" }, style: { background: "#fdecea", border: "1px solid #d32f2f" } },
];

const DUMMY_EDGES: Edge[] = [
  { id: "e1-3", source: "1", target: "3", animated: true, label: "UNTRUSTED_ORIGIN" },
  { id: "e2-3", source: "2", target: "3", animated: true, label: "SENSITIVE" },
];

export default function TaintGraph() {
  const nodes = useMemo(() => DUMMY_NODES, []);
  const edges = useMemo(() => DUMMY_EDGES, []);

  return (
    <section>
      <h2>오염 그래프 (더미 데이터)</h2>
      <TaintFlowDiagram nodes={nodes} edges={edges} />
    </section>
  );
}