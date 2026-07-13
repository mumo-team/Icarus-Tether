import type { Node, Edge } from "@xyflow/react";
import TaintFlowDiagram from "./TaintFlowDiagram";

const WITHOUT_NODES: Node[] = [
  { id: "w1", position: { x: 0, y: 60 }, data: { label: "read_email\n(UNTRUSTED_ORIGIN)" }, style: { background: "#fff3e0" } },
  { id: "w2", position: { x: 200, y: 0 }, data: { label: "query_customer_db\n(SENSITIVE)" }, style: { background: "#fdecea" } },
  { id: "w3", position: { x: 400, y: 30 }, data: { label: "send_email\n🛑 BLOCKED" }, style: { background: "#f5c2c0", border: "2px solid #d32f2f" } },
];
const WITHOUT_EDGES: Edge[] = [
  { id: "we1", source: "w1", target: "w3", animated: true },
  { id: "we2", source: "w2", target: "w3", animated: true },
];

const WITH_NODES: Node[] = [
  { id: "s1", position: { x: 0, y: 60 }, data: { label: "read_email\n(UNTRUSTED_ORIGIN)" }, style: { background: "#fff3e0" } },
  { id: "s2", position: { x: 200, y: 0 }, data: { label: "query_customer_db\n(SENSITIVE)" }, style: { background: "#fdecea" } },
  { id: "s3", position: { x: 400, y: 30 }, data: { label: "정화(TOKENIZATION)" }, style: { background: "#e3f2fd" } },
  { id: "s4", position: { x: 600, y: 30 }, data: { label: "send_email\n✅ ALLOWED" }, style: { background: "#dcedc8", border: "2px solid #558b2f" } },
];
const WITH_EDGES: Edge[] = [
  { id: "se1", source: "s1", target: "s3", animated: true },
  { id: "se2", source: "s2", target: "s3", animated: true },
  { id: "se3", source: "s3", target: "s4", animated: true },
];

const BEFORE_PAYLOAD = `{ "body": "고객 SSN: 123-45-6789, 연락처: 010-1234-5678" }`;
const AFTER_PAYLOAD = `{ "body": "고객 SSN: [SSN_REDACTED], 연락처: [PHONE_REDACTED]" }`;

export default function SanitizationCompareView() {
  return (
    <section>
      <h2>정화 전/후 비교</h2>
      <div style={{ display: "flex", gap: "24px" }}>
        <div style={{ flex: 1 }}>
          <h3>정화 없이</h3>
          <TaintFlowDiagram nodes={WITHOUT_NODES} edges={WITHOUT_EDGES} height={160} />
          <PayloadBox label="send_email로 나가려던 데이터" value={BEFORE_PAYLOAD} tone="danger" />
        </div>
        <div style={{ flex: 1 }}>
          <h3>정화 후</h3>
          <TaintFlowDiagram nodes={WITH_NODES} edges={WITH_EDGES} height={160} />
          <PayloadBox label="send_email로 나간 데이터" value={AFTER_PAYLOAD} tone="safe" />
        </div>
      </div>
    </section>
  );
}

function PayloadBox({ label, value, tone }: { label: string; value: string; tone: "danger" | "safe" }) {
  return (
    <div style={{ marginTop: "8px" }}>
      <div style={{ fontSize: "12px", color: "#666" }}>{label}</div>
      <pre style={{ background: tone === "danger" ? "#fdecea" : "#f6fbf7", border: `1px solid ${tone === "danger" ? "#f5c2c0" : "#c8e6c9"}`, borderRadius: "6px", padding: "8px", fontSize: "12px", overflowX: "auto" }}>
        {value}
      </pre>
    </div>
  );
}