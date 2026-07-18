import type { Node, Edge } from "@xyflow/react";
import TaintFlowDiagram from "./TaintFlowDiagram";
import { maskPii } from "../lib/pii/mask";

interface SanitizationState {
  method: string;
  originalTags: string[];
  resultTags: string[];
  ok: boolean;
}

const WITHOUT_NODES: Node[] = [
  { id: "w1", position: { x: 0, y: 60 }, data: { label: "fetch_web_page\n(UNTRUSTED_ORIGIN)" }, style: { background: "#fff3e0" } },
  { id: "w2", position: { x: 200, y: 0 }, data: { label: "query_customer_db\n(SENSITIVE)" }, style: { background: "#fdecea" } },
  { id: "w3", position: { x: 400, y: 30 }, data: { label: "send_email\n🛑 BLOCKED" }, style: { background: "#f5c2c0", border: "2px solid #d32f2f" } },
];
const WITHOUT_EDGES: Edge[] = [
  { id: "we1", source: "w1", target: "w3", animated: true },
  { id: "we2", source: "w2", target: "w3", animated: true },
];

const WITH_NODES: Node[] = [
  { id: "s1", position: { x: 0, y: 60 }, data: { label: "fetch_web_page\n(UNTRUSTED_ORIGIN)" }, style: { background: "#fff3e0" } },
  { id: "s2", position: { x: 200, y: 0 }, data: { label: "query_customer_db\n(SENSITIVE)" }, style: { background: "#fdecea" } },
  { id: "s3", position: { x: 400, y: 30 }, data: { label: "정화(TOKENIZATION)" }, style: { background: "#e3f2fd" } },
  { id: "s4", position: { x: 600, y: 30 }, data: { label: "send_email\n✅ ALLOWED" }, style: { background: "#dcedc8", border: "2px solid #558b2f" } },
];
const WITH_EDGES: Edge[] = [
  { id: "se1", source: "s1", target: "s3", animated: true },
  { id: "se2", source: "s2", target: "s3", animated: true },
  { id: "se3", source: "s3", target: "s4", animated: true },
];

// payload 원본 값은 엔진 vault에만 있어 세션에서 못 빼온다.
// 대신 maskPii(대시보드의 정규식 마스킹)를 실제로 돌려, 마스킹이 어떻게
// 동작하는지 그 자리에서 보여준다 — 값은 예시지만 변환은 진짜다.
const SAMPLE_RAW = `고객 홍길동, 이메일 hong@example.com, 연락처 010-1234-5678`;
const SAMPLE_MASKED = maskPii(SAMPLE_RAW);

export default function SanitizationCompareView({
  sanitization,
}: {
  sanitization: SanitizationState | null;
}) {
  const live = sanitization; // WS로 받은 실제 정화 결과 (없으면 아직 정화 안 함)

  return (
    <section>
      <h2>정화 전/후 비교</h2>
      {live && (
        <p
          style={{
            padding: "8px 12px",
            borderRadius: "6px",
            background: live.ok ? "#e8f5e9" : "#fff3e0",
            border: `1px solid ${live.ok ? "#c8e6c9" : "#ffe0b2"}`,
          }}
        >
          {live.ok ? "✅" : "⚠️"} 실제 정화됨 ({live.method}) — 세션 오염 태그{" "}
          <TagList tags={live.originalTags} tone="danger" /> →{" "}
          <TagList tags={live.resultTags} tone="safe" />
          {live.ok && live.resultTags.length < 2 && "  (트라이펙타 미성립 → 재전송 통과)"}
        </p>
      )}
      <div style={{ display: "flex", gap: "24px" }}>
        <div style={{ flex: 1 }}>
          <h3>정화 없이</h3>
          <TaintFlowDiagram nodes={WITHOUT_NODES} edges={WITHOUT_EDGES} height={160} />
          <PayloadBox label="send_email로 나가려던 데이터" value={SAMPLE_RAW} tone="danger" />
        </div>
        <div style={{ flex: 1 }}>
          <h3>정화 후</h3>
          <TaintFlowDiagram nodes={WITH_NODES} edges={WITH_EDGES} height={160} />
          <PayloadBox label="send_email로 나간 데이터 (maskPii 실제 적용)" value={SAMPLE_MASKED} tone="safe" />
        </div>
      </div>
    </section>
  );
}

function TagList({ tags, tone }: { tags: string[]; tone: "danger" | "safe" }) {
  if (tags.length === 0) return <span style={{ color: "#558b2f", fontWeight: "bold" }}>(오염 없음)</span>;
  return (
    <>
      {tags.map((t) => (
        <span
          key={t}
          style={{
            display: "inline-block",
            margin: "0 2px",
            padding: "1px 6px",
            borderRadius: "4px",
            fontSize: "12px",
            background: tone === "danger" ? "#fdecea" : "#f6fbf7",
            border: `1px solid ${tone === "danger" ? "#f5c2c0" : "#c8e6c9"}`,
          }}
        >
          {t}
        </span>
      ))}
    </>
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