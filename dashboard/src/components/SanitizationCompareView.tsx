import { maskPii } from "../lib/pii/mask";

interface SanitizationState {
  method: string;
  originalTags: string[];
  resultTags: string[];
  ok: boolean;
}

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
      {live ? (
        <p
          style={{
            padding: "8px 12px",
            borderRadius: "6px",
            background: live.ok ? "#e8f5e9" : "#fff3e0",
            border: `1px solid ${live.ok ? "#c8e6c9" : "#ffe0b2"}`,
            fontSize: "14px",
          }}
        >
          {live.ok ? "✅" : "⚠️"} 실제 정화됨 ({live.method}) — 세션 오염 태그{" "}
          <TagList tags={live.originalTags} tone="danger" /> →{" "}
          <TagList tags={live.resultTags} tone="safe" />
          {live.ok && live.resultTags.length < 2 && "  (트라이펙타 미성립 → 재전송 통과)"}
        </p>
      ) : (
        <p style={{ color: "#888", fontSize: "14px" }}>
          차단된 전송에서 <b>"민감 정보를 가리고 보내기"</b>를 누르면, 오른쪽 카드가 정화 후 상태로 강조됩니다.
        </p>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginTop: "12px" }}>
        {/* 정화 없이 (차단) */}
        <div
          style={{
            padding: "14px",
            borderRadius: "12px",
            background: "#fff",
            border: `2px solid ${live ? "#e0e0e0" : "#d32f2f"}`,
            opacity: live ? 0.5 : 1,
            transition: "opacity 0.3s, border-color 0.3s",
          }}
        >
          <Pill text={`정화 없이${!live ? " · 현재" : ""}`} tone="danger" />
          <FlowNode title="fetch_web_page" sub="UNTRUSTED_ORIGIN" tone="untrusted" />
          <FlowNode title="query_customer_db" sub="SENSITIVE" tone="danger" />
          <Arrow />
          <FlowNode title="send_email" sub="[차단]" tone="blocked" />
          <PayloadBox label="나가려던 데이터" value={SAMPLE_RAW} tone="danger" />
        </div>

        {/* 정화 후 (통과) */}
        <div
          style={{
            padding: "14px",
            borderRadius: "12px",
            background: "#fff",
            border: `2px solid ${live ? "#2e7d32" : "#e0e0e0"}`,
            opacity: live ? 1 : 0.5,
            transition: "opacity 0.3s, border-color 0.3s",
          }}
        >
          <Pill text={`정화 후${live ? ` · ${live.method}` : ""}`} tone="safe" />
          <FlowNode title="fetch_web_page" sub="UNTRUSTED_ORIGIN" tone="untrusted" />
          <FlowNode title="query_customer_db" sub="SENSITIVE 해제됨" tone="safe" />
          <Arrow />
          <FlowNode title="send_email" sub="[통과]" tone="allowed" />
          <PayloadBox label="정화되어 나간 데이터 (maskPii 실제 적용)" value={SAMPLE_MASKED} tone="safe" />
        </div>
      </div>
    </section>
  );
}

type NodeTone = "untrusted" | "danger" | "safe" | "blocked" | "allowed";

const NODE_STYLE: Record<NodeTone, { bg: string; border: string; title: string; sub: string }> = {
  untrusted: { bg: "#fff3e0", border: "#ffb74d", title: "#e65100", sub: "#ef6c00" },
  danger: { bg: "#fdecea", border: "#ef9a9a", title: "#b71c1c", sub: "#c62828" },
  safe: { bg: "#e8f5e9", border: "#a5d6a7", title: "#1b5e20", sub: "#2e7d32" },
  blocked: { bg: "#fdecea", border: "#e57373", title: "#7f0000", sub: "#b71c1c" },
  allowed: { bg: "#e8f5e9", border: "#66bb6a", title: "#1b5e20", sub: "#1b5e20" },
};

function FlowNode({ title, sub, tone }: { title: string; sub: string; tone: NodeTone }) {
  const s = NODE_STYLE[tone];
  const emphatic = tone === "blocked" || tone === "allowed";
  return (
    <div
      style={{
        marginTop: "8px",
        padding: "8px 10px",
        borderRadius: "8px",
        background: s.bg,
        border: `${emphatic ? "1.5px" : "0.5px"} solid ${s.border}`,
        textAlign: emphatic ? "center" : "left",
      }}
    >
      <div style={{ fontSize: "13px", fontWeight: 500, color: s.title, fontFamily: "monospace" }}>{title}</div>
      <div style={{ fontSize: "11px", color: s.sub }}>{sub}</div>
    </div>
  );
}

function Arrow() {
  return <div style={{ textAlign: "center", color: "#bbb", fontSize: "14px", lineHeight: "18px" }}>↓</div>;
}

function Pill({ text, tone }: { text: string; tone: "danger" | "safe" }) {
  const c = tone === "danger" ? { bg: "#fdecea", fg: "#b71c1c" } : { bg: "#e8f5e9", fg: "#1b5e20" };
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: "12px",
        fontWeight: 500,
        color: c.fg,
        background: c.bg,
        padding: "2px 8px",
        borderRadius: "6px",
      }}
    >
      {text}
    </span>
  );
}

function TagList({ tags, tone }: { tags: string[]; tone: "danger" | "safe" }) {
  if (tags.length === 0) return <span style={{ color: "#2e7d32", fontWeight: "bold" }}>(오염 없음)</span>;
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
    <div style={{ marginTop: "10px" }}>
      <div style={{ fontSize: "11px", color: "#999", marginBottom: "4px" }}>{label}</div>
      <pre
        style={{
          margin: 0,
          background: tone === "danger" ? "#fdecea" : "#f6fbf7",
          border: `0.5px solid ${tone === "danger" ? "#f5c2c0" : "#c8e6c9"}`,
          borderRadius: "6px",
          padding: "8px",
          fontSize: "11px",
          color: tone === "danger" ? "#712b13" : "#04342c",
          whiteSpace: "pre-wrap",
          fontFamily: "monospace",
        }}
      >
        {value}
      </pre>
    </div>
  );
}