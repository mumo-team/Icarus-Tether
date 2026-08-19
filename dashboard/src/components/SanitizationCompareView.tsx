import { useRef } from "react";
import { maskPii } from "../lib/pii/mask";
import type { AuditLogEntry } from "@icarus-tether/types";
import type { LineageNode } from "./TaintGraph";

interface SanitizationState {
  method: string;
  originalTags: string[];
  resultTags: string[];
  ok: boolean;
  maskedCount?: number;
  residualSensitiveData?: boolean;
}

interface FlowSource {
  toolName: string;
  tags: string[];
}

// 원본 payload는 엔진 보관소에만 있고, 브리지 전송경계 화이트리스트가 원본 값 방송을
// 막는다(의도된 설계). 그래서 아래 값 상자는 마스킹 동작을 보여주는 예시이고,
// 도구명·오염 태그·정화 결과는 이 세션의 실제 데이터다. 어느 쪽인지 화면에 밝힌다.
const MASK_EXAMPLE_RAW = `고객 홍길동, 이메일 hong@example.com, 연락처 010-1234-5678`;
const MASK_EXAMPLE_MASKED = maskPii(MASK_EXAMPLE_RAW);

// 아직 아무 판정도 안 온 초기 화면용. 실데이터가 들어오면 즉시 대체된다.
const EXAMPLE_SOURCES: FlowSource[] = [
  { toolName: "fetch_web_page", tags: ["UNTRUSTED_ORIGIN"] },
  { toolName: "query_customer_db", tags: ["SENSITIVE"] },
];
const EXAMPLE_SINK = "send_email";

/**
 * 이 세션에서 실제로 무엇이 오염을 날랐고 어디로 나가려 했는지 뽑는다.
 * 유출 시도 = 가장 최근 차단된 호출, 오염 출처 = 계보에서 태그가 남아 있는 노드.
 * 같은 도구가 여러 노드로 나뉘어도 화면에선 한 줄로 합친다.
 */
function deriveFlow(
  logs: AuditLogEntry[],
  lineage: LineageNode[]
): { sinkTool: string; sources: FlowSource[]; real: boolean; at: string | undefined } {
  const lastBlocked = [...logs].reverse().find((l) => l.decision === "BLOCKED");
  const sinkTool = lastBlocked?.toolName;

  const byTool = new Map<string, Set<string>>();
  for (const n of lineage) {
    if (n.tags.length === 0) continue; // 정화됐거나 중립인 노드는 이 이야기에 필요 없다
    if (n.toolName === sinkTool) continue; // 싱크 자신은 아래에 따로 그린다
    const set = byTool.get(n.toolName) ?? new Set<string>();
    n.tags.forEach((t) => set.add(t));
    byTool.set(n.toolName, set);
  }
  const sources: FlowSource[] = [...byTool].map(([toolName, tags]) => ({ toolName, tags: [...tags] }));

  if (!sinkTool || sources.length === 0) {
    return { sinkTool: EXAMPLE_SINK, sources: EXAMPLE_SOURCES, real: false, at: undefined };
  }
  return { sinkTool, sources, real: true, at: lastBlocked?.timestamp };
}

function sourceTone(tags: string[]): NodeTone {
  if (tags.includes("SENSITIVE")) return "danger";
  if (tags.includes("UNTRUSTED_ORIGIN")) return "untrusted";
  return "safe";
}

export default function SanitizationCompareView({
  sanitization,
  logs,
  lineage,
  blockedArgs,
}: {
  sanitization: SanitizationState | null;
  logs: AuditLogEntry[];
  lineage: LineageNode[];
  blockedArgs: string | null;
}) {
  const live = sanitization; // WS로 받은 실제 정화 결과 (없으면 아직 정화 안 함)
  // '정화 없이' 카드는 정화 직전 흐름을 보여줘야 한다. 최신 계보를 그대로 쓰면
  // 정화로 태그가 풀린 노드가 좌우 양쪽에서 같이 사라져, 왼쪽이 오른쪽을 따라가 버린다.
  // 그래서 정화가 오기 전까지만 갱신하고, 새 차단이 오면 그 시점 상태로 다시 잡는다.
  const computed = deriveFlow(logs, lineage);
  const frozen = useRef(computed);
  if (!live || frozen.current.at !== computed.at) frozen.current = computed;
  const flow = frozen.current;
  // 차단된 호출의 실제 인자가 오면 그것을 쓰고, 아직 없으면 마스킹 동작 예시를 보여준다.
  const payloadReal = blockedArgs !== null;
  const rawOut = blockedArgs ?? MASK_EXAMPLE_RAW;
  const maskedOut = blockedArgs ? maskPii(blockedArgs) : MASK_EXAMPLE_MASKED;

  return (
    <section>
      <h2>정화 전/후 비교</h2>
      <p style={{ fontSize: "12px", color: flow.real ? "#2e7d32" : "#888", margin: "0 0 8px" }}>
        {flow.real
          ? "[실데이터] 이 세션에서 실제로 기록된 도구와 오염 태그입니다."
          : "[예시] 아직 차단된 흐름이 없습니다 — 데모를 실행하면 실제 흐름으로 바뀝니다."}
      </p>
      {live ? (
        <p
          style={{
            padding: "8px 12px",
            borderRadius: "6px",
            background: live.ok && !live.residualSensitiveData ? "#e8f5e9" : "#fff3e0",
            border: `1px solid ${live.ok && !live.residualSensitiveData ? "#c8e6c9" : "#ffe0b2"}`,
            fontSize: "14px",
          }}
        >
          {live.residualSensitiveData ? "[주의] 부분 정화됨" : live.ok ? "[성공] 실제 정화됨" : "[주의] 실제 정화됨"}
          {" "}({live.method}{live.maskedCount !== undefined ? `, ${live.maskedCount}개 항목 토큰화` : ""}) — 세션 오염 태그{" "}
          <TagList tags={live.originalTags} tone="danger" /> →{" "}
          <TagList tags={live.resultTags} tone="safe" />
          {live.residualSensitiveData
            ? "  (비정형 값 잔존 — 다른 가드가 이후 전송을 계속 막을 수 있음)"
            : live.ok && live.resultTags.length < 2 && "  (트라이펙타 미성립 → 재전송 통과)"}
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
          {flow.sources.map((s) => (
            <FlowNode key={`before-${s.toolName}`} title={s.toolName} sub={s.tags.join("+")} tone={sourceTone(s.tags)} />
          ))}
          <Arrow />
          <FlowNode title={flow.sinkTool} sub="[차단]" tone="blocked" />
          <PayloadBox
            label={payloadReal ? "나가려던 실제 데이터 (차단된 호출의 인자)" : "마스킹 예시 — 입력"}
            value={rawOut}
            tone="danger"
          />
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
          {flow.sources.map((s) => {
            // 정화가 실제로 일어났으면 남은 태그만 보여준다 — 부분 정화를 숨기지 않는다.
            const remaining = live ? s.tags.filter((t) => live.resultTags.includes(t)) : [];
            return (
              <FlowNode
                key={`after-${s.toolName}`}
                title={s.toolName}
                sub={remaining.length ? `${remaining.join("+")} 잔존` : "해제됨"}
                tone={remaining.length ? sourceTone(remaining) : "safe"}
              />
            );
          })}
          <Arrow />
          <FlowNode title={flow.sinkTool} sub="[통과]" tone="allowed" />
          <PayloadBox
            label={payloadReal ? "maskPii를 실제로 적용한 결과" : "마스킹 예시 — maskPii 적용 결과"}
            value={maskedOut}
            tone="safe"
          />
        </div>
      </div>

      <p style={{ fontSize: "11px", color: "#999", marginTop: "10px", lineHeight: 1.6 }}>
        {payloadReal
          ? "값 상자는 실제로 차단된 호출의 인자입니다. 통과한 호출의 인자는 대시보드로 내보내지 않습니다 — 운영자가 확인해야 하는 것은 막힌 쪽이고, 그만큼 노출면을 좁힙니다."
          : "아래 값 상자는 마스킹이 어떻게 동작하는지 보여주는 예시입니다. 차단이 발생하면 실제로 나가려던 인자로 바뀝니다."}
      </p>
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