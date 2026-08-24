import { useRef } from "react";
import { maskPii } from "../lib/pii/mask";
import type { AuditLogEntry } from "@icarus-tether/types";
import type { LineageNode } from "./TaintGraph";
import { card, inset, mono, pill } from "../theme";

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

// 차단된 호출의 인자는 브리지가 blockedArgs로 실어 보내므로(화이트리스트 등재됨),
// 값 상자는 그 실제 값을 쓴다. 아직 차단이 없을 때만 아래 예시 문자열로 대체한다.
// 어느 쪽을 보고 있는지는 payloadReal 플래그로 화면에 밝힌다.
// (통과한 호출의 인자는 브리지가 싣지 않는다 — 차단 건만 나온다.)
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
  if (tags.includes("SENSITIVE")) return "sensitive";
  if (tags.includes("UNTRUSTED_ORIGIN")) return "untrusted";
  return "clean";
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
      <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "0 0 13px", flexWrap: "wrap" }}>
        <h3>정화 전 / 후</h3>
        {/* 실데이터인지 예시인지 반드시 밝힌다 — 예시를 실측처럼 두면 화면 전체의 신뢰가 깎인다 */}
        <span style={pill(flow.real ? "ok" : "muted")}>{flow.real ? "실데이터" : "예시"}</span>
      </div>

      {live && (
        <div
          style={{
            ...inset,
            padding: "11px 14px",
            marginBottom: 12,
            fontSize: 12.5,
            color: "var(--ink-2)",
            borderColor: live.ok && !live.residualSensitiveData ? "var(--ok-line)" : "var(--accent-line)",
          }}
        >
          <b style={{ color: live.ok && !live.residualSensitiveData ? "var(--ok)" : "var(--untrusted)" }}>
            {live.residualSensitiveData ? "부분 정화" : live.ok ? "정화 완료" : "정화됨 (주의)"}
          </b>{" "}
          <span style={mono}>
            {live.method}
            {live.maskedCount !== undefined ? ` · ${live.maskedCount}건 토큰화` : ""}
          </span>{" "}
          — <TagList tags={live.originalTags} tone="on" /> → <TagList tags={live.resultTags} tone="off" />
          {live.residualSensitiveData
            ? " (비정형 값 잔존 — 이후 전송이 계속 막힐 수 있음)"
            : live.ok && live.resultTags.length < 2 && " (트라이펙타 미성립 → 재전송 통과)"}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {/* 정화 없이 (차단) */}
        <div
          style={{
            ...card,
            borderColor: live ? "var(--line)" : "var(--danger-line)",
            opacity: live ? 0.55 : 1,
            transition: "opacity .3s, border-color .3s",
          }}
        >
          <h4 style={{ marginBottom: 14 }}>정화 전</h4>
          {flow.sources.map((s) => (
            <FlowNode key={`before-${s.toolName}`} title={s.toolName} sub={s.tags.join(" + ")} tone={sourceTone(s.tags)} />
          ))}
          <Arrow />
          <FlowNode title={flow.sinkTool} sub="차단" tone="blocked" />
          <PayloadBox label={payloadReal ? "나가려던 실제 인자" : "마스킹 예시 — 입력"} value={rawOut} tone="on" />
        </div>

        {/* 정화 후 (통과) */}
        <div
          style={{
            ...card,
            borderColor: live ? "var(--ok-line)" : "var(--line)",
            opacity: live ? 1 : 0.55,
            transition: "opacity .3s, border-color .3s",
          }}
        >
          <h4 style={{ marginBottom: 14 }}>정화 후{live ? ` · ${live.method}` : ""}</h4>
          {flow.sources.map((s) => {
            // 정화가 실제로 일어났으면 남은 태그만 보여준다 — 부분 정화를 숨기지 않는다.
            const remaining = live ? s.tags.filter((t) => live.resultTags.includes(t)) : [];
            return (
              <FlowNode
                key={`after-${s.toolName}`}
                title={s.toolName}
                sub={remaining.length ? `${remaining.join(" + ")} 잔존` : "해제됨"}
                tone={remaining.length ? sourceTone(remaining) : "clean"}
              />
            );
          })}
          <Arrow />
          <FlowNode title={flow.sinkTool} sub="통과" tone="allowed" />
          <PayloadBox
            label={payloadReal ? "maskPii 적용 결과" : "마스킹 예시 — 적용 결과"}
            value={maskedOut}
            tone="off"
          />
        </div>
      </div>
    </section>
  );
}

type NodeTone = "untrusted" | "sensitive" | "clean" | "blocked" | "allowed";

// 오염 축은 색상각이 아니라 채도로 나눈다 — 민감에 빨강을 쓰면 DB 조회 같은
// 정당한 동작이 나쁜 일로 읽힌다. 빨강은 '차단'이라는 결과에만 남긴다.
const NODE_STYLE: Record<NodeTone, { border: string; sub: string }> = {
  untrusted: { border: "var(--untrusted)", sub: "var(--untrusted)" },
  sensitive: { border: "var(--sensitive)", sub: "var(--sensitive)" },
  clean: { border: "var(--line-2)", sub: "var(--ok)" },
  blocked: { border: "var(--danger-line)", sub: "var(--danger-hi)" },
  allowed: { border: "var(--ok-line)", sub: "var(--ok)" },
};

function FlowNode({ title, sub, tone }: { title: string; sub: string; tone: NodeTone }) {
  const s = NODE_STYLE[tone];
  const verdict = tone === "blocked" || tone === "allowed";
  return (
    <div
      style={{
        ...inset,
        marginTop: 7,
        padding: "11px 13px",
        borderColor: s.border,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 10,
      }}
    >
      <span style={{ ...mono, fontSize: 11.5 }}>{title}</span>
      {verdict ? (
        <span style={pill(tone === "blocked" ? "danger" : "ok")}>{sub}</span>
      ) : (
        <span style={{ ...mono, fontSize: 9.5, color: s.sub, textAlign: "right" }}>{sub}</span>
      )}
    </div>
  );
}

function Arrow() {
  return <div style={{ textAlign: "center", color: "var(--ink-3)", fontSize: 14, lineHeight: "22px" }}>↓</div>;
}

function TagList({ tags, tone }: { tags: string[]; tone: "on" | "off" }) {
  if (tags.length === 0) return <span style={{ color: "var(--ok)", fontWeight: 600 }}>오염 없음</span>;
  return (
    <>
      {tags.map((t) => (
        <span
          key={t}
          style={{
            ...mono,
            display: "inline-block",
            margin: "0 2px",
            padding: "1px 6px",
            borderRadius: 4,
            fontSize: 10.5,
            color: tone === "on" ? "var(--untrusted-hi)" : "var(--ok)",
            background: "rgba(255,255,255,.05)",
            border: "1px solid var(--line-2)",
          }}
        >
          {t}
        </span>
      ))}
    </>
  );
}

function PayloadBox({ label, value, tone }: { label: string; value: string; tone: "on" | "off" }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ fontSize: 10.5, color: "var(--ink-3)", marginBottom: 6 }}>{label}</div>
      <pre
        style={{
          ...mono,
          margin: 0,
          background: "rgba(4,8,18,.7)",
          border: "1px solid var(--line)",
          borderRadius: "var(--r)",
          padding: "13px 14px",
          fontSize: 11.5,
          lineHeight: 1.78,
          color: tone === "on" ? "var(--untrusted-hi)" : "var(--ok)",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          overflowX: "auto",
        }}
      >
        {value}
      </pre>
    </div>
  );
}
