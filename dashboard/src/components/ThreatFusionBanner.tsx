import { useMemo } from "react";
import { ToolRiskTag, type AuditLogEntry } from "@icarus-tether/types";

// 융합에 쓰는 최소 신호 — 대시보드가 이미 받는 것에서 파생한다(새 state 없음).
interface InjectionSignal {
  isInjection: boolean;
  score: number;
}

// 여러 독립 신호를 하나의 위협 판정으로 종합한다.
// 실제 차단은 policy-engine(B) 소관 — 여기선 이미 받은 신호를 화면에서 합쳐 보여줄 뿐이다.
export default function ThreatFusionBanner({
  logs,
  injectionChecks,
}: {
  logs: AuditLogEntry[];
  injectionChecks: InjectionSignal[];
}) {
  const fusion = useMemo(() => {
    const lastBlocked = [...logs].reverse().find((l) => l.decision === "BLOCKED");
    const tags = lastBlocked?.matchedTags ?? [];
    const lastInjection = injectionChecks[injectionChecks.length - 1];

    const signalLineage = tags.length > 0;
    const signalTrifecta = tags.includes(ToolRiskTag.SENSITIVE) && tags.includes(ToolRiskTag.UNTRUSTED_ORIGIN);
    const signalInjection = lastInjection?.isInjection ?? false;

    const count = [signalLineage, signalTrifecta, signalInjection].filter(Boolean).length;
    const level = count >= 3 ? "높음" : count >= 1 ? "주의" : "정상";

    return { tags, lastInjection, signalLineage, signalTrifecta, signalInjection, level };
  }, [logs, injectionChecks]);

  const color =
    fusion.level === "높음"
      ? { fg: "#b71c1c", bg: "#fdecea", border: "#e57373" }
      : fusion.level === "주의"
      ? { fg: "#e65100", bg: "#fff3e0", border: "#ffb74d" }
      : { fg: "#555", bg: "#f5f5f5", border: "#ccc" };

  return (
    <section
      style={{
        margin: "12px 0",
        padding: "14px 16px",
        borderRadius: "8px",
        background: color.bg,
        border: `2px solid ${color.border}`,
      }}
    >
      <div style={{ fontWeight: 700, fontSize: "15px", color: color.fg, marginBottom: "8px" }}>
        종합 위협 판정 — [{fusion.level}]{" "}
        <span style={{ fontWeight: 400, fontSize: "13px", color: "#777" }}>
          (여러 신호를 합친 근거 — 최종 차단은 정책 엔진이 결정)
        </span>
      </div>
      <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "14px", lineHeight: 1.8 }}>
        <SignalRow
          on={fusion.signalLineage}
          label="계보 오염 추적"
          detail={fusion.signalLineage ? fusion.tags.join(", ") : "오염 없음"}
        />
        <SignalRow
          on={fusion.signalTrifecta}
          label="트라이펙타 규칙"
          detail={fusion.signalTrifecta ? "성립 (민감+비신뢰+외부유출)" : "미성립"}
        />
        <SignalRow
          on={fusion.signalInjection}
          label="ML 인젝션 탐지"
          detail={
            fusion.lastInjection
              ? `score=${fusion.lastInjection.score.toFixed(4)}`
              : "검사 이력 없음"
          }
        />
      </ul>
    </section>
  );
}

function SignalRow({ on, label, detail }: { on: boolean; label: string; detail: string }) {
  return (
    <li style={{ color: on ? "#b71c1c" : "#888" }}>
      <span style={{ fontWeight: 500 }}>[{on ? "감지" : "정상"}]</span> {label} — {detail}
    </li>
  );
}