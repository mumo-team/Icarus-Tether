import { useMemo } from "react";
import { ToolRiskTag, type AuditLogEntry } from "@icarus-tether/types";

// 융합에 쓰는 최소 신호 — 대시보드가 이미 받는 것에서 파생한다(새 state 없음).
interface InjectionSignal {
  isInjection: boolean;
  score: number;
  /** 모델 호출이 정상 종료했는지. false면 isInjection은 fail-safe 기본값이라 신뢰 불가 */
  evaluated: boolean;
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
    // evaluated=false는 모델 로드/추론 실패 시의 fail-safe 반환값(isInjection:true, score:1)이다.
    // 그대로 켜면 '모델 실패'가 화면에서 '탐지 성공'으로 둔갑한다 — 평가된 건만 신호로 센다.
    const signalInjection = (lastInjection?.evaluated ?? false) && lastInjection.isInjection;

    const count = [signalLineage, signalTrifecta, signalInjection].filter(Boolean).length;
    const level = count >= 3 ? "높음" : count >= 1 ? "주의" : "정상";

    return { tags, toolName: lastBlocked?.toolName, lastInjection, signalLineage, signalTrifecta, signalInjection, level };
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
          detail={fusion.signalTrifecta ? `성립 — ${fusion.toolName} 차단 (민감+비신뢰+외부유출)` : "미성립"}
        />
        <SignalRow
          on={fusion.signalInjection}
          unknown={!!fusion.lastInjection && !fusion.lastInjection.evaluated}
          label="ML 인젝션 탐지"
          detail={
            !fusion.lastInjection
              ? "검사 이력 없음"
              : !fusion.lastInjection.evaluated
              ? "모델 로드/추론 실패로 판정 불가 — 종합 판정에서 제외"
              : `score=${fusion.lastInjection.score.toFixed(4)}`
          }
        />
      </ul>
    </section>
  );
}

// unknown=true는 "신호를 얻지 못함" — 신호가 없는 '정상'과 반드시 구분한다.
// 판정 불가를 '정상'으로 적으면 화면이 근거 없는 안심을 준다.
function SignalRow({
  on,
  label,
  detail,
  unknown = false,
}: {
  on: boolean;
  label: string;
  detail: string;
  unknown?: boolean;
}) {
  const mark = unknown ? "판정불가" : on ? "감지" : "정상";
  return (
    <li style={{ color: unknown ? "#e65100" : on ? "#b71c1c" : "#888" }}>
      <span style={{ fontWeight: 500 }}>[{mark}]</span> {label} — {detail}
    </li>
  );
}